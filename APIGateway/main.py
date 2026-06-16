import asyncio
import logging
import time
from fastapi import FastAPI, Query, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Any
from opensearchpy.exceptions import ConnectionError as OSConnectionError, TransportError
from client import (
    indexer_client, SophosCentralClient, SophosAPIError,
    nessus_client, jira_client, wazuh_server_client,
)
from normalization import Normalizer
from models import (
    InvestigateRequest, InvestigateResponse, AlertsPage,
    JiraTicketRequest, JiraBatchCheckRequest, JiraAssignRequest, NessusExportRequest,
    CreateDashboardRequest, UpdateDashboardRequest, ShareDashboardRequest,
)
from auth import get_current_user, require_role
import custom_dashboards as cd

from investigation_querry import build_investigation_query
from integrations.virustotal import lookup_ip, lookup_domain, lookup_hash, VirusTotalError
from integrations.sophos import (
    list_devices,
    get_device,
    isolate_device,
    unisolate_device,
    normalize_device,
)
from integrations.ms_defender import (
    DefenderClient, DefenderClientError,
    ingest_alerts as defender_ingest,
    ensure_index_template as defender_ensure_template,
    delete_stale_indices as defender_delete_stale,
    DEFENDER_POLL_SECS,
)

log = logging.getLogger(__name__)

# Search both Wazuh-native and direct-Defender indices for unified correlation
ALERT_INDICES = "wazuh-alerts-*,siem-defender-*"


app = FastAPI(title="API GATEWAY", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(OSConnectionError)
async def opensearch_connection_handler(_request: Request, _exc: OSConnectionError):
    return JSONResponse(
        status_code=503,
        content={"detail": "Cannot reach the Wazuh Indexer — check that OpenSearch is running and reachable."},
    )


@app.exception_handler(TransportError)
async def opensearch_transport_handler(_request: Request, exc: TransportError):
    return JSONResponse(
        status_code=503,
        content={"detail": f"Wazuh Indexer error: {exc.error}"},
    )

normalizer       = Normalizer()
sophos_client    = SophosCentralClient()
defender_client  = DefenderClient()

# ── Defender background poll state ────────────────────────────────────────────
_defender_last_poll:  str | None = None   # ISO-8601 timestamp of most-recent successful poll
_defender_last_error: str | None = None   # Last poll error message (cleared on success)

# ── JIRA auto-ticket config ───────────────────────────────────────────────────
import os as _os
JIRA_AUTOPOLL_SECS  = int(_os.getenv("JIRA_AUTOPOLL_SECS",  "300"))   # how often to scan (default 5 min)
JIRA_AUTOPOLL_HOURS = int(_os.getenv("JIRA_AUTOPOLL_HOURS", "24"))    # look-back window for Critical alerts

SEVERITY_LEVEL_MAP = {
    "Critical": {"gte": 15},
    "High":     {"gte": 12, "lte": 14},
    "Medium":   {"gte": 7,  "lte": 11},
    "Low":      {"lte": 6},
}


def rule_level_to_severity(level: int) -> str:
    if level >= 15:
        return "Critical"
    elif 12 <= level <= 14:
        return "High"
    elif 7 <= level <= 11:
        return "Medium"
    else:
        return "Low"


def build_related(unified_events: list[dict]) -> dict:
    users, hosts, ips, domains = set(), set(), set(), set()
    for e in unified_events:
        if e.get("user"):   users.add(e["user"])
        if e.get("host"):   hosts.add(e["host"])
        if e.get("src_ip"): ips.add(e["src_ip"])
        if e.get("domain"): domains.add(e["domain"])
    return {
        "users":   sorted(list(users))[:20],
        "hosts":   sorted(list(hosts))[:20],
        "ips":     sorted(list(ips))[:20],
        "domains": sorted(list(domains))[:20],
    }


def build_alert_query(
    limit:    int,
    offset:   int,
    source:   Optional[str],
    severity: Optional[str],
    hours:    Optional[int],
    q:        Optional[str],
    ioc_only: bool = False,
) -> dict:
    filters = []

    if ioc_only:
        filters.append({"term":  {"misp.enriched":  True}})
        filters.append({"range": {"misp.hit_count": {"gte": 1}}})

    if hours:
        filters.append({
            "range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}
        })

    if source:
        if source == "wazuh":
            # Wazuh-native alerts: no data.integration AND not a darktrace rule-group alert
            filters.append({
                "bool": {
                    "must_not": [
                        {"exists": {"field": "data.integration"}},
                        {"term": {"rule.groups": "darktrace"}},
                    ]
                }
            })
        elif source == "darktrace":
            filters.append({"term": {"rule.groups": "darktrace"}})
        elif source == "ms-defender":
            filters.append({"term": {"data.integration": "ms-defender"}})
        else:
            filters.append({"term": {"data.integration": source}})

    if severity and severity in SEVERITY_LEVEL_MAP:
        # Darktrace severity comes from data.model.category, not rule.level
        # (all Darktrace alerts have rule.level=3 regardless of actual severity)
        _dt_cats = {
            "Critical": ["Critical"],
            "High":     ["Suspicious"],
            "Medium":   ["Unusual Activity", "Compliance"],
            "Low":      ["Informational"],
        }
        # Defender stores severity as a plain string: high/medium/low/informational
        _def_sevs = {
            "Critical": [],                            # Defender has no "critical" label
            "High":     ["high"],
            "Medium":   ["medium"],
            "Low":      ["low", "informational"],
        }
        sev_should = [
            # Non-Darktrace/non-Defender sources: match by rule.level
            {
                "bool": {
                    "filter":   [{"range": {"rule.level": SEVERITY_LEVEL_MAP[severity]}}],
                    "must_not": [
                        {"term": {"rule.groups": "darktrace"}},
                        {"term": {"data.integration": "ms-defender"}},
                    ],
                }
            },
            # Sophos explicit severity field
            {"term": {"data.sophos.severity": severity.lower()}},
        ]
        for cat in _dt_cats.get(severity, []):
            sev_should.append({"term": {"data.model.category.keyword": cat}})
        for sev_val in _def_sevs.get(severity, []):
            sev_should.append({"term": {"data.defender.severity": sev_val}})
        filters.append({"bool": {"should": sev_should, "minimum_should_match": 1}})

    must = []
    if q:
        must.append({
            "multi_match": {
                "query": q,
                "fields": [
                    "rule.description", "agent.name", "full_log",
                    "data.sophos.suser", "data.ms-graph.title",
                    "data.defender.title", "data.defender.description",
                    "data.defender.threat_family", "data.defender.device_hostname",
                    "data.defender.user_upn",
                ],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        })

    bool_query: dict = {}
    if must:    bool_query["must"]   = must
    if filters: bool_query["filter"] = filters

    return {
        "size":             limit,
        "from":             offset,
        "track_total_hits": True,
        "sort":             [{"@timestamp": {"order": "desc"}}],
        "query":            {"bool": bool_query} if bool_query else {"match_all": {}},
    }


@app.get("/")
def root():
    return {"status": "SOC API running"}


@app.get("/auth/me")
def auth_me(claims: dict[str, Any] = Depends(get_current_user)):
    """Return the current user's identity and roles from the Azure AD token."""
    return {
        "name":  claims.get("name"),
        "email": claims.get("preferred_username") or claims.get("upn"),
        "roles": claims.get("roles", []),
        "oid":   claims.get("oid"),
    }


@app.get("/indexer/health")
def indexer_health():
    return indexer_client.info()


# ── Debug endpoints ───────────────────────────────────────────────────────────

@app.get("/debug/msgraph-sample")
def debug_msgraph_sample(relationship: str = "alerts"):
    """Return raw _source of a recent MS Graph document.
    Use ?relationship=alerts to get alert docs (have evidence).
    Use ?relationship=incidents for incident docs."""
    q = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"data.integration": "ms-graph"}},
                    {"term": {"data.ms-graph.relationship": relationship}},
                ]
            }
        },
    }
    res  = indexer_client.search(index="wazuh-alerts-*", body=q)
    hits = res.get("hits", {}).get("hits", [])
    if not hits:
        return {"error": f"No MS Graph '{relationship}' documents found. Try relationship=incidents"}
    return {"_source": hits[0]["_source"]}


@app.get("/debug/msgraph-relationships")
def debug_msgraph_relationships():
    """Show what MS Graph relationship types exist and how many of each."""
    q = {
        "size": 0,
        "query": {"term": {"data.integration": "ms-graph"}},
        "aggs": {
            "by_relationship": {
                "terms": {"field": "data.ms-graph.relationship.keyword", "size": 20}
            }
        }
    }
    res = indexer_client.search(index="wazuh-alerts-*", body=q)
    buckets = res.get("aggregations", {}).get("by_relationship", {}).get("buckets", [])
    return {"relationships": [{b["key"]: b["doc_count"]} for b in buckets]}


@app.get("/debug/msgraph-mapping")
def debug_msgraph_mapping():
    """Return the OpenSearch field mapping for data.ms-graph fields."""
    mapping = indexer_client.indices.get_mapping(index="wazuh-alerts-*")
    result = {}
    for idx_name, idx_data in list(mapping.items())[:3]:
        props = idx_data.get("mappings", {}).get("properties", {})
        data_props = props.get("data", {}).get("properties", {})
        result[idx_name] = data_props.get("ms-graph", {})
    return result


@app.get("/debug/investigate-test")
def debug_investigate_test(entity_type: str, value: str):
    """Run an investigation and return the raw query + hit count for diagnosis."""
    q = build_investigation_query(entity_type=entity_type, value=value, size=3)
    res   = indexer_client.search(index=ALERT_INDICES, ignore_unavailable=True, body=q)
    total = res["hits"]["total"]["value"] if isinstance(res["hits"]["total"], dict) else res["hits"]["total"]
    hits  = res.get("hits", {}).get("hits", [])
    return {
        "entity_type": entity_type,
        "value":       value,
        "total_hits":  total,
        "query_used":  q["query"],
        "sample_sources": [h["_source"].get("data", {}).get("integration", "wazuh") for h in hits],
    }


@app.get("/stats")
def get_stats(
    hours: Optional[int] = Query(None, description="Time window in hours"),
    _user: dict = Depends(get_current_user),
):
    filters = []
    if hours:
        filters.append({
            "range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}
        })

    query = {
        "size":             0,
        "track_total_hits": True,
        "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
        "aggs": {
            "by_level": {
                "range": {
                    "field": "rule.level",
                    "ranges": [
                        {"key": "Low",      "to": 7},
                        {"key": "Medium",   "from": 7,  "to": 12},
                        {"key": "High",     "from": 12, "to": 15},
                        {"key": "Critical", "from": 15},
                    ]
                }
            },
            "by_source": {
                "filters": {
                    "filters": {
                        "darktrace":      {"term": {"rule.groups": "darktrace"}},
                        "sophos-central": {"term": {"data.integration": "sophos-central"}},
                        "ms-graph":       {"term": {"data.integration": "ms-graph"}},
                        "ms-defender":    {"term": {"data.integration": "ms-defender"}},
                        "wazuh": {
                            "bool": {
                                "must_not": [
                                    {"exists": {"field": "data.integration"}},
                                    {"term": {"rule.groups": "darktrace"}},
                                ]
                            }
                        },
                    }
                }
            },
            "ioc_alerts": {
                "filter": {
                    "bool": {
                        "must": [
                            {"term":  {"misp.enriched":  True}},
                            {"range": {"misp.hit_count": {"gte": 1}}},
                        ]
                    }
                }
            },
            "sophos_sev": {
                "filter": {"term": {"data.integration": "sophos-central"}},
                "aggs": {
                    "by_sev": {"terms": {"field": "data.sophos.severity", "size": 10}}
                }
            },
            "defender_sev": {
                "filter": {"term": {"data.integration": "ms-defender"}},
                "aggs": {
                    "by_sev": {"terms": {"field": "data.defender.severity", "size": 10}}
                }
            },
        }
    }

    res   = indexer_client.search(index=ALERT_INDICES, ignore_unavailable=True, body=query)
    total = res["hits"]["total"]["value"] if isinstance(res["hits"]["total"], dict) else res["hits"]["total"]
    aggs  = res.get("aggregations", {})

    by_severity = {
        b["key"]: b["doc_count"]
        for b in aggs.get("by_level", {}).get("buckets", [])
        if b["doc_count"] > 0
    }
    by_source = {
        name: bucket["doc_count"]
        for name, bucket in aggs.get("by_source", {}).get("buckets", {}).items()
        if bucket["doc_count"] > 0
    }

    ioc_count = aggs.get("ioc_alerts", {}).get("doc_count", 0)

    def _sev_map(agg: dict) -> dict:
        return {
            b["key"].capitalize(): b["doc_count"]
            for b in agg.get("by_sev", {}).get("buckets", [])
            if b["doc_count"] > 0
        }

    by_source_severity: dict = {}
    if aggs.get("sophos_sev", {}).get("doc_count", 0) > 0:
        by_source_severity["sophos-central"] = _sev_map(aggs["sophos_sev"])
    if aggs.get("defender_sev", {}).get("doc_count", 0) > 0:
        by_source_severity["ms-defender"] = _sev_map(aggs["defender_sev"])

    return {
        "total":               total,
        "by_severity":         by_severity,
        "by_source":           by_source,
        "by_source_severity":  by_source_severity,
        "ioc_count":           ioc_count,
    }


@app.get("/alerts", response_model=AlertsPage)
def get_alerts(
    limit:    int            = Query(50,   ge=1, le=200),
    offset:   int            = Query(0,    ge=0),
    source:   Optional[str] = Query(None, description="wazuh | sophos-central | ms-graph | darktrace"),
    severity: Optional[str] = Query(None, description="Low | Medium | High | Critical"),
    hours:    Optional[int] = Query(None, description="Time window in hours, e.g. 1, 24, 168, 720"),
    q:        Optional[str] = Query(None, description="Full-text search across rule description, agent name, log"),
    ioc_only: bool           = Query(False, description="Only return alerts with MISP IOC hits"),
    _user:    dict           = Depends(get_current_user),
):
    query  = build_alert_query(limit, offset, source, severity, hours, q, ioc_only)
    result = indexer_client.search(index=ALERT_INDICES, ignore_unavailable=True, body=query)
    total  = result["hits"]["total"]["value"] if isinstance(result["hits"]["total"], dict) else result["hits"]["total"]
    return {
        "total":  total,
        "events": [normalizer.normalize(hit) for hit in result["hits"]["hits"]],
    }


@app.post("/investigate", response_model=InvestigateResponse)
def investigate(req: InvestigateRequest, _user: dict = Depends(get_current_user)):
    q = build_investigation_query(
        entity_type=req.entity_type,
        value=req.value,
        start=req.start,
        end=req.end,
        size=req.limit,
        offset=req.offset,
        severities=req.severities,
    )

    res  = indexer_client.search(index=ALERT_INDICES, ignore_unavailable=True, body=q)
    hits = res.get("hits", {}).get("hits", [])

    unified = [normalizer.normalize(h) for h in hits]

    aggs       = res.get("aggregations", {})
    # by_source uses a filters agg (returns a dict of name→bucket, not a list)
    by_source_buckets = aggs.get("by_source", {}).get("buckets", {})
    by_source = {
        name: b["doc_count"]
        for name, b in by_source_buckets.items()
        if b["doc_count"] > 0
    }
    by_severity: dict = {}
    for b in aggs.get("by_rule_level", {}).get("buckets", []):
        sev = rule_level_to_severity(int(b["key"]))
        by_severity[sev] = by_severity.get(sev, 0) + b["doc_count"]

    total = res["hits"]["total"]["value"] if isinstance(res["hits"]["total"], dict) else res["hits"]["total"]

    return {
        "entity": {"type": req.entity_type, "value": req.value},
        "summary": {
            "total":       total,
            "by_source":   by_source,
            "by_severity": by_severity,
            "timeline":    aggs.get("timeline", {}).get("buckets", []),
        },
        "related": build_related(unified),
        "events":  unified,
    }

# ── Sophos Central endpoints ──────────────────────────────────────────────────
# NOTE: static routes (/search, /health/summary) must come before /{endpoint_id}
# so FastAPI doesn't swallow them as a path parameter.

def _sophos_http_error(e: Exception) -> HTTPException:
    """Convert a SophosAPIError to an HTTPException, preserving the status code."""
    if isinstance(e, SophosAPIError):
        return HTTPException(status_code=e.status_code, detail=e.detail)
    return HTTPException(status_code=500, detail=str(e))


@app.get("/endpoints/search")
def search_endpoints(
    ip:       Optional[str] = Query(None, description="IPv4 address to match"),
    hostname: Optional[str] = Query(None, description="Hostname to match (exact)"),
):
    """Find a device by IP or hostname — used for Wazuh alert correlation."""
    try:
        devices = list_devices(sophos_client)
        results = []
        for d in devices:
            if ip       and ip in d.get("ipv4Addresses", []):
                results.append(normalize_device(d))
            elif hostname and hostname.lower() == (d.get("hostname") or "").lower():
                results.append(normalize_device(d))
        return {"total": len(results), "devices": results}
    except Exception as e:
        raise _sophos_http_error(e)


@app.get("/endpoints/health/summary")
def health_summary():
    """Count of devices by health status."""
    try:
        devices = list_devices(sophos_client)
        summary: dict[str, int] = {"good": 0, "suspicious": 0, "bad": 0, "unknown": 0}
        for d in devices:
            status = d.get("health", {}).get("overall") or "unknown"
            summary[status] = summary.get(status, 0) + 1
        return {"total": len(devices), **summary}
    except Exception as e:
        raise _sophos_http_error(e)


@app.get("/endpoints")
def get_endpoints(
    health:   Optional[str] = Query(None, description="good | suspicious | bad"),
    type:     Optional[str] = Query(None, description="computer | server | securityVm"),
    lockdown: Optional[str] = Query(None, description="locked | notInstalled | installing | ..."),
):
    """List all Sophos endpoints with optional server-side filtering."""
    try:
        devices = list_devices(
            sophos_client,
            health_status=health,
            device_type=type,
            lockdown_status=lockdown,
        )
        return {
            "total":   len(devices),
            "devices": [normalize_device(d) for d in devices],
        }
    except Exception as e:
        raise _sophos_http_error(e)


@app.get("/endpoints/{endpoint_id}")
def get_endpoint(endpoint_id: str):
    """Get a single endpoint by ID."""
    try:
        device = get_device(sophos_client, endpoint_id)
        return normalize_device(device)
    except Exception as e:
        raise _sophos_http_error(e)


@app.post("/endpoints/{endpoint_id}/isolate")
def isolate_endpoint(
    endpoint_id: str,
    comment: str = Query("Isolated via SIEM", description="Reason for isolation"),
):
    """Isolate a Sophos endpoint."""
    try:
        isolate_device(sophos_client, endpoint_id, comment)
        return {"endpoint_id": endpoint_id, "isolated": True, "comment": comment}
    except Exception as e:
        raise _sophos_http_error(e)


@app.post("/endpoints/{endpoint_id}/unisolate")
def unisolate_endpoint(
    endpoint_id: str,
    comment: str = Query("Released via SIEM", description="Reason for releasing isolation"),
):
    """Release a Sophos endpoint from isolation."""
    try:
        unisolate_device(sophos_client, endpoint_id, comment)
        return {"endpoint_id": endpoint_id, "isolated": False, "comment": comment}
    except Exception as e:
        raise _sophos_http_error(e)


@app.get("/endpoints/{endpoint_id}/health")
def get_endpoint_health(endpoint_id: str):
    """Return the raw Sophos health object for the health dialog."""
    try:
        device = get_device(sophos_client, endpoint_id)
        return device.get("health", {})
    except Exception as e:
        raise _sophos_http_error(e)


@app.post("/endpoints/{endpoint_id}/scan")
def scan_endpoint(endpoint_id: str):
    """Trigger an on-demand scan on a Sophos endpoint."""
    try:
        return sophos_client.request("POST", f"/endpoint/v1/endpoints/{endpoint_id}/scans", payload={})
    except Exception as e:
        raise _sophos_http_error(e)


@app.post("/endpoints/{endpoint_id}/update-check")
def update_check_endpoint(endpoint_id: str):
    """Trigger a software update check on a Sophos endpoint."""
    try:
        return sophos_client.request("POST", f"/endpoint/v1/endpoints/{endpoint_id}/update-checks", payload={})
    except Exception as e:
        raise _sophos_http_error(e)


@app.get("/endpoints/{endpoint_id}/tamper-protection")
def get_tamper_protection(endpoint_id: str):
    """Get tamper protection status for a Sophos endpoint."""
    try:
        return sophos_client.request("GET", f"/endpoint/v1/endpoints/{endpoint_id}/tamper-protection")
    except Exception as e:
        raise _sophos_http_error(e)



@app.post("/endpoints/{endpoint_id}/tamper-protection")
def set_tamper_protection(
    endpoint_id: str,
    enabled: bool = Query(..., description="true to enable, false to disable"),
):
    """Enable or disable tamper protection on a Sophos endpoint."""
    try:
        return sophos_client.request(
            "POST",
            f"/endpoint/v1/endpoints/{endpoint_id}/tamper-protection",
            payload={"enabled": enabled},
        )
    except Exception as e:
        raise _sophos_http_error(e)


# ── Nessus endpoints ──────────────────────────────────────────────────────────

_NESSUS_SEV: dict[int, str] = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def _nessus_error(e: Exception) -> HTTPException:
    return HTTPException(status_code=502, detail=str(e))


@app.get("/nessus/folders")
def nessus_folders():
    try:
        data      = nessus_client.get("/scans")
        folders   = data.get("folders", []) or []
        scans     = data.get("scans",   []) or []
        by_folder: dict[int, list] = {}
        for scan in scans:
            fid = scan.get("folder_id")
            if fid is not None:
                by_folder.setdefault(fid, []).append(scan)
        result = [
            {
                "id":    f.get("id"),
                "name":  f.get("name", ""),
                "type":  f.get("type", ""),
                "scans": by_folder.get(f.get("id"), []),
            }
            for f in folders
        ]
        return {"folders": result}
    except Exception as e:
        raise _nessus_error(e)


@app.get("/nessus/scans/{scan_id}")
def nessus_scan_detail(scan_id: int, history_id: Optional[int] = Query(None)):
    try:
        params = {"history_id": history_id} if history_id is not None else None
        data   = nessus_client.get(f"/scans/{scan_id}", params=params)
        raw     = data.get("info", {})
        info    = {
            "id":         scan_id,
            "name":       raw.get("object_name") or raw.get("name", ""),
            "status":     raw.get("status", ""),
            "targets":    raw.get("targets", ""),
            "scan_start": raw.get("scan_start"),
            "scan_end":   raw.get("scan_end"),
        }
        hosts = [
            {
                "host_id":  h.get("host_id"),
                "hostname": h.get("hostname", ""),
                "critical": h.get("critical", 0),
                "high":     h.get("high", 0),
                "medium":   h.get("medium", 0),
                "low":      h.get("low", 0),
                "info":     h.get("info", 0),
            }
            for h in data.get("hosts", [])
        ]
        vulns = [
            {
                "plugin_id":     v.get("plugin_id"),
                "plugin_name":   v.get("plugin_name", ""),
                "severity":      v.get("severity", 0),
                "severity_label": _NESSUS_SEV.get(v.get("severity", 0), "info"),
                "count":         v.get("count", 1),
                "vuln_index":    v.get("vuln_index", 0),
            }
            for v in data.get("vulnerabilities", [])
        ]
        history = [
            {
                "history_id":             h.get("history_id"),
                "uuid":                   h.get("uuid", ""),
                "status":                 h.get("status", ""),
                "creation_date":          h.get("creation_date"),
                "last_modification_date": h.get("last_modification_date"),
            }
            for h in data.get("history", [])
        ]
        return {"info": info, "hosts": hosts, "vulnerabilities": vulns, "history": history}
    except Exception as e:
        raise _nessus_error(e)


@app.post("/nessus/scans/{scan_id}/export")
def nessus_export(scan_id: int, body: NessusExportRequest = NessusExportRequest()):
    fmt = body.format
    try:
        payload: dict = {"format": fmt}
        if fmt in ("csv", "html"):
            payload["chapters"] = "vuln_by_host"
        resp    = nessus_client.post(f"/scans/{scan_id}/export", payload)
        file_id = resp.get("file") or resp.get("token")
        if not file_id:
            raise HTTPException(status_code=502, detail="Nessus did not return an export token")
        for _ in range(30):
            time.sleep(2)
            status = nessus_client.get(f"/scans/{scan_id}/export/{file_id}/status")
            if status.get("status") == "ready":
                break
        else:
            raise HTTPException(status_code=504, detail="Export timed out after 60 s")
        content    = nessus_client.download(f"/scans/{scan_id}/export/{file_id}/download")
        media_type = {"csv": "text/csv", "html": "text/html", "nessus": "application/xml"}.get(fmt, "application/octet-stream")
        return Response(content=content, media_type=media_type)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


# ── JIRA endpoints ────────────────────────────────────────────────────────────

@app.get("/jira/tickets")
def list_jira_tickets(
    status:      Optional[str] = Query(None, description="open | all"),
    severity:    Optional[str] = Query(None, description="critical | high"),
    max_results: int           = Query(50, ge=1, le=200),
):
    """Return JIRA tickets labelled siem-auto (SIEM-generated tickets)."""
    if not jira_client.configured:
        raise HTTPException(status_code=503, detail="JIRA is not configured")

    jql_parts = [f'project = "{jira_client.project}"', 'labels = "siem-auto"']
    if not status or status == "open":
        jql_parts.append("statusCategory != Done")
    if severity:
        jql_parts.append(f'labels = "siem-{severity.lower()}"')
    jql = " AND ".join(jql_parts) + " ORDER BY created DESC"

    try:
        r = jira_client._session.post(
            f"{jira_client.base_url}/rest/api/3/search/jql",
            json={
                "jql":        jql,
                "fields":     ["summary", "status", "priority", "created", "labels", "assignee"],
                "maxResults": max_results,
            },
            timeout=15,
        )
        r.raise_for_status()
        data   = r.json()
        sev_labels = {"siem-critical", "siem-high", "siem-medium", "siem-low"}

        tickets = []
        for issue in data.get("issues", []):
            f      = issue.get("fields", {})
            labels = f.get("labels", [])
            sev    = next((l.replace("siem-", "") for l in labels if l in sev_labels), "")
            tickets.append({
                "key":             issue["key"],
                "url":             f"{jira_client.base_url}/browse/{issue['key']}",
                "summary":         f.get("summary", ""),
                "status":          (f.get("status") or {}).get("name", ""),
                "status_category": (f.get("status") or {}).get("statusCategory", {}).get("key", ""),
                "priority":        (f.get("priority") or {}).get("name", ""),
                "created":         f.get("created", ""),
                "assignee":        ((f.get("assignee") or {}).get("displayName")) or "Unassigned",
                "severity":        sev,
                "labels":          labels,
            })
        return {"total": data.get("total", len(tickets)), "tickets": tickets}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"JIRA API error: {e}")


@app.get("/jira/issue-types")
def jira_issue_types():
    """List available issue types for the configured JIRA project."""
    r = jira_client._session.get(
        f"{jira_client.base_url}/rest/api/3/project/{jira_client.project}",
        timeout=15,
    )
    if not r.ok:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    data = r.json()
    return {
        "project_key":  data.get("key"),
        "project_name": data.get("name"),
        "issue_types":  [{"id": t["id"], "name": t["name"]} for t in data.get("issueTypes", [])],
    }

import re as _re


def _build_adf(blocks: list[dict]) -> dict:
    return {"version": 1, "type": "doc", "content": blocks}


def _para(*texts: str) -> dict:
    return {"type": "paragraph", "content": [{"type": "text", "text": t} for t in texts]}


def _heading(text: str, level: int = 3) -> dict:
    return {"type": "heading", "attrs": {"level": level},
            "content": [{"type": "text", "text": text}]}


def _bullet(items: list[str]) -> dict:
    return {
        "type": "bulletList",
        "content": [
            {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": item}]}]}
            for item in items
        ],
    }


def _link_para(label: str, url: str) -> dict:
    return {
        "type": "paragraph",
        "content": [
            {"type": "text", "text": f"{label}: "},
            {"type": "text", "text": url,
             "marks": [{"type": "link", "attrs": {"href": url}}]},
        ],
    }


def _build_defender_description(req: JiraTicketRequest) -> dict:
    raw   = req.raw or {}
    mitre = req.mitre or []
    blocks: list[dict] = []

    # ── Overview ────────────────────────────────────────────────────────────────
    blocks.append(_heading("Overview", 2))
    overview = [
        f"Time: {req.time}",
        f"Severity: {req.severity}",
        f"Status: {raw.get('status', '—')}",
        f"Category: {raw.get('category', req.category)}",
        f"Service source: {raw.get('service_source', '—')}",
        f"Detection source: {raw.get('detection_source', '—')}",
    ]
    if raw.get("classification"):  overview.append(f"Classification: {raw['classification']}")
    if raw.get("determination"):   overview.append(f"Determination: {raw['determination']}")
    if raw.get("threat_family"):   overview.append(f"Threat family: {raw['threat_family']}")
    if raw.get("actor"):           overview.append(f"Threat actor: {raw['actor']}")
    if raw.get("assigned_to"):     overview.append(f"Assigned to: {raw['assigned_to']}")
    if raw.get("first_activity"):  overview.append(f"First activity: {raw['first_activity']}")
    if raw.get("last_activity"):   overview.append(f"Last activity: {raw['last_activity']}")
    if req.user:                   overview.append(f"User: {req.user}")
    if req.host:                   overview.append(f"Device: {req.host}")
    if req.src_ip:                 overview.append(f"IP: {req.src_ip}")
    blocks.append(_bullet(overview))

    # ── Defender portal links ────────────────────────────────────────────────────
    if raw.get("alert_url") or raw.get("incident_url"):
        blocks.append(_heading("Defender Portal Links", 3))
        if raw.get("alert_url"):    blocks.append(_link_para("Alert", raw["alert_url"]))
        if raw.get("incident_url"): blocks.append(_link_para("Incident", raw["incident_url"]))

    # ── Description ─────────────────────────────────────────────────────────────
    if raw.get("description"):
        blocks.append(_heading("Alert Description", 3))
        blocks.append(_para(raw["description"]))

    # ── MITRE techniques ────────────────────────────────────────────────────────
    if mitre:
        blocks.append(_heading("MITRE ATT&CK Techniques", 3))
        mitre_items = []
        for t in mitre:
            tid  = t.get("id") or t.get("technique", "")
            name = t.get("technique") or tid
            tacs = ", ".join(t.get("tactics") or [])
            line = f"{tid} — {name}" if name != tid else tid
            if tacs: line += f"  [{tacs}]"
            mitre_items.append(line)
        blocks.append(_bullet(mitre_items))

    # ── Evidence ────────────────────────────────────────────────────────────────
    ev_keys = [k for k in raw if _re.match(r'^(file|process|network|ip|url|email|device|user|mailbox)(_\d+)?$', k)]
    if ev_keys:
        blocks.append(_heading("Evidence", 3))
        ev_items = []
        for k in sorted(ev_keys):
            ev = raw[k]
            if not isinstance(ev, dict): continue
            parts = [f"{ek}: {ev[ek]}" for ek in sorted(ev) if ev[ek] and ek != "verdict" and ek != "remediation"]
            if parts: ev_items.append(f"[{k}]  " + " | ".join(parts[:6]))
        if ev_items: blocks.append(_bullet(ev_items))

    # ── Analyst comments ────────────────────────────────────────────────────────
    comment_keys = sorted(k for k in raw if k.startswith("comment_"))
    if comment_keys:
        blocks.append(_heading("Analyst Comments", 3))
        blocks.append(_bullet([str(raw[k]) for k in comment_keys]))

    # ── IDs ─────────────────────────────────────────────────────────────────────
    id_info = [f"Alert ID: {raw.get('alert_id', req.event_id)}"]
    if raw.get("incident_id"): id_info.append(f"Incident ID: {raw['incident_id']}")
    id_info.append(f"SIEM Event ID: {req.event_id}")
    blocks.append(_heading("Reference IDs", 3))
    blocks.append(_bullet(id_info))

    return _build_adf(blocks)


@app.post("/jira/tickets/batch-check")
def batch_check_jira_tickets(req: JiraBatchCheckRequest):
    """Given a list of event IDs, return a map of event_id → {key, url} for any that already have JIRA tickets."""
    if not jira_client.configured or not req.event_ids:
        return {"tickets": {}}

    safe_map = {eid: f"siem-{_re.sub(r'[^a-zA-Z0-9_-]', '_', eid)}" for eid in req.event_ids}
    label_list = ", ".join(f'"{lbl}"' for lbl in safe_map.values())
    jql = f'project = "{jira_client.project}" AND labels in ({label_list}) ORDER BY created DESC'

    try:
        r = jira_client._session.post(
            f"{jira_client.base_url}/rest/api/3/search/jql",
            json={"jql": jql, "fields": ["key", "labels"], "maxResults": len(req.event_ids)},
            timeout=15,
        )
        r.raise_for_status()
        result: dict = {}
        for issue in r.json().get("issues", []):
            issue_labels = set(issue["fields"].get("labels", []))
            for eid, lbl in safe_map.items():
                if lbl in issue_labels and eid not in result:
                    result[eid] = {
                        "key": issue["key"],
                        "url": f"{jira_client.base_url}/browse/{issue['key']}",
                    }
        return {"tickets": result}
    except Exception:
        return {"tickets": {}}  # silently fail — frontend falls back gracefully


@app.get("/jira/assignees")
def get_jira_assignees():
    """Return users assignable to the SIEM JIRA project."""
    if not jira_client.configured:
        raise HTTPException(status_code=503, detail="JIRA is not configured")
    try:
        r = jira_client._session.get(
            f"{jira_client.base_url}/rest/api/3/user/assignable/search",
            params={"project": jira_client.project, "maxResults": 100},
            timeout=15,
        )
        r.raise_for_status()
        return {
            "assignees": [
                {
                    "account_id":   u["accountId"],
                    "display_name": u.get("displayName", ""),
                    "avatar_url":   u.get("avatarUrls", {}).get("24x24", ""),
                }
                for u in r.json()
                if u.get("accountType") == "atlassian"
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"JIRA API error: {e}")


@app.put("/jira/tickets/{key}/assignee")
def assign_jira_ticket(key: str, req: JiraAssignRequest):
    """Assign a JIRA ticket to a user by accountId."""
    if not jira_client.configured:
        raise HTTPException(status_code=503, detail="JIRA is not configured")
    try:
        r = jira_client._session.put(
            f"{jira_client.base_url}/rest/api/3/issue/{key}/assignee",
            json={"accountId": req.account_id},
            timeout=15,
        )
        r.raise_for_status()
        return {"key": key, "assigned": True}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"JIRA API error: {e}")


def _ensure_jira_ticket(ev: dict) -> dict | None:
    """
    Idempotent: create a JIRA ticket for a normalized event if one doesn't exist yet.
    Returns {"key", "url", "created"} or None on any error.
    Used by both the HTTP endpoint and the background auto-ticket loop.
    """
    if not jira_client.configured:
        return None

    event_id = ev.get("event_id", "")
    safe_id  = _re.sub(r"[^a-zA-Z0-9_-]", "_", event_id)
    label    = f"siem-{safe_id}"

    try:
        existing = jira_client.find_by_label(label)
        if existing:
            return {"key": existing, "url": f"{jira_client.base_url}/browse/{existing}", "created": False}
    except Exception:
        pass  # search failure → attempt creation anyway

    req = JiraTicketRequest(
        event_id = event_id,
        time     = ev.get("time", ""),
        severity = ev.get("severity", ""),
        source   = ev.get("source", ""),
        category = ev.get("category", ""),
        summary  = ev.get("summary", ""),
        user     = ev.get("user"),
        host     = ev.get("host"),
        src_ip   = ev.get("src_ip"),
        raw      = ev.get("raw"),
        mitre    = ev.get("mitre"),
    )

    if req.source == "ms-defender":
        description = _build_defender_description(req)
    else:
        details = [
            f"Time: {req.time}",
            f"Source: {req.source}",
            f"Severity: {req.severity}",
            f"Category: {req.category}",
        ]
        if req.user:   details.append(f"User: {req.user}")
        if req.host:   details.append(f"Host: {req.host}")
        if req.src_ip: details.append(f"Source IP: {req.src_ip}")
        details.append(f"Event ID: {req.event_id}")
        description = _build_adf([
            _para(f"SIEM Alert automatically escalated — Severity: {req.severity}"),
            _para(f"Summary: {req.summary}"),
            _bullet(details),
        ])

    labels = ["siem-auto", label, f"siem-{req.severity.lower()}"]

    try:
        result = jira_client.create_issue(
            summary     = f"[{req.severity}] {req.summary[:200]}",
            description = description,
            labels      = labels,
        )
        key = result["key"]
        return {"key": key, "url": f"{jira_client.base_url}/browse/{key}", "created": True}
    except Exception as exc:
        log.error("JIRA create_issue failed for event %s: %s", event_id, exc)
        return None


@app.post("/jira/tickets")
def create_jira_ticket(req: JiraTicketRequest):
    if not jira_client.configured:
        raise HTTPException(status_code=503, detail="JIRA is not configured — check JIRA_BASE_URL and JIRA_PROJECT_KEY")

    result = _ensure_jira_ticket({
        "event_id": req.event_id,
        "time":     req.time,
        "severity": req.severity,
        "source":   req.source,
        "category": req.category,
        "summary":  req.summary,
        "user":     req.user,
        "host":     req.host,
        "src_ip":   req.src_ip,
        "raw":      req.raw,
        "mitre":    req.mitre,
    })
    if result is None:
        raise HTTPException(status_code=502, detail="JIRA API error — check gateway logs")
    return result


# ── VirusTotal endpoints ──────────────────────────────────────────────────────

def _vt_error(e: Exception) -> HTTPException:
    if isinstance(e, VirusTotalError):
        return HTTPException(status_code=e.status_code, detail=e.detail)
    return HTTPException(status_code=500, detail=str(e))


@app.get("/vt/ip/{ip}")
def vt_lookup_ip(ip: str, _user: dict = Depends(get_current_user)):
    """Query VirusTotal for an IP address reputation."""
    try:
        return lookup_ip(ip)
    except Exception as e:
        raise _vt_error(e)


@app.get("/vt/domain/{domain:path}")
def vt_lookup_domain(domain: str, _user: dict = Depends(get_current_user)):
    """Query VirusTotal for a domain reputation."""
    try:
        return lookup_domain(domain)
    except Exception as e:
        raise _vt_error(e)


@app.get("/vt/hash/{hash_value}")
def vt_lookup_hash(hash_value: str, _user: dict = Depends(get_current_user)):
    """Query VirusTotal for a file hash (MD5, SHA1, or SHA256)."""
    try:
        return lookup_hash(hash_value)
    except Exception as e:
        raise _vt_error(e)


# ── Custom dashboards ─────────────────────────────────────────────────────────

def _owner(user: dict, request: Request = None) -> str:
    # JWT claims are the trusted source when a token is present
    from_jwt = (
        user.get("preferred_username")
        or user.get("unique_name")
        or user.get("sub")
    )
    if from_jwt:
        return from_jwt
    # Fallback: custom header sent by the frontend from the MSAL account object.
    # The user is already authenticated via Azure AD (auth guard), so this is
    # safe for an internal tool where we trust the client session.
    if request:
        header = request.headers.get("X-SIEM-Owner", "").strip()
        if header:
            return header
    return "anonymous"


# ── Microsoft Defender direct endpoints ───────────────────────────────────────

def _defender_error(e: Exception) -> HTTPException:
    if isinstance(e, DefenderClientError):
        return HTTPException(status_code=e.status_code, detail=e.detail)
    return HTTPException(status_code=500, detail=str(e))


@app.post("/defender/ingest")
def defender_ingest_now(
    hours: int = Query(24, ge=1, le=168, description="How many hours back to pull"),
    _user: dict = Depends(get_current_user),
):
    """Trigger an immediate Defender alert ingest for the last N hours."""
    global _defender_last_poll, _defender_last_error
    if not defender_client.configured:
        raise HTTPException(status_code=503, detail="DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET not configured")
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(tz=timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        result = defender_ingest(defender_client, indexer_client, since_iso=since)
        _defender_last_poll  = since
        _defender_last_error = None
        return result
    except Exception as e:
        _defender_last_error = str(e)
        raise _defender_error(e)


@app.get("/defender/status")
def defender_status(_user: dict = Depends(get_current_user)):
    """Check Defender integration configuration, last poll time, and last error."""
    return {
        "configured":         defender_client.configured,
        "last_poll":          _defender_last_poll,
        "last_error":         _defender_last_error,
        "poll_interval_secs": DEFENDER_POLL_SECS,
    }


@app.get("/defender/alerts")
def defender_alerts(
    limit:    int           = Query(50,  ge=1, le=200),
    offset:   int           = Query(0,   ge=0),
    severity: Optional[str] = Query(None, description="high | medium | low | informational"),
    hours:    Optional[int] = Query(None, description="Time window in hours"),
    q:        Optional[str] = Query(None, description="Full-text search"),
    _user:    dict          = Depends(get_current_user),
):
    """List normalized Defender alerts from OpenSearch (already ingested)."""
    query = build_alert_query(limit, offset, "ms-defender", severity, hours, q)
    result = indexer_client.search(index=ALERT_INDICES, ignore_unavailable=True, body=query)
    total  = result["hits"]["total"]["value"] if isinstance(result["hits"]["total"], dict) else result["hits"]["total"]
    return {
        "total":  total,
        "events": [normalizer.normalize(hit) for hit in result["hits"]["hits"]],
    }


@app.get("/defender/debug/raw-alerts")
def defender_debug_raw_alerts(
    top:   int           = Query(3,    ge=1, le=10),
    hours: Optional[int] = Query(None, description="Filter to last N hours"),
    _user: dict          = Depends(get_current_user),
):
    """
    Fetch raw alerts straight from Graph API (no normalization, no OpenSearch).
    Use this to verify Graph API connectivity and inspect the exact response shape.
    """
    if not defender_client.configured:
        raise HTTPException(status_code=503, detail="DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET not configured")
    from datetime import datetime, timedelta, timezone
    since = None
    if hours:
        since = (datetime.now(tz=timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        raw_alerts = defender_client.get_alerts(since_iso=since, top=top)
        sample = raw_alerts[:top]
        # Show key fields + evidence/comments shape without full dump
        previews = []
        for a in sample:
            previews.append({
                "id":               a.get("id"),
                "title":            a.get("title"),
                "severity":         a.get("severity"),
                "status":           a.get("status"),
                "category":         a.get("category"),
                "createdDateTime":  a.get("createdDateTime"),
                "incidentId":       a.get("incidentId"),
                "evidence_count":   len(a.get("evidence") or []),
                "comments_count":   len(a.get("comments") or []),
                "evidence_types":   list({(e.get("@odata.type") or "unknown") for e in (a.get("evidence") or [])}),
                "top_keys":         sorted(a.keys()),
            })
        return {
            "total_fetched": len(raw_alerts),
            "since":         since,
            "sample":        previews,
        }
    except Exception as e:
        raise _defender_error(e)


@app.post("/defender/hunt")
def defender_hunt(
    body: dict,
    _user: dict = Depends(get_current_user),
):
    """
    Run a Microsoft Defender Advanced Hunting KQL query.

    Body: {"query": "KQL string", "timeout_secs": 30}

    Requires ThreatHunting.Read.All permission on the Azure AD app.
    Returns {"schema": [...], "results": [..., row_dicts]}.
    """
    if not defender_client.configured:
        raise HTTPException(status_code=503, detail="DEFENDER_CLIENT_ID / DEFENDER_CLIENT_SECRET not configured")
    kql     = (body.get("query") or "").strip()
    timeout = min(int(body.get("timeout_secs", 30)), 90)
    if not kql:
        raise HTTPException(status_code=422, detail="query is required")
    try:
        raw = defender_client.run_hunting_query(kql, timeout_secs=timeout)
        return {
            "schema":  raw.get("schema", []),
            "results": raw.get("results", []),
            "total":   len(raw.get("results", [])),
        }
    except Exception as e:
        raise _defender_error(e)


# ── Wazuh Server API proxy endpoints ─────────────────────────────────────────

def _wazuh_server_unavailable():
    return HTTPException(
        status_code=503,
        detail="Wazuh Server API not configured — set WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASS",
    )


@app.get("/wazuh/ping")
def wazuh_ping(_user: dict = Depends(get_current_user)):
    """Diagnostic: test Wazuh Server API connectivity and auth, return detailed status."""
    if not wazuh_server_client.configured:
        return {
            "ok": False,
            "stage": "config",
            "detail": "Missing WAZUH_API_URL, WAZUH_API_USER or WAZUH_API_PASS",
            "url": wazuh_server_client.base_url or "(not set)",
            "user": wazuh_server_client._user or "(not set)",
            "has_password": bool(wazuh_server_client._password),
        }
    try:
        wazuh_server_client._authenticate()
        return {
            "ok": True,
            "stage": "auth",
            "detail": "Authentication succeeded — JWT token obtained",
            "url": wazuh_server_client.base_url,
            "user": wazuh_server_client._user,
        }
    except Exception as exc:
        log.error("Wazuh ping auth failed: %s", exc)
        return {
            "ok": False,
            "stage": "auth",
            "detail": str(exc),
            "url": wazuh_server_client.base_url,
            "user": wazuh_server_client._user,
        }


@app.get("/wazuh/agents/")
def get_wazuh_agents(
    limit:  int           = Query(200, ge=1,  le=500),
    offset: int           = Query(0,   ge=0),
    status: Optional[str] = Query(None, description="active | disconnected | pending | never_connected"),
    search: Optional[str] = Query(None),
    _user:  dict          = Depends(get_current_user),
):
    if not wazuh_server_client.configured:
        raise _wazuh_server_unavailable()
    params: dict = {"limit": limit, "offset": offset}
    if status: params["status"] = status
    if search: params["search"] = search
    try:
        return wazuh_server_client.get("/agents", params)
    except Exception as exc:
        log.error("Wazuh /agents error: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/wazuh/rules/")
def get_wazuh_rules(
    limit:  int           = Query(500, ge=1,  le=2000),
    offset: int           = Query(0,   ge=0),
    level:  Optional[int] = Query(None, description="Minimum rule level"),
    search: Optional[str] = Query(None),
    _user:  dict          = Depends(get_current_user),
):
    if not wazuh_server_client.configured:
        raise _wazuh_server_unavailable()
    params: dict = {"limit": limit, "offset": offset}
    if level is not None: params["level"] = level
    if search:            params["search"] = search
    try:
        return wazuh_server_client.get("/rules", params)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh API error: {exc}")


@app.get("/wazuh/decoders/")
def get_wazuh_decoders(
    limit:  int           = Query(500, ge=1,  le=2000),
    offset: int           = Query(0,   ge=0),
    search: Optional[str] = Query(None),
    _user:  dict          = Depends(get_current_user),
):
    if not wazuh_server_client.configured:
        raise _wazuh_server_unavailable()
    params: dict = {"limit": limit, "offset": offset}
    if search: params["search"] = search
    try:
        return wazuh_server_client.get("/decoders", params)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh API error: {exc}")


@app.get("/wazuh/summary/")
def get_wazuh_summary(_user: dict = Depends(get_current_user)):
    if not wazuh_server_client.configured:
        raise _wazuh_server_unavailable()
    try:
        return wazuh_server_client.get("/manager/info")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wazuh API error: {exc}")


# ── Defender background poller ────────────────────────────────────────────────

async def _defender_poll_loop() -> None:
    """Runs as a background asyncio task; polls Defender every DEFENDER_POLL_SECS seconds."""
    global _defender_last_poll, _defender_last_error
    from datetime import datetime, timedelta, timezone as tz
    from integrations.ms_defender import DEFENDER_LOOKBACK_HOURS
    since = (datetime.now(tz=tz.utc) - timedelta(hours=DEFENDER_LOOKBACK_HOURS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    while True:
        try:
            result = await asyncio.to_thread(
                defender_ingest, defender_client, indexer_client, since
            )
            _defender_last_poll  = since
            _defender_last_error = None
            log.info("Defender poller: ingested=%d errors=%d since=%s",
                     result.get("ingested", 0), result.get("errors", 0), since)
            since = datetime.now(tz=tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception as exc:
            _defender_last_error = str(exc)
            log.error("Defender poller error: %s", exc)
        await asyncio.sleep(DEFENDER_POLL_SECS)


@app.on_event("startup")
async def _start_defender_poller():
    if defender_client.configured:
        # Apply index template first, then remove any stale indices built without it
        defender_ensure_template(indexer_client)
        defender_delete_stale(indexer_client)
        asyncio.create_task(_defender_poll_loop())
        log.info("Defender background poller started (interval=%ds, tenant=%s, client=%s)",
                 DEFENDER_POLL_SECS, defender_client.tenant_id[:8] + "…", defender_client.client_id[:8] + "…")
    else:
        log.warning("Defender not configured — set DEFENDER_CLIENT_ID and DEFENDER_CLIENT_SECRET")


# ── JIRA auto-ticket background poller ───────────────────────────────────────

async def _jira_autoticket_loop() -> None:
    """
    Runs every JIRA_AUTOPOLL_SECS seconds.
    Queries OpenSearch for Critical alerts in the last JIRA_AUTOPOLL_HOURS hours
    and creates a JIRA ticket for any that don't already have one.
    """
    log.info("JIRA auto-ticket poller started (interval=%ds, window=%dh)",
             JIRA_AUTOPOLL_SECS, JIRA_AUTOPOLL_HOURS)
    while True:
        await asyncio.sleep(JIRA_AUTOPOLL_SECS)
        try:
            query  = build_alert_query(200, 0, None, "Critical", JIRA_AUTOPOLL_HOURS, None)
            result = await asyncio.to_thread(
                indexer_client.search,
                index=ALERT_INDICES,
                ignore_unavailable=True,
                body=query,
            )
            hits = result.get("hits", {}).get("hits", [])
            created = skipped = errors = 0
            for hit in hits:
                ev = normalizer.normalize(hit)
                outcome = await asyncio.to_thread(_ensure_jira_ticket, ev)
                if outcome is None:
                    errors += 1
                elif outcome["created"]:
                    created += 1
                    log.info("JIRA auto-ticket created: %s ← event %s",
                             outcome["key"], ev.get("event_id", "?"))
                else:
                    skipped += 1
            if created or errors:
                log.info("JIRA auto-ticket run: %d critical alerts, %d new tickets, %d skipped, %d errors",
                         len(hits), created, skipped, errors)
        except Exception as exc:
            log.error("JIRA auto-ticket poller error: %s", exc)


@app.on_event("startup")
async def _start_jira_autoticket_poller():
    if jira_client.configured:
        asyncio.create_task(_jira_autoticket_loop())
        log.info("JIRA auto-ticket poller scheduled (interval=%ds, window=%dh)",
                 JIRA_AUTOPOLL_SECS, JIRA_AUTOPOLL_HOURS)
    else:
        log.warning("JIRA not configured — auto-ticket poller disabled (set JIRA_BASE_URL, JIRA_PROJECT_KEY, JIRA_EMAIL, JIRA_API_TOKEN)")


@app.on_event("startup")
async def _init_dashboard_index():
    try:
        cd.ensure_index(indexer_client)
    except Exception:
        pass  # non-fatal if OpenSearch is temporarily unavailable


@app.get("/custom-dashboards")
def list_dashboards(request: Request, user: dict = Depends(get_current_user)):
    return {"dashboards": cd.list_dashboards(indexer_client, _owner(user, request))}


@app.post("/custom-dashboards", status_code=201)
def create_dashboard(request: Request, req: CreateDashboardRequest, user: dict = Depends(get_current_user)):
    return cd.create_dashboard(indexer_client, _owner(user, request), req.name, req.description or "")


@app.get("/custom-dashboards/{dashboard_id}")
def get_dashboard(dashboard_id: str, request: Request, user: dict = Depends(get_current_user)):
    dash = cd.get_dashboard(indexer_client, dashboard_id)
    if not dash:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    owner = _owner(user, request)
    if not dash.get("shared") and dash.get("owner") != owner:
        raise HTTPException(status_code=403, detail="Access denied")
    return dash


@app.put("/custom-dashboards/{dashboard_id}")
def update_dashboard(
    dashboard_id: str,
    request: Request,
    req: UpdateDashboardRequest,
    user: dict = Depends(get_current_user),
):
    dash = cd.get_dashboard(indexer_client, dashboard_id)
    if not dash:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    if dash.get("owner") != _owner(user, request):
        raise HTTPException(status_code=403, detail="Only the owner can edit this dashboard")
    updates = {k: v for k, v in req.dict().items() if v is not None}
    return cd.update_dashboard(indexer_client, dashboard_id, updates)


@app.delete("/custom-dashboards/{dashboard_id}", status_code=204)
def delete_dashboard(dashboard_id: str, request: Request, user: dict = Depends(get_current_user)):
    dash = cd.get_dashboard(indexer_client, dashboard_id)
    if not dash:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    if dash.get("owner") != _owner(user, request):
        raise HTTPException(status_code=403, detail="Only the owner can delete this dashboard")
    cd.delete_dashboard(indexer_client, dashboard_id)


@app.patch("/custom-dashboards/{dashboard_id}/share")
def share_dashboard(
    dashboard_id: str,
    request: Request,
    req: ShareDashboardRequest,
    user: dict = Depends(get_current_user),
):
    dash = cd.get_dashboard(indexer_client, dashboard_id)
    if not dash:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    if dash.get("owner") != _owner(user, request):
        raise HTTPException(status_code=403, detail="Only the owner can change sharing")
    return cd.toggle_share(indexer_client, dashboard_id, req.shared)
