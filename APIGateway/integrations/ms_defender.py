"""
Microsoft Defender for email / Microsoft 365 Defender
Direct Graph API integration — no Wazuh involved.

Auth: Azure AD OAuth2 client_credentials
  Required app permissions (Application type, not Delegated):
    SecurityAlert.Read.All
    SecurityIncident.Read.All
    ThreatHunting.Read.All

Env vars: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

Flow:
  - Background poller ingests alerts_v2 + incidents every DEFENDER_POLL_SECS (default 300)
  - Each alert is upserted into siem-defender-YYYY.MM.DD by alert ID (no duplicates on re-poll)
  - On startup: back-fill the last DEFENDER_LOOKBACK_HOURS (default 24)

Document schema written to OpenSearch mirrors the Wazuh alert shape so the
existing normalizer, investigation queries and frontend all work without changes.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TOKEN_URL  = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_TOKEN_BUFFER_SECS   = 300   # refresh 5 min before expiry
DEFENDER_POLL_SECS   = int(os.getenv("DEFENDER_POLL_SECS", "300"))
DEFENDER_LOOKBACK_HOURS = int(os.getenv("DEFENDER_LOOKBACK_HOURS", "24"))

# Defender severity → rule.level (compatible with Wazuh level ranges)
_SEV_TO_LEVEL: dict[str, int] = {
    "informational": 3,
    "low":           5,
    "medium":        8,
    "high":          12,
    "unknown":       3,
}

# Defender alert category (camelCase from API) → (siem_category, siem_event_class)
_CATEGORY_MAP: dict[str, tuple[str, str]] = {
    "advancedPersistenceThreat": ("email Activity",  "APT"),
    "commandAndControl":         ("email Activity",   "C2 Communication"),
    "credentialAccess":          ("email Activity",     "Credential Access"),
    "defenseEvasion":            ("email Activity",  "Defense Evasion"),
    "discovery":                 ("email Activity",  "Discovery"),
    "execution":                 ("email Activity",  "Execution"),
    "exfiltration":              ("email Activity",   "Exfiltration"),
    "exploit":                   ("email Activity",  "Exploit"),
    "generalMalware":            ("email Activity",  "Malware"),
    "impact":                    ("email Activity",  "Impact"),
    "initialAccess":             ("email Activity",  "Initial Access"),
    "lateralMovement":           ("email Activity",   "Lateral Movement"),
    "maliciousActivity":         ("email Activity",  "Malicious Activity"),
    "phishing":                  ("Email Security",     "Phishing"),
    "persistence":               ("email Activity",  "Persistence"),
    "privilegeEscalation":       ("email Activity",  "Privilege Escalation"),
    "ransomware":                ("email Activity",  "Ransomware"),
    "suspiciousActivity":        ("email Activity",  "Suspicious Activity"),
    "unknownFutureValue":        ("email Activity",  "Security Alert"),
}

# odata evidence type → friendly label (for structured evidence list)
_EV_TYPE_MAP: dict[str, str] = {
    "deviceEvidence":          "device",
    "userEvidence":            "user",
    "fileEvidence":            "file",
    "processEvidence":         "process",
    "networkConnectionEvidence": "network",
    "registryKeyEvidence":     "registry_key",
    "registryValueEvidence":   "registry_value",
    "ipEvidence":              "ip",
    "urlEvidence":             "url",
    "cloudApplicationEvidence": "cloud_app",
    "mailboxEvidence":         "mailbox",
    "mailMessageEvidence":     "email",
    "mailClusterEvidence":     "email_cluster",
    "securityGroupEvidence":   "security_group",
    "alertEvidence":           "alert",
}


# ── Graph API client ───────────────────────────────────────────────────────────

class DefenderClientError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail      = detail
        super().__init__(f"Defender API {status_code}: {detail}")


class DefenderClient:
    """
    Thin wrapper around the Microsoft Graph Security API.
    Uses client_credentials (daemon app) — no user interaction required.
    """

    def __init__(self):
        # Tenant is shared; client ID + secret come from the Defender service principal,
        # NOT the SSO app (AZURE_CLIENT_ID is the SSO app and must not be used here).
        self.tenant_id     = os.getenv("AZURE_TENANT_ID", "")
        self.client_id     = os.getenv("DEFENDER_CLIENT_ID", "")
        self.client_secret = os.getenv("DEFENDER_CLIENT_SECRET", "")
        self._token:         str | None = None
        self._token_expiry:  float      = 0.0

    @property
    def configured(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _authenticate(self) -> None:
        r = requests.post(
            _TOKEN_URL.format(tenant=self.tenant_id),
            data={
                "grant_type":    "client_credentials",
                "client_id":     self.client_id,
                "client_secret": self.client_secret,
                "scope":         "https://graph.microsoft.com/.default",
            },
            timeout=30,
        )
        r.raise_for_status()
        data = r.json()
        self._token        = data["access_token"]
        self._token_expiry = time.monotonic() + int(data.get("expires_in", 3600))

    def _ensure_token(self) -> None:
        if not self._token or time.monotonic() >= (self._token_expiry - _TOKEN_BUFFER_SECS):
            self._authenticate()

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type":  "application/json",
            "ConsistencyLevel": "eventual",
        }

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None) -> dict:
        self._ensure_token()
        r = requests.get(
            f"{_GRAPH_BASE}{path}",
            headers=self._headers(),
            params=params,
            timeout=30,
        )
        if not r.ok:
            raise DefenderClientError(r.status_code, r.text[:500])
        return r.json()

    def _post(self, path: str, body: dict) -> dict:
        self._ensure_token()
        r = requests.post(
            f"{_GRAPH_BASE}{path}",
            headers=self._headers(),
            json=body,
            timeout=90,
        )
        if not r.ok:
            raise DefenderClientError(r.status_code, r.text[:500])
        return r.json()

    def _get_paged(self, path: str, params: dict | None = None) -> list[dict]:
        """Follow @odata.nextLink pagination automatically."""
        items: list[dict] = []
        url: str | None = f"{_GRAPH_BASE}{path}"
        while url:
            self._ensure_token()
            r = requests.get(url, headers=self._headers(), params=params, timeout=30)
            if not r.ok:
                raise DefenderClientError(r.status_code, r.text[:500])
            data   = r.json()
            items.extend(data.get("value", []))
            url    = data.get("@odata.nextLink")
            params = None   # nextLink already encodes all params
        return items

    # ── Domain methods ────────────────────────────────────────────────────────

    def get_alerts(self, since_iso: str | None = None, top: int = 1000) -> list[dict]:
        """
        Pull security alerts v2. Evidence and comments are inline properties returned
        automatically — $expand is NOT supported for them and causes a 400.
        $orderby is omitted when $filter is present (Graph rejects the combination).
        """
        params: dict = {
            "$top": min(top, 1000),
        }
        if since_iso:
            params["$filter"] = f"createdDateTime ge {since_iso}"
        else:
            params["$orderby"] = "createdDateTime desc"
        return self._get_paged("/security/alerts_v2", params=params)

    def get_incidents(self, since_iso: str | None = None, top: int = 50) -> list[dict]:
        """
        Pull incident metadata for alert enrichment.
        Returns a {incident_id: incident_meta} map.
        Notes:
          - Graph hard-caps $top at 50 for /security/incidents
          - $expand is omitted to avoid nested-collection $top issues
          - $orderby is omitted when $filter is present
        """
        params: dict = {"$top": min(top, 50)}
        if since_iso:
            params["$filter"] = f"createdDateTime ge {since_iso}"
        else:
            params["$orderby"] = "createdDateTime desc"
        items = self._get_paged("/security/incidents", params=params)
        return {
            str(i["id"]): {
                "title":          i.get("displayName", ""),
                "severity":       i.get("severity", ""),
                "status":         i.get("status", ""),
                "classification": i.get("classification", ""),
                "determination":  i.get("determination", ""),
                "assigned_to":    i.get("assignedTo", ""),
                "tags":           i.get("tags", []),
                "incident_url":   i.get("incidentWebUrl", ""),
            }
            for i in items
            if i.get("id")
        }

    def list_incidents_with_alerts(self, days: int = 7, top: int = 50) -> list[dict]:
        """
        Pull incidents with all associated alerts expanded — for the Incidents UI tab.
        Note: Graph hard-caps $top at 50 for incidents; $orderby cannot be used with $filter.
        Evidence is returned automatically inside each expanded alert.
        """
        since = (datetime.now(tz=timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return self._get_paged(
            "/security/incidents",
            params={
                "$filter": f"lastUpdateDateTime ge {since}",
                "$expand": "alerts",
                "$top":    min(top, 50),
            },
        )

    def get_incident_detail(self, incident_id: str) -> dict:
        """
        Fetch a single incident with all associated alerts (evidence inline).
        Uses GET /security/incidents/{id}?$expand=alerts
        Evidence is returned automatically inside each alert — no nested $expand needed.
        """
        return self._get(
            f"/security/incidents/{incident_id}",
            params={"$expand": "alerts"},
        )

    def run_hunting_query(self, kql: str, timeout_secs: int = 30) -> dict:
        """
        Execute an Advanced Hunting KQL query.
        Returns {"schema": [...], "results": [...]} from Graph API.
        """
        return self._post(
            "/security/runHuntingQuery",
            {"Query": kql, "timeoutInSeconds": timeout_secs},
        )


# ── Evidence extraction helpers ────────────────────────────────────────────────

def _ev_type(ev: dict) -> str:
    """Extract the short evidence type name from @odata.type."""
    raw = ev.get("@odata.type") or ev.get("odataType", "")
    suffix = raw.split(".")[-1].replace("#", "")
    return _EV_TYPE_MAP.get(suffix, suffix or "unknown")


def _extract_evidence(raw_evidence: list[dict]) -> tuple[list[dict], dict]:
    """
    Normalise each Defender evidence item into a structured dict.

    Returns:
        structured_list : evidence items ready for storage
        flat_entities   : {device_hostname, device_ip, user_upn, user_account,
                           remote_ip, remote_port, file_hashes, domains}
    """
    structured:   list[dict]  = []
    device_hostname:  str | None = None
    device_ip:        str | None = None
    user_upn:         str | None = None
    user_account:     str | None = None
    remote_ip:        str | None = None
    remote_port:      str | None = None
    file_hashes:      list[str]  = []
    domains:          list[str]  = []

    for ev in raw_evidence or []:
        etype = _ev_type(ev)
        base = {
            "type":        etype,
            "verdict":     ev.get("verdict"),
            "remediation": ev.get("remediationStatus"),
        }

        if etype == "device":
            ips = ev.get("ipInterfaces") or ev.get("publicIpAddress") or []
            if isinstance(ips, str):
                ips = [ips]
            host = ev.get("deviceDnsName") or ev.get("hostName") or ""
            ip   = ips[0] if ips else None
            item = {**base,
                "hostname":  host,
                "ip":        ip,
                "os":        ev.get("osPlatform"),
                "device_id": ev.get("mdeDeviceId") or ev.get("azureAdDeviceId"),
                "roles":     ev.get("roles", []),
            }
            if host and not device_hostname: device_hostname = host
            if ip   and not device_ip:       device_ip       = ip

        elif etype == "user":
            ua    = ev.get("userAccount") or {}
            upn   = ua.get("userPrincipalName") or ev.get("userPrincipalName", "")
            acct  = ua.get("accountName") or ev.get("accountName", "")
            item  = {**base,
                "upn":          upn,
                "account":      acct,
                "domain":       ua.get("domainName"),
                "display_name": ua.get("displayName") or ev.get("displayName"),
                "aad_id":       ua.get("azureAdUserId"),
            }
            if upn  and not user_upn:     user_upn     = upn
            if acct and not user_account: user_account = acct

        elif etype == "file":
            sha256 = ev.get("sha256") or ev.get("fileHash", {}).get("hashValue")
            sha1   = ev.get("sha1")
            md5    = ev.get("md5")
            item   = {**base,
                "name":   ev.get("fileName") or ev.get("instanceName"),
                "path":   ev.get("filePath"),
                "sha256": sha256,
                "sha1":   sha1,
                "md5":    md5,
                "size":   ev.get("fileSize"),
            }
            for h in [sha256, sha1, md5]:
                if h and h not in file_hashes:
                    file_hashes.append(h)

        elif etype == "process":
            img  = ev.get("imageFile") or {}
            item = {**base,
                "command_line": ev.get("processCommandLine"),
                "pid":          ev.get("processId"),
                "ppid":         ev.get("parentProcessId"),
                "image":        img.get("fileName") or ev.get("fileName"),
                "image_path":   img.get("filePath"),
                "sha256":       img.get("sha256") or ev.get("sha256"),
                "user":         (ev.get("userAccount") or {}).get("accountName"),
                "created":      ev.get("processCreationDateTime"),
            }
            h = img.get("sha256") or ev.get("sha256")
            if h and h not in file_hashes:
                file_hashes.append(h)

        elif etype == "network":
            rip  = ev.get("remoteIpAddress") or ev.get("remoteIP")
            rport = ev.get("remotePort")
            item = {**base,
                "local_ip":    ev.get("localIpAddress"),
                "remote_ip":   rip,
                "local_port":  ev.get("localPort"),
                "remote_port": rport,
                "protocol":    ev.get("protocol"),
                "direction":   ev.get("direction"),
                "dns_name":    ev.get("domainName"),
            }
            if rip   and not remote_ip:   remote_ip   = rip
            if rport and not remote_port: remote_port = str(rport)
            if ev.get("domainName") and ev["domainName"] not in domains:
                domains.append(ev["domainName"])

        elif etype == "registry_key":
            item = {**base,
                "key":  ev.get("registryKey"),
                "hive": ev.get("registryHive"),
            }

        elif etype == "registry_value":
            item = {**base,
                "key":        ev.get("registryKey"),
                "value_name": ev.get("registryValueName"),
                "value_data": ev.get("registryValueData"),
                "value_type": ev.get("registryValueType"),
            }

        elif etype == "ip":
            ip = ev.get("ipAddress")
            item = {**base,
                "ip":      ip,
                "country": ev.get("countryLetterCode"),
            }
            if ip and not remote_ip: remote_ip = ip

        elif etype == "url":
            url = ev.get("url", "")
            item = {**base, "url": url}
            try:
                from urllib.parse import urlparse
                dom = urlparse(url).hostname
                if dom and dom not in domains:
                    domains.append(dom)
            except Exception:
                pass

        elif etype == "email":
            p1 = ev.get("p1Sender") or {}
            p2 = ev.get("p2Sender") or {}
            # p1 = envelope/Return-Path sender; p2 = From header — use p2 as fallback
            sender_email  = p1.get("emailAddress")  or p2.get("emailAddress")
            sender_domain = p1.get("domainName")    or p2.get("domainName")
            sender_name   = p1.get("displayName")   or p2.get("displayName")
            item = {**base,
                "subject":        ev.get("subject"),
                "sender":         sender_email,
                "sender_display": sender_name,
                "sender_domain":  sender_domain,
                "recipient":      ev.get("recipientEmailAddress"),
                "delivery":       ev.get("deliveryAction"),
                "sender_ip":      ev.get("senderIp"),
                "sha256":         ev.get("sha256"),
                "message_id":     ev.get("networkMessageId"),
            }
            dom = p1.get("domainName")
            if dom and dom not in domains:
                domains.append(dom)

        elif etype == "cloud_app":
            item = {**base,
                "app_id":   ev.get("appId"),
                "app_name": ev.get("displayName"),
            }

        else:
            # Pass-through for any unknown evidence types
            item = {**base, "raw": {
                k: v for k, v in ev.items()
                if k not in ("@odata.type", "odataType") and v not in (None, "", [])
            }}

        structured.append({k: v for k, v in item.items() if v not in (None, "", [])})

    flat_entities = {
        "device_hostname": device_hostname,
        "device_ip":       device_ip,
        "user_upn":        user_upn,
        "user_account":    user_account,
        "remote_ip":       remote_ip,
        "remote_port":     remote_port,
        "file_hashes":     file_hashes or None,
        "domains":         domains or None,
    }
    return structured, {k: v for k, v in flat_entities.items() if v is not None}


def _mitre_techniques(alert: dict) -> list[dict] | None:
    """Extract MITRE techniques in the normalizer-compatible format."""
    raw = alert.get("mitreTechniques") or []
    if not raw:
        return None
    result = []
    for t in raw:
        if isinstance(t, str):
            # alerts_v2 returns technique IDs as plain strings ("T1059.003")
            result.append({"id": t, "technique": t, "tactics": []})
        elif isinstance(t, dict):
            result.append({
                "id":        t.get("techniqueID") or t.get("id"),
                "technique": t.get("technique") or t.get("id"),
                "tactics":   t.get("tactics") or [],
            })
    return result or None


# ── Alert → OpenSearch document ────────────────────────────────────────────────

def normalize_alert(alert: dict, incident_map: dict | None = None) -> tuple[str, str, dict]:
    """
    Convert a Defender alerts_v2 item into an OpenSearch document.

    Returns: (doc_id, index_name, document)
      - doc_id is the Defender alert ID — used for upsert deduplication
      - index_name is date-sharded: siem-defender-YYYY.MM.DD
    """
    alert_id   = alert.get("id", "")
    # Normalize to millisecond precision — Graph returns 7 fractional digits
    # (100-nanosecond FILETIME) which some OpenSearch date parsers reject
    _raw_ts  = alert.get("createdDateTime", "")
    import re as _re
    created  = _re.sub(r'(\.\d{3})\d+', r'\1', _raw_ts)
    severity   = (alert.get("severity") or "unknown").lower()
    rule_level = _SEV_TO_LEVEL.get(severity, 3)

    # Evidence
    evidence_raw, flat_ents = _extract_evidence(alert.get("evidence") or [])

    # Incident enrichment
    incident_id  = str(alert.get("incidentId", ""))
    incident_ctx = (incident_map or {}).get(incident_id, {}) if incident_id else {}

    # MITRE
    mitre = _mitre_techniques(alert)

    # Comments (analyst notes)
    comments = [
        {
            "text":    c.get("comment", ""),
            "author":  c.get("createdByDisplayName"),
            "created": c.get("createdDateTime"),
        }
        for c in (alert.get("comments") or [])
        if c.get("comment")
    ]

    # Build the defender-specific sub-document
    defender_doc = {
        "alert_id":        alert_id,
        "incident_id":     incident_id or None,
        "title":           alert.get("title", ""),
        "description":     alert.get("description", ""),
        "severity":        severity,
        "status":          alert.get("status", ""),
        "category":        alert.get("category", ""),
        "classification":  alert.get("classification", ""),
        "determination":   alert.get("determination", ""),
        "service_source":  alert.get("serviceSource", ""),
        "detection_source": alert.get("detectionSource", ""),
        "actor":           alert.get("actorDisplayName"),
        "threat_family":   alert.get("threatFamilyName") or alert.get("threatDisplayName"),
        "alert_url":       alert.get("alertWebUrl", ""),
        "incident_url":    alert.get("incidentWebUrl", "") or incident_ctx.get("incident_url", ""),
        "assigned_to":     alert.get("assignedTo") or incident_ctx.get("assigned_to"),
        "created":         created,
        "first_activity":  alert.get("firstActivityDateTime"),
        "last_activity":   alert.get("lastActivityDateTime"),
        "resolved":        alert.get("resolvedDateTime"),
        "mitreTechniques": mitre,
        "evidence":        evidence_raw or None,
        "comments":        comments or None,
        # Flat entity fields for easy search / filtering
        **flat_ents,
        # Incident context
        **({"incident": incident_ctx} if incident_ctx else {}),
    }
    # Drop None / empty values to keep documents lean
    defender_doc = {k: v for k, v in defender_doc.items() if v not in (None, "", [])}

    # Date-sharded index
    try:
        date_str = datetime.fromisoformat(created.replace("Z", "+00:00")).strftime("%Y.%m.%d")
    except Exception:
        date_str = datetime.now(tz=timezone.utc).strftime("%Y.%m.%d")
    index_name = f"siem-defender-{date_str}"

    # Final document — mirrors Wazuh alert shape so the normalizer works unchanged
    doc = {
        "@timestamp": created,
        "timestamp":  created,
        "rule": {
            "id":          "ms-defender",
            "level":       rule_level,
            "description": alert.get("title", ""),
            "groups":      ["ms-defender"],
        },
        "agent": {
            "id":   flat_ents.get("device_id") or "000",
            "name": flat_ents.get("device_hostname") or "",
            "ip":   flat_ents.get("device_ip") or "",
        },
        "data": {
            "integration": "ms-defender",
            "defender":    defender_doc,
        },
    }

    return alert_id, index_name, doc


# ── Index template ────────────────────────────────────────────────────────────

_INDEX_TEMPLATE = {
    "index_patterns": ["siem-defender-*"],
    "template": {
        "settings": {
            "number_of_shards":   1,
            "number_of_replicas": 0,
            "refresh_interval":   "5s",
        },
        "mappings": {
            # Map every string field as keyword by default so term/filter queries work.
            # This mirrors how the Wazuh index template behaves for wazuh-alerts-*.
            "dynamic_templates": [
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "mapping": {
                            "type":         "keyword",
                            "ignore_above": 1024,
                        },
                    }
                }
            ],
            "properties": {
                "@timestamp":  {"type": "date"},
                "timestamp":   {"type": "date"},
                "rule": {
                    "properties": {
                        "level":       {"type": "integer"},
                        "id":          {"type": "keyword"},
                        "description": {"type": "text"},
                        "groups":      {"type": "keyword"},
                    }
                },
                "data": {
                    "properties": {
                        "integration": {"type": "keyword"},
                        "defender": {
                            "dynamic": True,
                            "properties": {
                                "title":          {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 512}}},
                                "description":    {"type": "text"},
                                "severity":       {"type": "keyword"},
                                "status":         {"type": "keyword"},
                                "category":       {"type": "keyword"},
                                "alert_id":       {"type": "keyword"},
                                "incident_id":    {"type": "keyword"},
                                "service_source": {"type": "keyword"},
                                "created":        {"type": "date"},
                                "first_activity": {"type": "date"},
                                "last_activity":  {"type": "date"},
                            },
                        },
                    }
                },
            },
        },
    },
}


def ensure_index_template(indexer) -> None:
    """Create or update the siem-defender-* index template."""
    try:
        indexer.indices.put_index_template(name="siem-defender-template", body=_INDEX_TEMPLATE)
        log.info("Defender: index template siem-defender-template applied")
    except Exception as exc:
        log.warning("Defender: could not apply index template: %s", exc)


def delete_stale_indices(indexer) -> None:
    """
    Delete any siem-defender-* indices created WITHOUT the template
    (wrong dynamic string→text mapping). The next ingest recreates them correctly.
    """
    try:
        resp = indexer.indices.get(index="siem-defender-*", ignore_unavailable=True)
        to_delete = []
        for idx_name, meta in resp.items():
            props = meta.get("mappings", {}).get("properties", {})
            data_integ = (
                props.get("data", {})
                    .get("properties", {})
                    .get("integration", {})
                    .get("type")
            )
            if data_integ == "text":
                to_delete.append(idx_name)
        if to_delete:
            indexer.indices.delete(index=",".join(to_delete))
            log.info("Defender: deleted stale indices with wrong mapping: %s", to_delete)
    except Exception as exc:
        log.warning("Defender: stale-index cleanup failed: %s", exc)


# ── Ingest to OpenSearch ───────────────────────────────────────────────────────

def ingest_alerts(client: DefenderClient, indexer, since_iso: str | None = None) -> dict:
    """
    Pull Defender alerts + incident metadata, normalize, and upsert to OpenSearch.

    Returns summary: {"ingested": N, "errors": N, "since": since_iso}
    """
    if not client.configured:
        return {"ingested": 0, "errors": 0, "skipped": "not configured"}

    # Default: look back DEFENDER_LOOKBACK_HOURS
    if not since_iso:
        dt = datetime.now(tz=timezone.utc) - timedelta(hours=DEFENDER_LOOKBACK_HOURS)
        since_iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    log.info("Defender: fetching alerts since %s", since_iso)

    try:
        incidents = client.get_incidents(since_iso=since_iso)
    except Exception as exc:
        log.warning("Defender: incident fetch failed (%s) — continuing without incident enrichment", exc)
        incidents = {}

    try:
        alerts = client.get_alerts(since_iso=since_iso)
    except Exception as exc:
        log.error("Defender: alert fetch failed: %s", exc)
        return {"ingested": 0, "errors": 1, "since": since_iso}

    ingested = errors = 0
    for alert in alerts:
        try:
            doc_id, index_name, doc = normalize_alert(alert, incident_map=incidents)
            indexer.index(
                index=index_name,
                id=doc_id,
                body=doc,
                op_type="index",   # upsert — overwrite if same ID already exists
            )
            ingested += 1
        except Exception as exc:
            log.error("Defender: failed to ingest alert %s: %s", alert.get("id"), exc)
            errors += 1

    log.info("Defender: ingested %d alerts (%d errors) since %s", ingested, errors, since_iso)
    return {"ingested": ingested, "errors": errors, "since": since_iso}
