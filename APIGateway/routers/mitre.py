"""
MITRE ATT&CK coverage — aggregates technique/tactic hits from OpenSearch alerts.
Index source: wazuh-alerts-* + siem-defender-*
"""
from fastapi import APIRouter, Depends, Query
from auth import get_current_user

ALERT_INDICES = "wazuh-alerts-*,siem-defender-*"

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

TACTIC_LABELS = {
    "reconnaissance":     "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access":     "Initial Access",
    "execution":          "Execution",
    "persistence":        "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion":    "Defense Evasion",
    "credential-access":  "Credential Access",
    "discovery":          "Discovery",
    "lateral-movement":   "Lateral Movement",
    "collection":         "Collection",
    "command-and-control": "Command & Control",
    "exfiltration":       "Exfiltration",
    "impact":             "Impact",
}


def create_router(indexer_client) -> APIRouter:
    router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])

    @router.get("/coverage")
    def get_coverage(
        hours:  int  = Query(168, description="Look-back window in hours (default 7 days)"),
        source: str  = Query("all", description="all | wazuh | defender | darktrace | sophos"),
        _user:  dict = Depends(get_current_user),
    ):
        """
        Return MITRE ATT&CK technique hit counts aggregated from alerts.
        Respects the same time range and source filters as the alerts page.
        """
        filters: list = [
            {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
            {"exists": {"field": "mitre"}},
        ]
        if source != "all":
            filters.append({"term": {"data.integration": source}})

        query = {
            "size": 0,
            "query": {"bool": {"filter": filters}},
            "aggs": {
                "techniques": {
                    "terms": {"field": "mitre.id", "size": 200},
                    "aggs": {
                        "name":    {"terms": {"field": "mitre.technique",     "size": 1}},
                        "tactics": {"terms": {"field": "mitre.tactics",       "size": 10}},
                        "by_sev":  {"terms": {"field": "rule.level",          "size": 5}},
                    }
                }
            }
        }

        try:
            r = indexer_client.search(index=ALERT_INDICES, body=query)
        except Exception as exc:
            return {"error": str(exc), "techniques": [], "tactics": [], "total": 0}

        buckets = r["hits"]["aggregations"]["techniques"]["buckets"] \
            if "aggregations" in r["hits"] else \
            r.get("aggregations", {}).get("techniques", {}).get("buckets", [])

        # Fix: aggregations are at top level
        buckets = r.get("aggregations", {}).get("techniques", {}).get("buckets", [])

        techniques = []
        tactic_counts: dict[str, int] = {}

        for b in buckets:
            tech_id   = b["key"]
            count     = b["doc_count"]
            name_hits = b.get("name", {}).get("buckets", [])
            name      = name_hits[0]["key"] if name_hits else tech_id
            tac_hits  = b.get("tactics", {}).get("buckets", [])
            tactics   = [t["key"] for t in tac_hits]

            techniques.append({
                "id":       tech_id,
                "name":     name,
                "count":    count,
                "tactics":  tactics,
            })
            for tac in tactics:
                tactic_counts[tac] = tactic_counts.get(tac, 0) + count

        # Sort by count descending
        techniques.sort(key=lambda x: x["count"], reverse=True)

        # Build tactic summary in ATT&CK order
        tactic_summary = []
        for tac_id in TACTIC_ORDER:
            if tac_id in tactic_counts or True:  # always include all tactics
                tactic_summary.append({
                    "id":    tac_id,
                    "label": TACTIC_LABELS.get(tac_id, tac_id),
                    "count": tactic_counts.get(tac_id, 0),
                    "techniques": [
                        t for t in techniques if tac_id in t["tactics"]
                    ]
                })

        return {
            "total":      sum(t["count"] for t in techniques),
            "techniques": techniques[:50],       # top 50
            "tactics":    tactic_summary,
            "hours":      hours,
        }

    @router.get("/techniques/{technique_id}/alerts")
    def technique_alerts(
        technique_id: str,
        hours:  int  = Query(168),
        limit:  int  = Query(20),
        _user:  dict = Depends(get_current_user),
    ):
        """Return recent alerts for a specific MITRE technique."""
        query = {
            "size": limit,
            "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": [
                {"range":  {"@timestamp": {"gte": f"now-{hours}h"}}},
                {"term":   {"mitre.id": technique_id}},
            ]}},
            "_source": ["@timestamp", "rule.description", "rule.level",
                        "agent.name", "data.integration", "mitre"],
        }
        try:
            r = indexer_client.search(index=ALERT_INDICES, body=query)
            return [h["_source"] for h in r["hits"]["hits"]]
        except Exception as exc:
            return {"error": str(exc)}

    return router
