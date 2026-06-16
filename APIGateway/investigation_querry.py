from typing import Optional, List
from field_mapping import (
    REGULAR_FIELDS,
    MSGRAPH_EVIDENCE_FIELDS,
    MSGRAPH_NESTED_PATH,
    MSGRAPH_EVIDENCE_EMAIL_FIELDS,
)

_SEVERITY_LEVEL_RANGES = {
    "Critical": {"gte": 15},
    "High":     {"gte": 12, "lte": 14},
    "Medium":   {"gte": 7,  "lte": 11},
    "Low":      {"lte": 6},
}


def build_investigation_query(
    entity_type: str,
    value: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    size: int = 100,
    offset: int = 0,
    severities: Optional[List[str]] = None,
) -> dict:
    # ── Entity match clauses ──────────────────────────────────────────────────
    should_clauses = []

    for field in REGULAR_FIELDS.get(entity_type, []):
        if field == "full_log":
            should_clauses.append({"match_phrase": {field: value}})
        else:
            should_clauses.append({"term": {field: value}})

    if entity_type == "domain":
        # Darktrace AGEMail: data.from holds the full sender address (e.g. user@evil.com)
        # Match exact domain and one level of subdomain
        should_clauses.append({"wildcard": {"data.from": f"*@{value}"}})
        should_clauses.append({"wildcard": {"data.from": f"*@*.{value}"}})
        # MS Defender email evidence: sender_domain is a flat keyword on the evidence array
        should_clauses.append({"term": {"data.defender.evidence.sender_domain": value}})

    nested_fields = MSGRAPH_EVIDENCE_FIELDS.get(entity_type, [])
    if nested_fields:
        nested_should = [{"term": {f: value}} for f in nested_fields]
        if entity_type == "domain":
            for ef in MSGRAPH_EVIDENCE_EMAIL_FIELDS:
                nested_should.append({"wildcard": {ef: f"*@{value}"}})
                nested_should.append({"wildcard": {ef: f"*@*.{value}"}})
        should_clauses.append({
            "nested": {
                "path": MSGRAPH_NESTED_PATH,
                "query": {
                    "bool": {
                        "should": nested_should,
                        "minimum_should_match": 1,
                    }
                },
            }
        })

    # ── Filters ───────────────────────────────────────────────────────────────
    filters: list = []

    time_range: dict = {}
    if start:
        time_range["gte"] = start
    if end:
        time_range["lte"] = end
    if not start and not end:
        time_range["gte"] = "now-30d"
    filters.append({"range": {"@timestamp": time_range}})

    if severities:
        sev_clauses = [
            {"range": {"rule.level": _SEVERITY_LEVEL_RANGES[s]}}
            for s in severities
            if s in _SEVERITY_LEVEL_RANGES
        ]
        if sev_clauses:
            filters.append({"bool": {"should": sev_clauses, "minimum_should_match": 1}})

    # ── Full query ────────────────────────────────────────────────────────────
    return {
        "query": {
            "bool": {
                "should":               should_clauses,
                "minimum_should_match": 1,
                "filter":               filters,
            }
        },
        "size": size,
        "from": offset,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "aggs": {
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
            "by_rule_level": {
                "terms": {
                    "field": "rule.level",
                    "size":  20,
                }
            },
            "timeline": {
                "date_histogram": {
                    "field":             "@timestamp",
                    "calendar_interval": "1d",
                    "format":            "yyyy-MM-dd",
                }
            },
        },
    }
