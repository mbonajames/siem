"""
Audit log storage and query — backed by an OpenSearch index.
All writes are best-effort (errors are logged but never re-raised).
"""
import uuid
import logging
from datetime import datetime, timezone

from opensearchpy.exceptions import RequestError

log = logging.getLogger(__name__)

AUDIT_INDEX = "siem-audit-logs"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_index(client) -> None:
    if client.indices.exists(index=AUDIT_INDEX):
        return
    client.indices.create(
        index=AUDIT_INDEX,
        body={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "timestamp":  {"type": "date"},
                    "user":       {"type": "keyword"},
                    "action":     {"type": "keyword"},
                    "resource":   {"type": "keyword"},
                    "outcome":    {"type": "keyword"},
                    "ip_address": {"type": "keyword"},
                    "details":    {"type": "text"},
                }
            },
        },
    )
    log.info("Created OpenSearch index: %s", AUDIT_INDEX)


def write_entry(
    client, *,
    user:       str,
    action:     str,
    resource:   str,
    outcome:    str,
    ip_address: str = "",
    details:    str = "",
) -> None:
    try:
        client.index(
            index=AUDIT_INDEX,
            id=str(uuid.uuid4()),
            body={
                "timestamp":  _now(),
                "user":       user,
                "action":     action,
                "resource":   resource,
                "outcome":    outcome,
                "ip_address": ip_address,
                "details":    details,
            },
            refresh=False,
        )
    except Exception as exc:
        log.warning("audit_log.write_entry failed: %s", exc)


def delete_entry(client, log_id: str) -> bool:
    """Delete a single audit log entry by ID. Returns True if deleted."""
    try:
        res = client.delete(index=AUDIT_INDEX, id=log_id, refresh=True)
        return res.get("result") == "deleted"
    except Exception as exc:
        log.warning("audit_log.delete_entry failed: %s", exc)
        return False


def clear_all(client) -> int:
    """Delete all audit log entries. Returns count of deleted docs."""
    try:
        res = client.delete_by_query(
            index=AUDIT_INDEX,
            body={"query": {"match_all": {}}},
            refresh=True,
        )
        return res.get("deleted", 0)
    except Exception as exc:
        log.warning("audit_log.clear_all failed: %s", exc)
        return 0


def query_logs(
    client, *,
    hours:   int = 24,
    limit:   int = 200,
    outcome: str = "",
) -> dict:
    filters = [{"range": {"timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}]
    if outcome:
        filters.append({"term": {"outcome": outcome}})

    try:
        res = client.search(
            index=AUDIT_INDEX,
            body={
                "size": limit,
                "query": {"bool": {"filter": filters}},
                "sort": [{"timestamp": {"order": "desc"}}],
            },
        )
    except RequestError:
        return {"total": 0, "logs": []}
    except Exception as exc:
        log.warning("audit_log.query_logs failed: %s", exc)
        return {"total": 0, "logs": []}

    hits = res["hits"]["hits"]
    total = res["hits"]["total"]
    total_val = total["value"] if isinstance(total, dict) else total
    return {
        "total": total_val,
        "logs": [{"id": h["_id"], **h["_source"]} for h in hits],
    }
