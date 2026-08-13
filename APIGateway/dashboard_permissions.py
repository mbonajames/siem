"""
Grafana dashboard access control overlay.

Maintains a `siem-dashboard-permissions` index that maps each Grafana
dashboard UID to its SIEM owner and the list of users it has been
explicitly shared with.

Dashboards with NO record in this index are visible to everyone
(backward-compatible default). Once a dashboard is created through the
SIEM portal it gets a record and is only visible to its owner + shared_with.
"""

import logging
from opensearchpy.exceptions import NotFoundError

log = logging.getLogger(__name__)
INDEX = "siem-dashboard-permissions"

_MAPPING = {
    "mappings": {
        "properties": {
            "uid":         {"type": "keyword"},
            "owner":       {"type": "keyword"},
            "shared_with": {"type": "keyword"},
        }
    }
}


def ensure_index(client) -> None:
    try:
        if not client.indices.exists(index=INDEX):
            client.indices.create(index=INDEX, body=_MAPPING)
            log.info("Created index %s", INDEX)
    except Exception as exc:
        log.warning("Could not ensure %s: %s", INDEX, exc)


def register_dashboard(client, uid: str, owner: str) -> None:
    client.index(
        index=INDEX,
        id=uid,
        body={"uid": uid, "owner": owner, "shared_with": []},
        refresh="wait_for",
    )


def get_permission(client, uid: str) -> dict | None:
    try:
        r = client.get(index=INDEX, id=uid)
        return r["_source"]
    except NotFoundError:
        return None
    except Exception:
        return None


def update_shared_with(client, uid: str, emails: list[str]) -> None:
    client.update(
        index=INDEX,
        id=uid,
        body={"doc": {"shared_with": list(set(emails))}},
        refresh="wait_for",
    )


def delete_permission(client, uid: str) -> None:
    try:
        client.delete(index=INDEX, id=uid)
    except NotFoundError:
        pass
    except Exception as exc:
        log.warning("Could not delete permission for %s: %s", uid, exc)


def enrich_dashboards(client, dashboards: list[dict], caller: str) -> list[dict]:
    """Return all dashboards enriched with `owner`, `shared_with`, `accessible`.

    Dashboards with no ACL record are treated as accessible by everyone
    (legacy / Grafana-native). Dashboards with an ACL record are only
    accessible to their owner or users listed in shared_with.
    All dashboards are returned so the frontend can show locked cards.
    """
    if not dashboards:
        return []

    uids = [d.get("uid") for d in dashboards if d.get("uid")]
    perms: dict[str, dict] = {}

    if uids:
        try:
            r = client.search(
                index=INDEX,
                body={"query": {"terms": {"_id": uids}}, "size": len(uids)},
                request_timeout=5,
            )
            for hit in r["hits"]["hits"]:
                perms[hit["_id"]] = hit["_source"]
        except Exception:
            pass  # index missing or unavailable → treat all as uncontrolled

    result = []
    for d in dashboards:
        uid = d.get("uid", "")
        perm = perms.get(uid)
        if perm is None:
            result.append({**d, "owner": None, "shared_with": [], "accessible": True})
        else:
            owner = perm.get("owner", "")
            shared_with = perm.get("shared_with", [])
            accessible = (owner == caller) or (caller in shared_with)
            result.append({**d, "owner": owner, "shared_with": shared_with, "accessible": accessible})

    return result


def get_known_users(client, q: str = "", limit: int = 25) -> list[str]:
    """Return known user emails from the audit-logs index."""
    try:
        body: dict = {
            "size": 0,
            "aggs": {"users": {"terms": {"field": "user", "size": 200}}},
        }
        if q:
            body["query"] = {"wildcard": {"user": {"value": f"*{q.lower()}*"}}}
        r = client.search(index="siem-audit-logs", body=body)
        buckets = r.get("aggregations", {}).get("users", {}).get("buckets", [])
        emails = [b["key"] for b in buckets if b.get("key")]
        if q:
            emails = [e for e in emails if q.lower() in e.lower()]
        return emails[:limit]
    except Exception as exc:
        log.warning("get_known_users failed: %s", exc)
        return []
