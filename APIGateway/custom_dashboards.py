import uuid
from datetime import datetime, timezone
from typing import Optional

from opensearchpy.exceptions import NotFoundError, RequestError

DASHBOARD_INDEX = "siem-custom-dashboards"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_index(client) -> None:
    if client.indices.exists(index=DASHBOARD_INDEX):
        return
    client.indices.create(
        index=DASHBOARD_INDEX,
        body={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "owner":      {"type": "keyword"},
                    "shared":     {"type": "boolean"},
                    "name":       {"type": "text", "fields": {"kw": {"type": "keyword"}}},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                }
            },
        },
    )


def list_dashboards(client, owner: str) -> list:
    try:
        res = client.search(
            index=DASHBOARD_INDEX,
            body={
                "size": 200,
                "query": {
                    "bool": {
                        "should": [
                            {"term": {"owner": owner}},
                            {"term": {"shared": True}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "sort": [{"updated_at": {"order": "desc"}}],
            },
        )
    except RequestError:
        return []
    return [{"id": h["_id"], **h["_source"]} for h in res["hits"]["hits"]]


def get_dashboard(client, dashboard_id: str) -> Optional[dict]:
    try:
        res = client.get(index=DASHBOARD_INDEX, id=dashboard_id)
        return {"id": res["_id"], **res["_source"]}
    except NotFoundError:
        return None


def create_dashboard(client, owner: str, name: str, description: str = "") -> dict:
    did = str(uuid.uuid4())
    now = _now()
    doc = {
        "name":        name,
        "description": description,
        "owner":       owner,
        "shared":      False,
        "created_at":  now,
        "updated_at":  now,
        "widgets":     [],
    }
    client.index(index=DASHBOARD_INDEX, id=did, body=doc, refresh="wait_for")
    return {"id": did, **doc}


def update_dashboard(client, dashboard_id: str, updates: dict) -> Optional[dict]:
    updates["updated_at"] = _now()
    client.update(
        index=DASHBOARD_INDEX, id=dashboard_id,
        body={"doc": updates}, refresh="wait_for",
    )
    return get_dashboard(client, dashboard_id)


def delete_dashboard(client, dashboard_id: str) -> None:
    client.delete(index=DASHBOARD_INDEX, id=dashboard_id, refresh="wait_for")


def toggle_share(client, dashboard_id: str, shared: bool) -> Optional[dict]:
    return update_dashboard(client, dashboard_id, {"shared": shared})
