"""
Alert status workflow — stores New / Acknowledged / Closed state,
analyst assignment, comments and tags for any alert.

Call create_router(indexer_client) and include_router() it in main.py.
Index: siem-alert-status
"""
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from auth import get_current_user

INDEX = "siem-alert-status"
STATUS_VALUES = {"new", "acknowledged", "closed"}


class StatusUpdate(BaseModel):
    alert_id: str
    status:   str
    assignee: Optional[str] = None
    comment:  Optional[str] = None
    tags:     Optional[list[str]] = None


class CommentAdd(BaseModel):
    comment: str


def _ensure_index(client):
    if not client.indices.exists(index=INDEX):
        client.indices.create(index=INDEX, body={
            "mappings": {"properties": {
                "alert_id":   {"type": "keyword"},
                "status":     {"type": "keyword"},
                "assignee":   {"type": "keyword"},
                "tags":       {"type": "keyword"},
                "updated_by": {"type": "keyword"},
                "updated_at": {"type": "date"},
                "comments":   {"type": "object", "enabled": True},
            }}
        })


def _get_doc(client, alert_id: str):
    try:
        r = client.search(index=INDEX, body={
            "query": {"term": {"alert_id": alert_id}}, "size": 1
        })
        hits = r["hits"]["hits"]
        if hits:
            return hits[0]["_id"], hits[0]["_source"]
    except Exception:
        pass
    return None, None


def create_router(indexer_client) -> APIRouter:
    router = APIRouter(prefix="/alert-status", tags=["Alert Status"])

    def _client():
        return indexer_client

    @router.get("")
    def batch_get(
        ids:   str  = Query(..., description="Comma-separated alert IDs"),
        _user: dict = Depends(get_current_user),
    ):
        id_list = [i.strip() for i in ids.split(",") if i.strip()]
        if not id_list:
            return []
        try:
            r = indexer_client.search(index=INDEX, body={
                "query": {"terms": {"alert_id": id_list}}, "size": 500
            })
            return [h["_source"] for h in r["hits"]["hits"]]
        except Exception:
            return []

    @router.get("/{alert_id}")
    def get_status(alert_id: str, _user: dict = Depends(get_current_user)):
        _, doc = _get_doc(indexer_client, alert_id)
        if not doc:
            return {"alert_id": alert_id, "status": "new",
                    "assignee": None, "tags": [], "comments": []}
        return doc

    @router.post("", status_code=200)
    def upsert_status(body: StatusUpdate, user: dict = Depends(get_current_user)):
        if body.status not in STATUS_VALUES:
            raise HTTPException(400, f"status must be one of {STATUS_VALUES}")
        _ensure_index(indexer_client)
        caller = user.get("email") or user.get("preferred_username") or "unknown"
        now    = datetime.now(timezone.utc).isoformat()

        doc_id, existing = _get_doc(indexer_client, body.alert_id)
        if existing:
            existing["status"]     = body.status
            existing["assignee"]   = body.assignee if body.assignee is not None else existing.get("assignee")
            existing["tags"]       = body.tags     if body.tags     is not None else existing.get("tags", [])
            existing["updated_by"] = caller
            existing["updated_at"] = now
            if body.comment:
                clist = existing.get("comments") or []
                clist.append({"author": caller, "text": body.comment, "ts": now})
                existing["comments"] = clist
            indexer_client.index(index=INDEX, id=doc_id, body=existing, refresh=True)
            return existing
        else:
            doc = {
                "alert_id":   body.alert_id,
                "status":     body.status,
                "assignee":   body.assignee,
                "tags":       body.tags or [],
                "updated_by": caller,
                "updated_at": now,
                "comments":   [{"author": caller, "text": body.comment, "ts": now}] if body.comment else [],
            }
            indexer_client.index(index=INDEX, body=doc, refresh=True)
            return doc

    @router.post("/{alert_id}/comment", status_code=200)
    def add_comment(
        alert_id: str,
        body:     CommentAdd,
        user:     dict = Depends(get_current_user),
    ):
        _ensure_index(indexer_client)
        caller = user.get("email") or user.get("preferred_username") or "unknown"
        now    = datetime.now(timezone.utc).isoformat()
        entry  = {"author": caller, "text": body.comment, "ts": now}

        doc_id, existing = _get_doc(indexer_client, alert_id)
        if existing:
            clist = existing.get("comments") or []
            clist.append(entry)
            existing["comments"]   = clist
            existing["updated_by"] = caller
            existing["updated_at"] = now
            indexer_client.index(index=INDEX, id=doc_id, body=existing, refresh=True)
            return existing
        else:
            doc = {
                "alert_id":   alert_id,
                "status":     "acknowledged",
                "assignee":   caller,
                "tags":       [],
                "updated_by": caller,
                "updated_at": now,
                "comments":   [entry],
            }
            indexer_client.index(index=INDEX, body=doc, refresh=True)
            return doc

    return router
