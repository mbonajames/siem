"""
Saved searches / threat hunting queries.
Analysts can save an alert filter set and re-run it any time.

Index: siem-saved-searches
"""
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from auth import get_current_user

INDEX = "siem-saved-searches"

# Pre-built threat hunting queries shipped with the platform
BUILTIN_SEARCHES = [
    {
        "id": "builtin-brute-force",
        "name": "Brute Force Attempts",
        "description": "Multiple failed authentication events from the same source IP",
        "category": "Authentication",
        "icon": "login",
        "color": "#f59e0b",
        "filters": {"severity": "High,Critical", "hours": 24, "q": "authentication failure"},
        "is_builtin": True,
    },
    {
        "id": "builtin-lateral-movement",
        "name": "Lateral Movement",
        "description": "Defender or Wazuh alerts classified as lateral movement",
        "category": "Endpoint",
        "icon": "swap_horiz",
        "color": "#ef4444",
        "filters": {"severity": "High,Critical", "hours": 168, "q": "lateral"},
        "is_builtin": True,
    },
    {
        "id": "builtin-darktrace-critical",
        "name": "Darktrace Critical Models",
        "description": "Darktrace AI model breaches scored Critical in the last 24h",
        "category": "Network",
        "icon": "bubble_chart",
        "color": "#60a5fa",
        "filters": {"source": "darktrace", "severity": "Critical", "hours": 24},
        "is_builtin": True,
    },
    {
        "id": "builtin-new-devices",
        "name": "New Devices on Network",
        "description": "Darktrace events for devices seen for the first time",
        "category": "Network",
        "icon": "devices",
        "color": "#3fb950",
        "filters": {"source": "darktrace", "hours": 72, "q": "new device"},
        "is_builtin": True,
    },
    {
        "id": "builtin-ransomware",
        "name": "Ransomware Indicators",
        "description": "Defender or Sophos alerts with ransomware classification",
        "category": "Endpoint",
        "icon": "lock",
        "color": "#da3633",
        "filters": {"severity": "Critical", "hours": 168, "q": "ransomware"},
        "is_builtin": True,
    },
    {
        "id": "builtin-phishing",
        "name": "Phishing Emails",
        "description": "Email security events classified as phishing",
        "category": "Email",
        "icon": "phishing",
        "color": "#f85149",
        "filters": {"source": "darktrace", "hours": 72, "q": "phish"},
        "is_builtin": True,
    },
    {
        "id": "builtin-ioc-hits",
        "name": "IOC Matches (MISP)",
        "description": "Alerts with MISP threat intelligence IOC matches",
        "category": "Threat Intel",
        "icon": "gpp_bad",
        "color": "#fb923c",
        "filters": {"ioc_only": "true", "hours": 168},
        "is_builtin": True,
    },
    {
        "id": "builtin-privilege-escalation",
        "name": "Privilege Escalation",
        "description": "Events matching MITRE T1068 or Defender privilege escalation category",
        "category": "Identity",
        "icon": "security",
        "color": "#818cf8",
        "filters": {"severity": "High,Critical", "hours": 168, "q": "privilege"},
        "is_builtin": True,
    },
]


class SavedSearchCreate(BaseModel):
    name:        str
    description: Optional[str] = ""
    category:    Optional[str] = "Custom"
    icon:        Optional[str] = "search"
    color:       Optional[str] = "#8b949e"
    filters:     dict           # mirrors AlertsComponent filter state


def _ensure_index(client):
    if not client.indices.exists(index=INDEX):
        client.indices.create(index=INDEX, body={
            "mappings": {"properties": {
                "id":          {"type": "keyword"},
                "name":        {"type": "text", "fields": {"kw": {"type": "keyword"}}},
                "category":    {"type": "keyword"},
                "created_by":  {"type": "keyword"},
                "created_at":  {"type": "date"},
                "is_builtin":  {"type": "boolean"},
            }}
        })


def create_router(indexer_client) -> APIRouter:
    router = APIRouter(prefix="/saved-searches", tags=["Saved Searches"])

    @router.get("")
    def list_searches(_user: dict = Depends(get_current_user)):
        """Return built-in + user-saved searches."""
        user_searches = []
        try:
            r = indexer_client.search(index=INDEX, body={
                "query": {"match_all": {}},
                "size": 200,
                "sort": [{"created_at": {"order": "desc"}}],
            })
            user_searches = [h["_source"] | {"_id": h["_id"]} for h in r["hits"]["hits"]]
        except Exception:
            pass
        return {"builtin": BUILTIN_SEARCHES, "saved": user_searches}

    @router.post("", status_code=201)
    def create_search(body: SavedSearchCreate, user: dict = Depends(get_current_user)):
        _ensure_index(indexer_client)
        caller = user.get("email") or user.get("preferred_username") or "unknown"
        doc = {
            "id":          str(uuid.uuid4()),
            "name":        body.name,
            "description": body.description,
            "category":    body.category,
            "icon":        body.icon,
            "color":       body.color,
            "filters":     body.filters,
            "is_builtin":  False,
            "created_by":  caller,
            "created_at":  datetime.now(timezone.utc).isoformat(),
        }
        indexer_client.index(index=INDEX, body=doc, refresh=True)
        return doc

    @router.delete("/{search_id}", status_code=204)
    def delete_search(search_id: str, _user: dict = Depends(get_current_user)):
        try:
            r = indexer_client.search(index=INDEX, body={
                "query": {"term": {"id": search_id}}, "size": 1
            })
            hits = r["hits"]["hits"]
            if not hits:
                raise HTTPException(404, "Search not found")
            indexer_client.delete(index=INDEX, id=hits[0]["_id"], refresh=True)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(500, str(exc))

    return router
