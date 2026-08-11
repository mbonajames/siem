"""
Teams / webhook notification system.

Stores webhook config in OpenSearch `siem-settings`.
A background poller (started in main.py startup) fires Teams messages
when new Critical / High alerts arrive since the last check.
"""
import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from auth import get_current_user

log = logging.getLogger(__name__)

SETTINGS_INDEX = "siem-settings"
SETTINGS_ID    = "notification_config"
ALERT_INDICES  = "wazuh-alerts-*,siem-defender-*"


class NotificationConfig(BaseModel):
    teams_webhook_url:    Optional[str] = None
    enabled:              bool          = True
    min_severity:         str           = "Critical"   # Critical | High
    poll_interval_secs:   int           = 300
    mention_channel:      bool          = False


def _get_config(client) -> dict:
    try:
        r = client.get(index=SETTINGS_INDEX, id=SETTINGS_ID)
        return r["_source"]
    except Exception:
        return {}


def _save_config(client, cfg: dict):
    if not client.indices.exists(index=SETTINGS_INDEX):
        client.indices.create(index=SETTINGS_INDEX, body={
            "mappings": {"properties": {"updated_at": {"type": "date"}}}
        })
    client.index(index=SETTINGS_INDEX, id=SETTINGS_ID, body=cfg, refresh=True)


def _build_teams_card(alerts: list[dict], since: str) -> dict:
    """Build an Adaptive Card payload for Microsoft Teams."""
    count    = len(alerts)
    criticals = sum(1 for a in alerts if (a.get("rule", {}).get("level", 0) or 0) >= 15
                    or a.get("data", {}).get("defender", {}).get("severity", "").lower() == "high")

    facts = []
    for a in alerts[:5]:
        src   = a.get("_source", a)
        desc  = (src.get("rule", {}).get("description")
                 or src.get("data", {}).get("defender", {}).get("title")
                 or "Unknown alert")
        agent = src.get("agent", {}).get("name", "—")
        facts.append({"title": agent, "value": desc[:120]})

    body = [
        {
            "type": "TextBlock",
            "text": f"🚨 {count} new alert{'s' if count != 1 else ''} — Hope-Armor SIEM",
            "weight": "Bolder",
            "size": "Medium",
            "color": "Attention",
        },
        {
            "type": "TextBlock",
            "text": f"Since {since}  |  {criticals} critical",
            "isSubtle": True,
            "size": "Small",
        },
        {"type": "FactSet", "facts": facts},
    ]
    if count > 5:
        body.append({
            "type": "TextBlock",
            "text": f"… and {count - 5} more. Open the SIEM for details.",
            "isSubtle": True,
            "size": "Small",
        })

    return {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": body,
            }
        }]
    }


async def _post_to_teams(webhook_url: str, payload: dict):
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(webhook_url, json=payload)
        r.raise_for_status()


# ── Background poller ─────────────────────────────────────────────────────────

_last_notified_at: str = datetime.now(timezone.utc).isoformat()


async def notification_poller(indexer_client):
    """
    Runs as an asyncio background task started at app startup.
    Every poll_interval_secs seconds, checks for new critical/high alerts
    and sends a Teams card if any are found.
    """
    global _last_notified_at
    while True:
        try:
            cfg = _get_config(indexer_client)
            interval = cfg.get("poll_interval_secs", 300)
            await asyncio.sleep(interval)

            if not cfg.get("enabled", True):
                continue
            webhook = cfg.get("teams_webhook_url") or os.getenv("TEAMS_WEBHOOK_URL", "")
            if not webhook:
                continue

            min_sev = cfg.get("min_severity", "Critical")
            level_floor = 15 if min_sev == "Critical" else 12

            since = _last_notified_at
            _last_notified_at = datetime.now(timezone.utc).isoformat()

            r = indexer_client.search(index=ALERT_INDICES, body={
                "size": 50,
                "sort": [{"@timestamp": "desc"}],
                "query": {"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": since}}},
                    {"bool": {"should": [
                        {"range": {"rule.level": {"gte": level_floor}}},
                        {"terms": {"data.defender.severity": ["high", "critical"]}},
                    ], "minimum_should_match": 1}},
                ]}},
            })
            hits = r["hits"]["hits"]
            if not hits:
                continue

            payload = _build_teams_card([h["_source"] for h in hits], since)
            await _post_to_teams(webhook, payload)
            log.info("Teams notification sent: %d alerts", len(hits))

        except asyncio.CancelledError:
            break
        except Exception as exc:
            log.warning("Notification poller error: %s", exc)


# ── Router ────────────────────────────────────────────────────────────────────

def create_router(indexer_client) -> APIRouter:
    router = APIRouter(prefix="/notifications", tags=["Notifications"])

    @router.get("/config")
    def get_config(_user: dict = Depends(get_current_user)):
        cfg = _get_config(indexer_client)
        # Mask webhook URL for non-admins
        if cfg.get("teams_webhook_url"):
            cfg["teams_webhook_url_masked"] = "••••••••" + cfg["teams_webhook_url"][-12:]
            cfg.pop("teams_webhook_url", None)
        return cfg

    @router.post("/config")
    def save_config(body: NotificationConfig, user: dict = Depends(get_current_user)):
        caller = user.get("email") or user.get("preferred_username") or "unknown"
        doc = body.model_dump()
        doc["updated_by"] = caller
        doc["updated_at"] = datetime.now(timezone.utc).isoformat()
        _save_config(indexer_client, doc)
        return {"ok": True}

    @router.post("/test")
    async def send_test(_user: dict = Depends(get_current_user)):
        cfg     = _get_config(indexer_client)
        webhook = cfg.get("teams_webhook_url") or os.getenv("TEAMS_WEBHOOK_URL", "")
        if not webhook:
            raise HTTPException(400, "Teams webhook URL not configured")
        payload = _build_teams_card([{
            "rule": {"description": "Test alert from Hope-Armor SIEM", "level": 15},
            "agent": {"name": "test-host"},
        }], datetime.now(timezone.utc).isoformat())
        try:
            await _post_to_teams(webhook, payload)
            return {"ok": True}
        except Exception as exc:
            raise HTTPException(502, f"Teams delivery failed: {exc}")

    @router.get("/status")
    def get_status(_user: dict = Depends(get_current_user)):
        return {
            "last_notified_at": _last_notified_at,
            "webhook_configured": bool(
                _get_config(indexer_client).get("teams_webhook_url")
                or os.getenv("TEAMS_WEBHOOK_URL", "")
            ),
        }

    return router
