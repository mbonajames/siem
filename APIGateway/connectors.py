"""
Connector registry — describes every integration and can test connectivity.

Each connector is read-only from the environment (env vars set in the .env /
deployment config). The UI shows which are configured and lets users trigger
a live health check.
"""
import os
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

log = logging.getLogger(__name__)


# ── Connector definitions ─────────────────────────────────────────────────────
# Fields:
#   id          – machine ID (used in API paths)
#   name        – display name
#   category    – UI group: SIEM | Endpoint | Network | Identity | Threat Intel | Ticketing | Scanner | Future
#   description – one-line description shown on the card
#   env_keys    – list of env var names that must be non-empty to be "configured"
#   icon        – Material icon name (used in Angular card)
#   color       – accent hex used on the card icon background

CONNECTORS = [
    {
        "id":          "opensearch",
        "name":        "Wazuh Indexer",
        "category":    "SIEM",
        "description": "Core security event storage and search (OpenSearch)",
        "env_keys":    ["WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD"],
        "icon":        "storage",
        "color":       "#4e9af1",
    },
    {
        "id":          "wazuh-api",
        "name":        "Wazuh Manager",
        "category":    "SIEM",
        "description": "Wazuh agent management, rules and active response",
        "env_keys":    ["WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASS"],
        "icon":        "shield",
        "color":       "#f59e0b",
    },
    {
        "id":          "sophos",
        "name":        "Sophos Central",
        "category":    "Endpoint",
        "description": "Endpoint protection, device isolation and threat events",
        "env_keys":    ["SOPHOS_CLIENT_ID", "SOPHOS_CLIENT_SECRET"],
        "icon":        "security",
        "color":       "#3fb950",
    },
    {
        "id":          "defender",
        "name":        "Microsoft Defender",
        "category":    "Endpoint",
        "description": "Microsoft Defender for Endpoint alerts via Graph API",
        "env_keys":    ["DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"],
        "icon":        "verified_user",
        "color":       "#0078d4",
    },
    {
        "id":          "darktrace",
        "name":        "Darktrace",
        "category":    "Network",
        "description": "Network anomaly detection and AI-driven threat intelligence",
        "env_keys":    ["WAZUH_INDEXER_URL"],   # Darktrace events land in OpenSearch via Wazuh pipeline
        "icon":        "bubble_chart",
        "color":       "#60a5fa",
    },
    {
        "id":          "nessus",
        "name":        "Nessus / Tenable",
        "category":    "Scanner",
        "description": "Vulnerability scanning and compliance assessment",
        "env_keys":    ["NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"],
        "icon":        "radar",
        "color":       "#a78bfa",
    },
    {
        "id":          "virustotal",
        "name":        "VirusTotal",
        "category":    "Threat Intel",
        "description": "IP, domain, URL and file hash reputation lookups",
        "env_keys":    ["VT_API_KEY"],
        "icon":        "gpp_bad",
        "color":       "#ef4444",
    },
    {
        "id":          "jira",
        "name":        "JIRA",
        "category":    "Ticketing",
        "description": "Security incident ticketing and case management",
        "env_keys":    ["JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN"],
        "icon":        "confirmation_number",
        "color":       "#818cf8",
    },
    {
        "id":          "entra-id",
        "name":        "Microsoft Entra ID",
        "category":    "Identity",
        "description": "Azure AD identity protection, risky sign-ins and user risk",
        "env_keys":    ["DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET"],
        "icon":        "manage_accounts",
        "color":       "#0ea5e9",
    },
    {
        "id":          "grafana",
        "name":        "Grafana",
        "category":    "SIEM",
        "description": "Dashboard visualization layer for OpenSearch/Wazuh data",
        "env_keys":    ["GRAFANA_URL", "GRAFANA_API_KEY"],
        "icon":        "bar_chart",
        "color":       "#f97316",
    },
    # ── Future integrations (pre-registered, not yet configured) ──────────────
    {
        "id":          "graylog",
        "name":        "Graylog",
        "category":    "Future",
        "description": "Centralized log management and analysis",
        "env_keys":    ["GRAYLOG_URL", "GRAYLOG_API_TOKEN"],
        "icon":        "list_alt",
        "color":       "#6b7280",
    },
    {
        "id":          "cyberark",
        "name":        "CyberArk",
        "category":    "Future",
        "description": "Privileged access management and vault activity monitoring",
        "env_keys":    ["CYBERARK_URL", "CYBERARK_APP_ID"],
        "icon":        "key",
        "color":       "#6b7280",
    },
]


def _env_set(key: str) -> bool:
    return bool(os.getenv(key, "").strip())


def _is_configured(connector: dict) -> bool:
    return all(_env_set(k) for k in connector["env_keys"])


def list_connectors() -> list[dict]:
    """Return all connectors with their static metadata and configuration status."""
    result = []
    for c in CONNECTORS:
        configured = _is_configured(c)
        result.append({
            "id":          c["id"],
            "name":        c["name"],
            "category":    c["category"],
            "description": c["description"],
            "icon":        c["icon"],
            "color":       c["color"],
            "configured":  configured,
            "status":      "unknown",       # health check not run yet
            "last_checked": None,
        })
    return result


# ── Per-connector health checks ───────────────────────────────────────────────

async def _check_opensearch() -> dict:
    url = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
    user = os.getenv("WAZUH_INDEXER_USER", "")
    pw   = os.getenv("WAZUH_INDEXER_PASSWORD", "")
    try:
        async with httpx.AsyncClient(verify=False, timeout=8) as c:
            r = await c.get(f"{url}/_cluster/health", auth=(user, pw))
        status = r.json().get("status", "unknown")
        return {"status": "connected", "detail": f"cluster: {status}"}
    except Exception as exc:
        return {"status": "disconnected", "detail": str(exc)}


async def _check_wazuh_api() -> dict:
    url  = os.getenv("WAZUH_API_URL", "").rstrip("/")
    user = os.getenv("WAZUH_API_USER", "wazuh-wui")
    pw   = os.getenv("WAZUH_API_PASS", "")
    if not url or not pw:
        return {"status": "not_configured", "detail": "WAZUH_API_URL or WAZUH_API_PASS missing"}
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            # Wazuh API uses JWT — authenticate first, then verify with a lightweight call
            auth_r = await c.post(
                f"{url}/security/user/authenticate",
                auth=(user, pw),
            )
        if auth_r.status_code == 200:
            try:
                token = auth_r.json()["data"]["token"]
                version = auth_r.headers.get("x-frame-options", "")
            except Exception:
                token = None
            return {"status": "connected", "detail": f"JWT obtained — user '{user}' authenticated"}
        return {"status": "disconnected", "detail": f"Auth failed HTTP {auth_r.status_code}: {auth_r.text[:120]}"}
    except Exception as exc:
        return {"status": "disconnected", "detail": str(exc)}


async def _check_sophos() -> dict:
    cid = os.getenv("SOPHOS_CLIENT_ID", "")
    cse = os.getenv("SOPHOS_CLIENT_SECRET", "")
    if not cid or not cse:
        return {"status": "not_configured", "detail": "credentials missing"}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                "https://id.sophos.com/api/v2/oauth2/token",
                data={"grant_type": "client_credentials", "client_id": cid,
                      "client_secret": cse, "scope": "token"},
            )
        if r.status_code == 200:
            return {"status": "connected", "detail": "token acquired"}
        return {"status": "disconnected", "detail": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"status": "disconnected", "detail": str(exc)}


async def _check_defender() -> dict:
    tenant = os.getenv("AZURE_TENANT_ID", "")
    cid    = os.getenv("DEFENDER_CLIENT_ID", "")
    cse    = os.getenv("DEFENDER_CLIENT_SECRET", "")
    if not (tenant and cid and cse):
        return {"status": "not_configured", "detail": "credentials missing"}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                data={"grant_type": "client_credentials", "client_id": cid,
                      "client_secret": cse,
                      "scope": "https://api.securitycenter.microsoft.com/.default"},
            )
        if r.status_code == 200:
            return {"status": "connected", "detail": "token acquired"}
        return {"status": "disconnected", "detail": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"status": "disconnected", "detail": str(exc)}


async def _check_nessus() -> dict:
    url = os.getenv("NESSUS_URL", "https://localhost:8834").rstrip("/")
    ak  = os.getenv("NESSUS_ACCESS_KEY", "")
    sk  = os.getenv("NESSUS_SECRET_KEY", "")
    if not (ak and sk):
        return {"status": "not_configured", "detail": "API keys missing"}
    try:
        async with httpx.AsyncClient(verify=False, timeout=8,
                                     headers={"X-ApiKeys": f"accessKey={ak}; secretKey={sk}"}) as c:
            r = await c.get(f"{url}/server/status")
        if r.status_code == 200:
            return {"status": "connected", "detail": r.json().get("status", "ok")}
        return {"status": "disconnected", "detail": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"status": "disconnected", "detail": str(exc)}


async def _check_virustotal() -> dict:
    key = os.getenv("VT_API_KEY", "")
    if not key:
        return {"status": "not_configured", "detail": "API key missing"}
    try:
        async with httpx.AsyncClient(timeout=8,
                                     headers={"x-apikey": key}) as c:
            r = await c.get("https://www.virustotal.com/api/v3/users/me")
        if r.status_code == 200:
            return {"status": "connected", "detail": r.json().get("data", {}).get("id", "ok")}
        return {"status": "disconnected", "detail": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"status": "disconnected", "detail": str(exc)}




async def _check_grafana() -> dict:
    url = (os.getenv("GRAFANA_URL") or "").rstrip("/")
    key = os.getenv("GRAFANA_API_KEY", "")
    if not url or not key:
        return {"status": "not_configured", "detail": "GRAFANA_URL or GRAFANA_API_KEY missing"}
    try:
        async with httpx.AsyncClient(timeout=8, verify=False) as c:
            r = await c.get(f"{url}/api/health", headers={"Authorization": f"Bearer {key}"})
        if r.status_code == 200:
            data = r.json()
            return {"status": "connected", "detail": f"v{data.get('version', '?')} — {data.get('database', 'ok')}"}
        return {"status": "disconnected", "detail": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"status": "disconnected", "detail": str(exc)}


async def _check_jira() -> dict:
    base  = (os.getenv("JIRA_BASE_URL") or "").rstrip("/")
    email = os.getenv("JIRA_EMAIL", "")
    token = os.getenv("JIRA_API_TOKEN", "")
    if not (base and email and token):
        return {"status": "not_configured", "detail": "credentials missing"}
    try:
        async with httpx.AsyncClient(timeout=8,
                                     auth=(email, token)) as c:
            r = await c.get(f"{base}/rest/api/3/myself")
        if r.status_code == 200:
            return {"status": "connected", "detail": r.json().get("displayName", "ok")}
        return {"status": "disconnected", "detail": f"HTTP {r.status_code}"}
    except Exception as exc:
        return {"status": "disconnected", "detail": str(exc)}


_HEALTH_CHECKS = {
    "opensearch": _check_opensearch,
    "wazuh-api":  _check_wazuh_api,
    "sophos":     _check_sophos,
    "defender":   _check_defender,
    "entra-id":   _check_defender,   # same Azure app credentials
    "nessus":     _check_nessus,
    "virustotal": _check_virustotal,
    "jira":       _check_jira,
    "grafana":    _check_grafana,
    "darktrace":  _check_opensearch, # Darktrace events come via OpenSearch
}


async def test_connector(connector_id: str) -> dict:
    """Run the health check for a single connector. Returns status + detail + timestamp."""
    check_fn = _HEALTH_CHECKS.get(connector_id)
    if check_fn is None:
        return {
            "status":  "not_configured",
            "detail":  "No health check available — configure env vars and redeploy",
            "checked": datetime.now(timezone.utc).isoformat(),
        }

    connector = next((c for c in CONNECTORS if c["id"] == connector_id), None)
    if connector and not _is_configured(connector):
        return {
            "status":  "not_configured",
            "detail":  "Required environment variables are not set",
            "checked": datetime.now(timezone.utc).isoformat(),
        }

    result = await check_fn()
    result["checked"] = datetime.now(timezone.utc).isoformat()
    return result
