"""
VirusTotal API v3 — on-demand IOC lookups.
Supports: IP addresses, domains, file hashes (MD5/SHA1/SHA256).

Environment variables
---------------------
  VT_API_KEY    Your VirusTotal API key (required)
  VT_TIMEOUT    HTTP timeout in seconds (default: 15)
"""

import os
from typing import Optional
import requests

VT_BASE    = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = int(os.getenv("VT_TIMEOUT", "15"))


def _api_key() -> str:
    return os.getenv("VT_API_KEY", "")

# RFC-1918 / loopback / link-local prefixes
_PRIV_PREFIXES = (
    "10.", "192.168.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)


class VirusTotalError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIV_PREFIXES)


def _headers() -> dict:
    return {"x-apikey": _api_key(), "Accept": "application/json"}


def _get(path: str) -> dict:
    if not _api_key():
        raise VirusTotalError(503, "VT_API_KEY is not configured on the server")
    try:
        resp = requests.get(
            f"{VT_BASE}{path}",
            headers=_headers(),
            timeout=VT_TIMEOUT,
        )
    except requests.exceptions.Timeout:
        raise VirusTotalError(504, "VirusTotal request timed out")
    except requests.exceptions.RequestException as exc:
        raise VirusTotalError(502, f"VirusTotal unreachable: {exc}")

    if resp.status_code == 404:
        raise VirusTotalError(404, "IOC not found in VirusTotal database")
    if resp.status_code == 401:
        raise VirusTotalError(401, "VirusTotal API key is invalid or expired")
    if resp.status_code == 429:
        raise VirusTotalError(429, "VirusTotal rate limit exceeded — try again later")
    if not resp.ok:
        raise VirusTotalError(resp.status_code, f"VirusTotal returned HTTP {resp.status_code}")
    return resp.json()


def _verdict(stats: dict) -> str:
    malicious  = stats.get("malicious",  0)
    suspicious = stats.get("suspicious", 0)
    if malicious  >= 3: return "malicious"
    if malicious  >= 1: return "suspicious"
    if suspicious >= 3: return "suspicious"
    if suspicious >= 1: return "suspicious"
    if sum(stats.values()) == 0: return "unknown"
    return "clean"


def _top_detections(results: dict, limit: int = 15) -> list:
    out = []
    for engine, det in results.items():
        cat = det.get("category", "")
        if cat in ("malicious", "suspicious"):
            out.append({
                "engine":   engine,
                "category": cat,
                "result":   det.get("result") or cat,
            })
        if len(out) >= limit:
            break
    return out


def _whois_summary(raw: str, max_lines: int = 10) -> Optional[str]:
    if not raw:
        return None
    lines = [
        l.strip() for l in raw.splitlines()
        if l.strip() and not l.startswith(("%", "#", ";"))
    ]
    return "\n".join(lines[:max_lines]) or None


def lookup_ip(ip: str) -> dict:
    if is_private_ip(ip):
        raise VirusTotalError(400, f"{ip} is a private/reserved address — not queryable")
    data  = _get(f"/ip_addresses/{ip}")["data"]
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ioc_type":    "ip",
        "ioc_value":   ip,
        "verdict":     _verdict(stats),
        "stats":       stats,
        "reputation":  attrs.get("reputation"),
        "country":     attrs.get("country"),
        "asn":         attrs.get("asn"),
        "as_owner":    attrs.get("as_owner"),
        "network":     attrs.get("network"),
        "tags":        attrs.get("tags") or [],
        "whois":       _whois_summary(attrs.get("whois", "")),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "top_detections":     _top_detections(attrs.get("last_analysis_results", {})),
        "permalink":   f"https://www.virustotal.com/gui/ip-address/{ip}",
    }


def lookup_domain(domain: str) -> dict:
    data  = _get(f"/domains/{domain}")["data"]
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    # categories is a vendor→label dict; de-duplicate values
    cat_dict = attrs.get("categories") or {}
    cat_list = list(dict.fromkeys(cat_dict.values()))[:6]
    return {
        "ioc_type":    "domain",
        "ioc_value":   domain,
        "verdict":     _verdict(stats),
        "stats":       stats,
        "reputation":  attrs.get("reputation"),
        "registrar":   attrs.get("registrar"),
        "categories":  cat_list,
        "creation_date": attrs.get("creation_date"),
        "last_update_date": attrs.get("last_modification_date"),
        "tags":        attrs.get("tags") or [],
        "whois":       _whois_summary(attrs.get("whois", "")),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "top_detections":     _top_detections(attrs.get("last_analysis_results", {})),
        "permalink":   f"https://www.virustotal.com/gui/domain/{domain}",
    }


def lookup_hash(hash_value: str) -> dict:
    h = hash_value.strip().lower()
    data  = _get(f"/files/{h}")["data"]
    attrs = data.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ioc_type":    "hash",
        "ioc_value":   h,
        "verdict":     _verdict(stats),
        "stats":       stats,
        "reputation":  attrs.get("reputation"),
        "meaningful_name":   attrs.get("meaningful_name"),
        "type_description":  attrs.get("type_description"),
        "size":              attrs.get("size"),
        "sha256":            attrs.get("sha256"),
        "sha1":              attrs.get("sha1"),
        "md5":               attrs.get("md5"),
        "tags":              attrs.get("tags") or [],
        "last_analysis_date": attrs.get("last_analysis_date"),
        "top_detections":    _top_detections(attrs.get("last_analysis_results", {})),
        "permalink":  f"https://www.virustotal.com/gui/file/{attrs.get('sha256', h)}",
    }
