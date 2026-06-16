# #!/var/ossec/framework/python/bin/python3
# """
# Wazuh → MISP Enrichment Integration
# =====================================
# Triggered by Wazuh for every matching alert.  Extracts IOCs, queries MISP,
# then patches the alert document in the Wazuh Indexer (OpenSearch) with the
# results under a top-level "misp" key.

# Deployment
# ----------
#   cp custom-misp      /var/ossec/integrations/custom-misp
#   cp custom-misp.py   /var/ossec/integrations/custom-misp.py
#   chmod 750           /var/ossec/integrations/custom-misp
#   chmod 750           /var/ossec/integrations/custom-misp.py
#   chown root:wazuh    /var/ossec/integrations/custom-misp*

# Configuration (ossec.conf)
# --------------------------
#   <integration>
#     <name>custom-misp</name>
#     <group>sophos,darktrace</group>
#     <alert_format>json</alert_format>
#   </integration>

# Environment variables (set in /etc/systemd/system/wazuh-manager.service.d/misp.conf
# or export them before starting wazuh-manager)
# ---------------------------------------------------------------------------
#   MISP_URL              https://your-misp-instance
#   MISP_KEY              <your MISP automation key>
#   MISP_VERIFY_CERT      false   (true for production with valid cert)
#   MISP_CACHE_TTL        300     (seconds; prevents hammering MISP with the same IOC)
#   INDEXER_URL           https://192.168.47.178:9200
#   INDEXER_USER          admin
#   INDEXER_PASS          <password>
#   INDEXER_VERIFY_CERT   false
# """

# import sys
# import os
# import json
# import re
# import logging
# import time
# from datetime import datetime, timezone
# from collections import defaultdict
# import socket

# try:
#     import urllib3
#     urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# except ImportError:
#     pass

# try:
#     import requests
# except ImportError:
#     sys.exit("requests library not available in this Python environment")


# # ── Configuration ─────────────────────────────────────────────────────────────

# MISP_URL         = os.getenv("MISP_URL",              "https://misp.hope.local")
# MISP_KEY         = os.getenv("MISP_KEY",              "")
# MISP_VERIFY_CERT = os.getenv("MISP_VERIFY_CERT",      "false").lower() == "true"
# MISP_CACHE_TTL   = int(os.getenv("MISP_CACHE_TTL",    "300"))
# MISP_TIMEOUT     = int(os.getenv("MISP_TIMEOUT",      "10"))

# INDEXER_URL      = os.getenv("INDEXER_URL",           "https://192.168.47.178:9200")
# INDEXER_USER     = os.getenv("INDEXER_USER",          "admin")
# INDEXER_PASS     = os.getenv("INDEXER_PASS",          "admin")
# INDEXER_VERIFY   = os.getenv("INDEXER_VERIFY_CERT",   "false").lower() == "true"
# INDEXER_TIMEOUT  = int(os.getenv("INDEXER_TIMEOUT",   "10"))
# INDEXER_RETRIES     = int(os.getenv("INDEXER_RETRIES",      "5"))
# INDEXER_RETRY_DELAY = float(os.getenv("INDEXER_RETRY_DELAY", "2.0"))
# LOG_FILE         = os.getenv("MISP_LOG", "/var/ossec/logs/integrations/custom-misp.log")
# LOG_LEVEL        = os.getenv("MISP_LOG_LEVEL", "INFO").upper()
# WAZUH_QUEUE = "/var/ossec/queue/sockets/queue"


# # ── Logging ───────────────────────────────────────────────────────────────────

# os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
# logging.basicConfig(
#     filename=LOG_FILE,
#     level=getattr(logging, LOG_LEVEL, logging.INFO),
#     format="%(asctime)s %(levelname)s %(message)s",
# )
# log = logging.getLogger("custom-misp")


# # ── Regex helpers ─────────────────────────────────────────────────────────────

# _CVE_FULL = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
# _CVE_BARE = re.compile(r"\b(20\d{2}-\d{4,})\b")   # Sophos omits "CVE-" prefix
# _IP_RE    = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# _HASH_RE  = re.compile(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
# _PRIV_RE  = re.compile(
#     r"^(10\.\d+\.\d+\.\d+"
#     r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
#     r"|192\.168\.\d+\.\d+"
#     r"|127\.\d+\.\d+\.\d+"
#     r"|169\.254\.\d+\.\d+)$"
# )

# _THREAT_LEVEL = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}


# def _is_private(ip: str) -> bool:
#     return bool(_PRIV_RE.match(ip))


# # ── In-process IOC cache ──────────────────────────────────────────────────────
# # Prevents duplicate MISP calls when the same IOC appears in multiple alerts
# # within the same process lifetime (each integration run is a fresh process,
# # so this mainly helps when multiple IOCs from one alert share cache entries
# # across rapid consecutive runs via a pool).

# _cache: dict = {}

# def _cache_get(key):
#     entry = _cache.get(key)
#     if entry and (time.monotonic() - entry["ts"]) < MISP_CACHE_TTL:
#         return entry["data"]
#     return None

# def _cache_set(key, data):
#     _cache[key] = {"data": data, "ts": time.monotonic()}


# # ── MISP REST API ─────────────────────────────────────────────────────────────

# def _misp_headers() -> dict:
#     return {
#         "Authorization": MISP_KEY,
#         "Accept":        "application/json",
#         "Content-Type":  "application/json",
#     }


# def _misp_search(value: str, type_attribute: str = None) -> list:
#     """
#     Call MISP /attributes/restSearch and return a list of per-event summaries.
#     Returns [] on any error so the caller can continue without failing.
#     """
#     cache_key = f"{type_attribute}:{value}"
#     cached = _cache_get(cache_key)
#     if cached is not None:
#         return cached

#     body: dict = {"value": value, "returnFormat": "json", "limit": 50, "includeEventTags": True}
#     if type_attribute:
#         body["type"] = type_attribute

#     try:
#         resp = requests.post(
#             f"{MISP_URL}/attributes/restSearch",
#             headers=_misp_headers(),
#             json=body,
#             verify=MISP_VERIFY_CERT,
#             timeout=MISP_TIMEOUT,
#         )
#         resp.raise_for_status()
#         attributes = resp.json().get("response", {}).get("Attribute", [])
#     except requests.exceptions.RequestException as exc:
#         log.warning("MISP query failed for %r (%s): %s", value, type_attribute, exc)
#         return []

#     hits = _collapse_attributes(attributes)
#     _cache_set(cache_key, hits)
#     log.debug("MISP: %r → %d event(s)", value, len(hits))
#     return hits


# def _collapse_attributes(attributes: list) -> list:
#     """One summary dict per MISP event from a flat attribute list."""
#     events: dict = {}
#     for attr in attributes:
#         ev     = attr.get("Event", {}) or {}
#         eid    = str(ev.get("id", attr.get("event_id", "?")))
#         if eid not in events:
#             # Collect tags from event level
#             ev_tags  = [t.get("name", "") for t in (ev.get("Tag") or [])]
#             # Also collect tags from attribute level
#             att_tags = [t.get("name", "") for t in (attr.get("Tag") or [])]
#             all_tags = sorted(set(ev_tags + att_tags))

#             events[eid] = {
#                 "event_id":        eid,
#                 "event_uuid":      ev.get("uuid", ""),
#                 "event_name":      ev.get("info", ""),
#                 "threat_level":    _THREAT_LEVEL.get(str(ev.get("threat_level_id", "4")), "Undefined"),
#                 "tags":            all_tags,
#                 "org":             (ev.get("Orgc") or {}).get("name", ""),
#                 "date":            ev.get("date", ""),
#                 "published":       bool(ev.get("published")),
#                 "attribute_count": 0,
#             }
#         events[eid]["attribute_count"] += 1

#     return list(events.values())


# def misp_lookup_ip(ip: str) -> list:
#     if not ip or _is_private(ip):
#         return []
#     return _misp_search(ip)


# def misp_lookup_cve(cve: str) -> list:
#     return _misp_search(cve.upper(), type_attribute="vulnerability")


# def misp_lookup_domain(domain: str) -> list:
#     return _misp_search(domain.lower(), type_attribute="domain")


# def misp_lookup_hash(value: str) -> list:
#     type_map = {32: "md5", 40: "sha1", 64: "sha256"}
#     htype = type_map.get(len(value))
#     return _misp_search(value.lower(), type_attribute=htype)


# # ── IOC Extraction ────────────────────────────────────────────────────────────

# def extract_sophos_iocs(data: dict) -> dict:
#     sophos   = data.get("sophos", {}) or {}
#     ips_data = sophos.get("ips_threat_data", {}) or {}
#     raw_data = ips_data.get("rawData", "") or ""
#     threat   = sophos.get("threat", "") or ""

#     ips: set    = set()
#     cves: set   = set()
#     domains: set = set()
#     hashes: set = set()

#     # Remote IP from IPS event (primary external IOC)
#     r_ip = ips_data.get("remoteIp", "")
#     if r_ip and not _is_private(r_ip):
#         ips.add(r_ip)

#     # Additional IPs hidden in the rawData blob
#     for ip in _IP_RE.findall(raw_data):
#         if not _is_private(ip):
#             ips.add(ip)

#     # CVEs from rawData and threat string
#     for cve in _CVE_FULL.findall(raw_data):
#         cves.add(cve.upper())
#     for cve in _CVE_FULL.findall(threat):
#         cves.add(cve.upper())
#     # Bare year-NNNN pattern Sophos uses (e.g. "2021-41773")
#     for bare in _CVE_BARE.findall(threat):
#         cves.add(f"CVE-{bare}")

#     # Hashes in rawData (e.g. executable hashes in other Sophos event types)
#     for h in _HASH_RE.findall(raw_data):
#         hashes.add(h.lower())

#     return {
#         "ips":     sorted(ips),
#         "cves":    sorted(cves),
#         "domains": sorted(domains),
#         "hashes":  sorted(hashes),
#     }


# # Stubs — populated when Darktrace / MS Graph enrichment is added
# def extract_darktrace_iocs(data: dict) -> dict:
#     return {"ips": [], "cves": [], "domains": [], "hashes": []}

# def extract_msgraph_iocs(data: dict) -> dict:
#     return {"ips": [], "cves": [], "domains": [], "hashes": []}


# IOC_EXTRACTORS = {
#     "sophos":    extract_sophos_iocs,
#     "darktrace": extract_darktrace_iocs,
#     "ms-graph":  extract_msgraph_iocs,
# }


# # ── MISP enrichment runner ────────────────────────────────────────────────────

# def run_enrichment(iocs: dict) -> dict:
#     hits: list = []

#     for ip in iocs["ips"]:
#         for h in misp_lookup_ip(ip):
#             hits.append({"ioc_type": "ip", "ioc_value": ip, **h})

#     for cve in iocs["cves"]:
#         for h in misp_lookup_cve(cve):
#             hits.append({"ioc_type": "cve", "ioc_value": cve, **h})

#     for domain in iocs["domains"]:
#         for h in misp_lookup_domain(domain):
#             hits.append({"ioc_type": "domain", "ioc_value": domain, **h})

#     for hash_val in iocs["hashes"]:
#         for h in misp_lookup_hash(hash_val):
#             hits.append({"ioc_type": "hash", "ioc_value": hash_val, **h})

#     severity_boost = _calc_boost(hits)

#     return {
#         "enriched_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
#         "iocs_checked":   iocs,
#         "hits":           hits,
#         "hit_count":      len(hits),
#         "severity_boost": severity_boost,
#         "enriched":       len(hits) > 0,
#     }


# def _calc_boost(hits: list) -> int:
#     if not hits:
#         return 0
#     levels = {h.get("threat_level") for h in hits}
#     if "High"   in levels: return 4
#     if "Medium" in levels: return 2
#     return 1
# def send_wazuh_event(alert: dict, enrichment: dict, iocs: dict) -> None:
#     """Inject a new alert into Wazuh analysisd for every MISP IOC match."""
#     if not enrichment.get("enriched"):
#         return

#     hits      = enrichment.get("hits", [])
#     rank      = {"High": 3, "Medium": 2, "Low": 1, "Undefined": 0}
#     top_hit   = max(hits, key=lambda h: rank.get(h.get("threat_level", "Undefined"), 0), default={})

#     event = {
#         "misp_match":        True,
#         "misp_hit_count":    enrichment["hit_count"],
#         "misp_threat_level": top_hit.get("threat_level", "Undefined"),
#         "misp_event_name":   top_hit.get("event_name", ""),
#         "misp_event_id":     top_hit.get("event_id", ""),
#         "misp_org":          top_hit.get("org", ""),
#         "misp_tags":         list({tag for h in hits for tag in h.get("tags", [])}),
#         "misp_iocs_ips":     iocs.get("ips", []),
#         "misp_iocs_cves":    iocs.get("cves", []),
#         "misp_iocs_domains": iocs.get("domains", []),
#         "misp_iocs_hashes":  iocs.get("hashes", []),
#         "src_alert_id":      alert.get("id", ""),
#         "src_agent_name":    alert.get("agent", {}).get("name", ""),
#         "src_agent_ip":      alert.get("agent", {}).get("ip", ""),
#         "src_rule_desc":     alert.get("rule", {}).get("description", ""),
#         "src_source":        detect_source(alert),
#     }

#     try:
#         msg  = json.dumps(event, separators=(",", ":"))
#         sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
#         sock.connect(WAZUH_QUEUE)
#         sock.send(f"1:misp:{msg}".encode("utf-8"))
#         sock.close()
#         log.info("MISP event injected to Wazuh queue for alert %s", alert.get("id"))
#     except Exception as exc:
#         log.warning("Failed to inject MISP event to Wazuh queue: %s", exc)
        

# # ── OpenSearch / Wazuh Indexer ────────────────────────────────────────────────

# def _indexer_session() -> requests.Session:
#     s = requests.Session()
#     s.auth    = (INDEXER_USER, INDEXER_PASS)
#     s.verify  = INDEXER_VERIFY
#     s.headers.update({"Content-Type": "application/json"})
#     return s

# def find_document_with_retry(session: requests.Session, wazuh_id: str):
#     """
#     Retry the OpenSearch lookup to handle near-real-time indexing delay.
#     Wazuh fires integrations before the document is committed (~1s lag).
#     """
#     for attempt in range(1, INDEXER_RETRIES + 1):
#         index, doc_id = find_document(session, wazuh_id)
#         if doc_id:
#             return index, doc_id
#         if attempt < INDEXER_RETRIES:
#             log.debug(
#                 "Alert %s not indexed yet — retrying in %.0fs (attempt %d/%d)",
#                 wazuh_id, INDEXER_RETRY_DELAY, attempt, INDEXER_RETRIES,
#             )
#             time.sleep(INDEXER_RETRY_DELAY)
#     return None, None

# def find_document(session: requests.Session, wazuh_id: str):
#     """
#     Locate the OpenSearch document for this Wazuh alert ID.
#     Returns (index, doc_id) or (None, None).
#     """
#     body = {
#         "size": 1,
#         "_source": False,
#         "query": {"term": {"id": wazuh_id}},
#     }
#     try:
#         resp = session.get(
#             f"{INDEXER_URL}/wazuh-alerts-*/_search",
#             json=body,
#             timeout=INDEXER_TIMEOUT,
#         )
#         resp.raise_for_status()
#         hits = resp.json().get("hits", {}).get("hits", [])
#         if hits:
#             return hits[0]["_index"], hits[0]["_id"]
#     except requests.exceptions.RequestException as exc:
#         log.error("OpenSearch find failed for alert %s: %s", wazuh_id, exc)
#     return None, None


# def patch_document(session: requests.Session, index: str, doc_id: str, misp_data: dict) -> bool:
#     """Add/replace the top-level 'misp' field on the alert document."""
#     try:
#         resp = session.post(
#             f"{INDEXER_URL}/{index}/_update/{doc_id}",
#             json={"doc": {"misp": misp_data}},
#             timeout=INDEXER_TIMEOUT,
#         )
#         resp.raise_for_status()
#         return True
#     except requests.exceptions.RequestException as exc:
#         log.error("OpenSearch update failed for %s/%s: %s", index, doc_id, exc)
#         return False


# # ── Entry point ───────────────────────────────────────────────────────────────

# def detect_source(alert: dict) -> str:
#     data   = alert.get("data", {}) or {}
#     integ  = data.get("integration", "")
#     groups = alert.get("rule", {}).get("groups", []) or []

#     if integ in ("sophos-central",):
#         return "sophos"
#     if "darktrace" in groups:
#         return "darktrace"
#     if integ == "ms-graph":
#         return "ms-graph"
#     return "wazuh"


# def main():
#     if len(sys.argv) < 2:
#         log.error("Usage: custom-misp.py <alert_file> [api_key] [hook_url]")
#         sys.exit(1)

#     alert_file = sys.argv[1]

#     # argv[2] can carry MISP_KEY if set in ossec.conf <api_key> block
#     if len(sys.argv) >= 3 and sys.argv[2].strip():
#         global MISP_KEY
#         MISP_KEY = sys.argv[2].strip()

#     if not MISP_KEY:
#         log.error("MISP_KEY not set — cannot enrich. Set MISP_KEY env var or <api_key> in ossec.conf")
#         sys.exit(1)

#     try:
#         with open(alert_file) as fh:
#             alert = json.load(fh)
#     except (OSError, json.JSONDecodeError) as exc:
#         log.error("Cannot read alert file %s: %s", alert_file, exc)
#         sys.exit(1)

#     wazuh_id = alert.get("id", "")
#     source   = detect_source(alert)
#     extractor = IOC_EXTRACTORS.get(source)

#     if extractor is None:
#         log.debug("No IOC extractor for source %r (alert %s) — skipping", source, wazuh_id)
#         sys.exit(0)

#     iocs = extractor(alert.get("data", {}))
#     total_iocs = sum(len(v) for v in iocs.values())

#     if total_iocs == 0:
#         log.debug("No IOCs extracted from %s alert %s — skipping", source, wazuh_id)
#         sys.exit(0)

#     log.info("Enriching alert %s (source=%s) — %d IOC(s): %s",
#              wazuh_id, source, total_iocs, iocs)

#     enrichment = run_enrichment(iocs)
#     send_wazuh_event(alert, enrichment, iocs)
#     session = _indexer_session()
#     index, doc_id = find_document_with_retry(session, wazuh_id)

#     if not doc_id:
#         log.warning("Alert %s not found in OpenSearch — cannot patch", wazuh_id)
#         sys.exit(0)

#     ok = patch_document(session, index, doc_id, enrichment)

#     if ok:
#         log.info("Alert %s patched — %d MISP hit(s), boost +%d",
#                  wazuh_id, enrichment["hit_count"], enrichment["severity_boost"])
#     else:
#         log.error("Failed to patch alert %s", wazuh_id)
#         sys.exit(1)


# if __name__ == "__main__":
#     main()

#!/var/ossec/framework/python/bin/python3
"""
Wazuh → MISP Enrichment Integration
=====================================
Triggered by Wazuh for every matching alert.  Extracts IOCs, queries MISP,
then patches the alert document in the Wazuh Indexer (OpenSearch) with the
results under a top-level "misp" key.

Deployment
----------
  cp custom-misp      /var/ossec/integrations/custom-misp
  cp custom-misp.py   /var/ossec/integrations/custom-misp.py
  chmod 750           /var/ossec/integrations/custom-misp
  chmod 750           /var/ossec/integrations/custom-misp.py
  chown root:wazuh    /var/ossec/integrations/custom-misp*

Configuration (ossec.conf)
--------------------------
  <integration>
    <name>custom-misp</name>
    <group>sophos,darktrace</group>
    <alert_format>json</alert_format>
  </integration>

Environment variables (set in /etc/systemd/system/wazuh-manager.service.d/misp.conf
or export them before starting wazuh-manager)
---------------------------------------------------------------------------
  MISP_URL              https://your-misp-instance
  MISP_KEY              <your MISP automation key>
  MISP_VERIFY_CERT      false   (true for production with valid cert)
  MISP_CACHE_TTL        300     (seconds; prevents hammering MISP with the same IOC)
  INDEXER_URL           https://192.168.47.178:9200
  INDEXER_USER          admin
  INDEXER_PASS          <password>
  INDEXER_VERIFY_CERT   false
"""

import sys
import os
import json
import re
import logging
import time
from datetime import datetime, timezone
from collections import defaultdict

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    pass

try:
    import requests
except ImportError:
    sys.exit("requests library not available in this Python environment")


# ── Configuration ─────────────────────────────────────────────────────────────

MISP_URL         = os.getenv("MISP_URL",              "https://misp.hope.local")
MISP_KEY         = os.getenv("MISP_KEY",              "")
MISP_VERIFY_CERT = os.getenv("MISP_VERIFY_CERT",      "false").lower() == "true"
MISP_CACHE_TTL   = int(os.getenv("MISP_CACHE_TTL",    "300"))
MISP_TIMEOUT     = int(os.getenv("MISP_TIMEOUT",      "10"))

INDEXER_URL      = os.getenv("INDEXER_URL",           "https://192.168.47.178:9200")
INDEXER_USER     = os.getenv("INDEXER_USER",          "admin")
INDEXER_PASS     = os.getenv("INDEXER_PASS",          "admin")
INDEXER_VERIFY   = os.getenv("INDEXER_VERIFY_CERT",   "false").lower() == "true"
INDEXER_TIMEOUT  = int(os.getenv("INDEXER_TIMEOUT",   "10"))
INDEXER_RETRIES     = int(os.getenv("INDEXER_RETRIES",      "5"))
INDEXER_RETRY_DELAY = float(os.getenv("INDEXER_RETRY_DELAY", "2.0"))
LOG_FILE         = os.getenv("MISP_LOG", "/var/ossec/logs/integrations/custom-misp.log")
LOG_LEVEL        = os.getenv("MISP_LOG_LEVEL", "INFO").upper()


# ── Logging ───────────────────────────────────────────────────────────────────

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("custom-misp")


# ── Regex helpers ─────────────────────────────────────────────────────────────

_CVE_FULL = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CVE_BARE = re.compile(r"\b(20\d{2}-\d{4,})\b")   # Sophos omits "CVE-" prefix
_IP_RE    = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE  = re.compile(r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
_PRIV_RE  = re.compile(
    r"^(10\.\d+\.\d+\.\d+"
    r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+"
    r"|127\.\d+\.\d+\.\d+"
    r"|169\.254\.\d+\.\d+)$"
)

_THREAT_LEVEL = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}


def _is_private(ip: str) -> bool:
    return bool(_PRIV_RE.match(ip))


# ── In-process IOC cache ──────────────────────────────────────────────────────
# Prevents duplicate MISP calls when the same IOC appears in multiple alerts
# within the same process lifetime (each integration run is a fresh process,
# so this mainly helps when multiple IOCs from one alert share cache entries
# across rapid consecutive runs via a pool).

_cache: dict = {}

def _cache_get(key):
    entry = _cache.get(key)
    if entry and (time.monotonic() - entry["ts"]) < MISP_CACHE_TTL:
        return entry["data"]
    return None

def _cache_set(key, data):
    _cache[key] = {"data": data, "ts": time.monotonic()}


# ── MISP REST API ─────────────────────────────────────────────────────────────

def _misp_headers() -> dict:
    return {
        "Authorization": MISP_KEY,
        "Accept":        "application/json",
        "Content-Type":  "application/json",
    }


def _misp_search(value: str, type_attribute: str = None) -> list:
    """
    Call MISP /attributes/restSearch and return a list of per-event summaries.
    Returns [] on any error so the caller can continue without failing.
    """
    cache_key = f"{type_attribute}:{value}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    body: dict = {"value": value, "returnFormat": "json", "limit": 50, "includeEventTags": True}
    if type_attribute:
        body["type"] = type_attribute

    try:
        resp = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers=_misp_headers(),
            json=body,
            verify=MISP_VERIFY_CERT,
            timeout=MISP_TIMEOUT,
        )
        resp.raise_for_status()
        attributes = resp.json().get("response", {}).get("Attribute", [])
    except requests.exceptions.RequestException as exc:
        log.warning("MISP query failed for %r (%s): %s", value, type_attribute, exc)
        return []

    hits = _collapse_attributes(attributes)
    _cache_set(cache_key, hits)
    log.debug("MISP: %r → %d event(s)", value, len(hits))
    return hits


def _collapse_attributes(attributes: list) -> list:
    """One summary dict per MISP event from a flat attribute list."""
    events: dict = {}
    for attr in attributes:
        ev     = attr.get("Event", {}) or {}
        eid    = str(ev.get("id", attr.get("event_id", "?")))
        if eid not in events:
            # Collect tags from event level
            ev_tags  = [t.get("name", "") for t in (ev.get("Tag") or [])]
            # Also collect tags from attribute level
            att_tags = [t.get("name", "") for t in (attr.get("Tag") or [])]
            all_tags = sorted(set(ev_tags + att_tags))

            events[eid] = {
                "event_id":        eid,
                "event_uuid":      ev.get("uuid", ""),
                "event_name":      ev.get("info", ""),
                "threat_level":    _THREAT_LEVEL.get(str(ev.get("threat_level_id", "4")), "Undefined"),
                "tags":            all_tags,
                "org":             (ev.get("Orgc") or {}).get("name", ""),
                "date":            ev.get("date", ""),
                "published":       bool(ev.get("published")),
                "attribute_count": 0,
            }
        events[eid]["attribute_count"] += 1

    return list(events.values())


def misp_lookup_ip(ip: str) -> list:
    if not ip or _is_private(ip):
        return []
    return _misp_search(ip)


def misp_lookup_cve(cve: str) -> list:
    return _misp_search(cve.upper(), type_attribute="vulnerability")


def misp_lookup_domain(domain: str) -> list:
    return _misp_search(domain.lower(), type_attribute="domain")


def misp_lookup_hash(value: str) -> list:
    type_map = {32: "md5", 40: "sha1", 64: "sha256"}
    htype = type_map.get(len(value))
    return _misp_search(value.lower(), type_attribute=htype)


# ── IOC Extraction ────────────────────────────────────────────────────────────

def extract_sophos_iocs(data: dict) -> dict:
    sophos   = data.get("sophos", {}) or {}
    ips_data = sophos.get("ips_threat_data", {}) or {}
    raw_data = ips_data.get("rawData", "") or ""
    threat   = sophos.get("threat", "") or ""

    ips: set    = set()
    cves: set   = set()
    domains: set = set()
    hashes: set = set()

    # Remote IP from IPS event (primary external IOC)
    r_ip = ips_data.get("remoteIp", "")
    if r_ip and not _is_private(r_ip):
        ips.add(r_ip)

    # Additional IPs hidden in the rawData blob
    for ip in _IP_RE.findall(raw_data):
        if not _is_private(ip):
            ips.add(ip)

    # CVEs from rawData and threat string
    for cve in _CVE_FULL.findall(raw_data):
        cves.add(cve.upper())
    for cve in _CVE_FULL.findall(threat):
        cves.add(cve.upper())
    # Bare year-NNNN pattern Sophos uses (e.g. "2021-41773")
    for bare in _CVE_BARE.findall(threat):
        cves.add(f"CVE-{bare}")

    # Hashes in rawData (e.g. executable hashes in other Sophos event types)
    for h in _HASH_RE.findall(raw_data):
        hashes.add(h.lower())

    return {
        "ips":     sorted(ips),
        "cves":    sorted(cves),
        "domains": sorted(domains),
        "hashes":  sorted(hashes),
    }


def extract_darktrace_iocs(data: dict) -> dict:
    ips: set     = set()
    domains: set = set()
    hashes: set  = set()

    # AGEMail events carry email-specific fields; Model Breach events carry network fields
    is_agemail = "from" in data or "recipients" in data or "subject" in data

    if is_agemail:
        # Sender domain — primary IOC for phishing/spam investigation
        from_addr = (data.get("from") or "").strip()
        if "@" in from_addr:
            sender_domain = from_addr.split("@", 1)[1].strip().lower()
            if sender_domain:
                domains.add(sender_domain)

        # Domains embedded in hyperlinks inside the email body
        for host in (data.get("link_hosts") or []):
            host = str(host).strip().lower()
            if host:
                domains.add(host)

        # Attachment hashes
        for att in (data.get("attachments") or []):
            for hf in ("sha256", "sha1", "md5", "hash"):
                hv = (att.get(hf) or "").strip()
                if _HASH_RE.search(hv):
                    hashes.add(hv.lower())
    else:
        # Model Breach — network-facing IOCs
        src_ip = (data.get("sourceIP") or "").strip()
        if src_ip and _IP_RE.search(src_ip) and not _is_private(src_ip):
            ips.add(src_ip)

        dest = (data.get("dest") or "").strip()
        if dest:
            if _IP_RE.search(dest) and not _is_private(dest):
                ips.add(dest)
            elif dest:
                domains.add(dest.lower())

        for comp in (data.get("triggeredComponents") or []):
            for fv in (comp.get("filterValues") or []):
                fv = str(fv).strip()
                if _IP_RE.search(fv) and not _is_private(fv):
                    ips.add(fv)

        for ip in ((data.get("device") or {}).get("ips") or []):
            if _IP_RE.search(str(ip)) and not _is_private(str(ip)):
                ips.add(str(ip))

    return {
        "ips":     sorted(ips),
        "cves":    [],
        "domains": sorted(domains),
        "hashes":  sorted(hashes),
    }


def extract_msgraph_iocs(data: dict) -> dict:
    return {"ips": [], "cves": [], "domains": [], "hashes": []}


IOC_EXTRACTORS = {
    "sophos":    extract_sophos_iocs,
    "darktrace": extract_darktrace_iocs,
    "ms-graph":  extract_msgraph_iocs,
}


# ── MISP enrichment runner ────────────────────────────────────────────────────

def run_enrichment(iocs: dict) -> dict:
    hits: list = []

    for ip in iocs["ips"]:
        for h in misp_lookup_ip(ip):
            hits.append({"ioc_type": "ip", "ioc_value": ip, **h})

    for cve in iocs["cves"]:
        for h in misp_lookup_cve(cve):
            hits.append({"ioc_type": "cve", "ioc_value": cve, **h})

    for domain in iocs["domains"]:
        for h in misp_lookup_domain(domain):
            hits.append({"ioc_type": "domain", "ioc_value": domain, **h})

    for hash_val in iocs["hashes"]:
        for h in misp_lookup_hash(hash_val):
            hits.append({"ioc_type": "hash", "ioc_value": hash_val, **h})

    severity_boost = _calc_boost(hits)

    return {
        "enriched_at":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iocs_checked":   iocs,
        "hits":           hits,
        "hit_count":      len(hits),
        "severity_boost": severity_boost,
        "enriched":       len(hits) > 0,
    }


def _calc_boost(hits: list) -> int:
    if not hits:
        return 0
    levels = {h.get("threat_level") for h in hits}
    if "High"   in levels: return 4
    if "Medium" in levels: return 2
    return 1


# ── OpenSearch / Wazuh Indexer ────────────────────────────────────────────────

def _indexer_session() -> requests.Session:
    s = requests.Session()
    s.auth    = (INDEXER_USER, INDEXER_PASS)
    s.verify  = INDEXER_VERIFY
    s.headers.update({"Content-Type": "application/json"})
    return s

# def find_document_with_retry(session: requests.Session, wazuh_id: str):
#     """
#     Retry the OpenSearch lookup to handle near-real-time indexing delay.
#     Wazuh fires integrations before the document is committed (~1s lag).
#     """
#     for attempt in range(1, INDEXER_RETRIES + 1):
#         index, doc_id = find_document(session, wazuh_id)
#         if doc_id:
#             return index, doc_id
#         if attempt < INDEXER_RETRIES:
#             log.debug(
#                 "Alert %s not indexed yet — retrying in %.0fs (attempt %d/%d)",
#                 wazuh_id, INDEXER_RETRY_DELAY, attempt, INDEXER_RETRIES,
#             )
#             time.sleep(INDEXER_RETRY_DELAY)
#     return None, None


def find_document_with_retry(session: requests.Session, wazuh_id: str):
    # Force NRT refresh on first attempt so the doc is immediately visible
    try:
        session.post(
            f"{INDEXER_URL}/wazuh-alerts-*/_refresh",
            timeout=INDEXER_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        log.debug("Index refresh failed (non-fatal): %s", exc)

    for attempt in range(1, INDEXER_RETRIES + 1):
        index, doc_id = find_document(session, wazuh_id)
        if doc_id:
            return index, doc_id
        if attempt < INDEXER_RETRIES:
            log.debug(
                "Alert %s not indexed yet — retrying in %.0fs (attempt %d/%d)",
                wazuh_id, INDEXER_RETRY_DELAY, attempt, INDEXER_RETRIES,
            )
            time.sleep(INDEXER_RETRY_DELAY)
    return None, None

def find_document(session: requests.Session, wazuh_id: str):
    """
    Locate the OpenSearch document for this Wazuh alert ID.
    Returns (index, doc_id) or (None, None).
    """
    body = {
        "size": 1,
        "_source": False,
        "query": {"term": {"id": wazuh_id}},
    }
    try:
        resp = session.get(
            f"{INDEXER_URL}/wazuh-alerts-*/_search",
            json=body,
            timeout=INDEXER_TIMEOUT,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        if hits:
            return hits[0]["_index"], hits[0]["_id"]
    except requests.exceptions.RequestException as exc:
        log.error("OpenSearch find failed for alert %s: %s", wazuh_id, exc)
    return None, None


def patch_document(session: requests.Session, index: str, doc_id: str, misp_data: dict) -> bool:
    """Add/replace the top-level 'misp' field on the alert document."""
    try:
        resp = session.post(
            f"{INDEXER_URL}/{index}/_update/{doc_id}",
            json={"doc": {"misp": misp_data}},
            timeout=INDEXER_TIMEOUT,
        )
        resp.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        log.error("OpenSearch update failed for %s/%s: %s", index, doc_id, exc)
        return False


# ── Entry point ───────────────────────────────────────────────────────────────

def detect_source(alert: dict) -> str:
    data   = alert.get("data", {}) or {}
    integ  = data.get("integration", "")
    groups = alert.get("rule", {}).get("groups", []) or []

    if integ in ("sophos-central",):
        return "sophos"
    if "darktrace" in groups:
        return "darktrace"
    if integ == "ms-graph":
        return "ms-graph"
    return "wazuh"


def main():
    if len(sys.argv) < 2:
        log.error("Usage: custom-misp.py <alert_file> [api_key] [hook_url]")
        sys.exit(1)

    alert_file = sys.argv[1]

    # argv[2] can carry MISP_KEY if set in ossec.conf <api_key> block
    if len(sys.argv) >= 3 and sys.argv[2].strip():
        global MISP_KEY
        MISP_KEY = sys.argv[2].strip()

    if not MISP_KEY:
        log.error("MISP_KEY not set — cannot enrich. Set MISP_KEY env var or <api_key> in ossec.conf")
        sys.exit(1)

    try:
        with open(alert_file) as fh:
            alert = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Cannot read alert file %s: %s", alert_file, exc)
        sys.exit(1)

    wazuh_id = alert.get("id", "")
    source   = detect_source(alert)
    extractor = IOC_EXTRACTORS.get(source)

    if extractor is None:
        log.debug("No IOC extractor for source %r (alert %s) — skipping", source, wazuh_id)
        sys.exit(0)

    iocs = extractor(alert.get("data", {}))
    total_iocs = sum(len(v) for v in iocs.values())

    if total_iocs == 0:
        log.debug("No IOCs extracted from %s alert %s — skipping", source, wazuh_id)
        sys.exit(0)

    log.info("Enriching alert %s (source=%s) — %d IOC(s): %s",
             wazuh_id, source, total_iocs, iocs)

    enrichment = run_enrichment(iocs)

    session = _indexer_session()
    index, doc_id = find_document_with_retry(session, wazuh_id)

    if not doc_id:
        log.warning("Alert %s not found in OpenSearch — cannot patch", wazuh_id)
        sys.exit(0)

    ok = patch_document(session, index, doc_id, enrichment)

    if ok:
        log.info("Alert %s patched — %d MISP hit(s), boost +%d",
                 wazuh_id, enrichment["hit_count"], enrichment["severity_boost"])
    else:
        log.error("Failed to patch alert %s", wazuh_id)
        sys.exit(1)


if __name__ == "__main__":
    main()