import csv
import io
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_RISK_TO_SEV = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "none":     "info",
    "":         "info",
}
_SEV_NUM = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _unique_summary(findings: list) -> dict:
    """Count unique vulnerabilities by plugin_id (not per-host occurrences)."""
    summary = {s: 0 for s in SEVERITY_ORDER}
    seen: set = set()
    for f in findings:
        key = f.get("plugin_id") or f.get("plugin_name", "unknown")
        if key and key not in seen:
            seen.add(key)
            summary[f.get("severity", "info")] += 1
    summary["total_findings"] = len(seen)
    return summary


# ── CSV parser (Nessus CSV export) ────────────────────────────────────────────

def parse_nessus_csv(content: bytes, mfi: str, quarter: str, year: int, filename: str) -> dict:
    text = content.decode("utf-8-sig")   # strip BOM if present
    reader = csv.DictReader(io.StringIO(text))

    findings  = []
    hosts_map = {}   # ip → per-host counts dict

    for row in reader:
        host    = (row.get("Host") or "").strip()
        risk    = (row.get("Risk") or "").strip().lower()
        sev     = _RISK_TO_SEV.get(risk, "info")
        sev_num = _SEV_NUM[sev]

        if host not in hosts_map:
            hosts_map[host] = {"name": host, "ip": host, "os": "", "fqdn": "",
                               **{s: 0 for s in SEVERITY_ORDER}}
        hosts_map[host][sev] += 1

        cve_raw = (row.get("CVE") or "").strip()
        cves    = [c.strip() for c in cve_raw.split(",") if c.strip()]

        findings.append({
            "plugin_id":    (row.get("Plugin ID") or "").strip(),
            "plugin_name":  (row.get("Name")      or "").strip(),
            "severity":     sev,
            "severity_num": sev_num,
            "host":         host,
            "port":         (row.get("Port")     or "0").strip(),
            "protocol":     (row.get("Protocol") or "").strip(),
            "svc_name":     "",
            "description":  (row.get("Description") or "").strip(),
            "solution":     (row.get("Solution")    or "").strip(),
            "risk_factor":  (row.get("Risk Factor")  or "").strip(),
            "cvss_base":    _float(row.get("CVSS v2.0 Base Score")),
            "cvss3_base":   _float(row.get("CVSS v3.0 Base Score")),
            "cve":          cves,
            "see_also":     (row.get("See Also")      or "").strip(),
            "plugin_output":(row.get("Plugin Output") or "").strip()[:1500],
        })

    hosts   = list(hosts_map.values())
    # summary counts unique vulnerabilities (by plugin_id), not host occurrences
    summary = _unique_summary(findings)
    summary["total_hosts"]    = len(hosts)

    return {
        "scan_id":     str(uuid.uuid4()),
        "mfi":         mfi,
        "quarter":     quarter,
        "year":        year,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "filename":    filename,
        "summary":     summary,
        "hosts":       hosts,
        "findings":    findings,      # all raw findings kept; dedup done at report time
    }


# ── XML parser (.nessus format) ───────────────────────────────────────────────

_XML_SEV_MAP = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}


def parse_nessus_xml(content: bytes, mfi: str, quarter: str, year: int, filename: str) -> dict:
    root    = ET.fromstring(content)
    hosts   = []
    findings = []

    for report in root.iter("Report"):
        for rhost in report.findall("ReportHost"):
            host_name   = rhost.get("name", "unknown")
            props       = {t.get("name"): t.text for t in rhost.findall("HostProperties/tag")}
            host_counts = {s: 0 for s in SEVERITY_ORDER}

            for item in rhost.findall("ReportItem"):
                sev     = _XML_SEV_MAP.get(int(item.get("severity", 0)), "info")
                sev_num = _SEV_NUM[sev]
                host_counts[sev] += 1

                findings.append({
                    "plugin_id":    item.get("pluginID", ""),
                    "plugin_name":  item.get("pluginName", ""),
                    "severity":     sev,
                    "severity_num": sev_num,
                    "host":         host_name,
                    "port":         item.get("port", "0"),
                    "protocol":     item.get("protocol", ""),
                    "svc_name":     item.get("svc_name", ""),
                    "description":  (item.findtext("description") or "").strip(),
                    "solution":     (item.findtext("solution")    or "").strip(),
                    "risk_factor":   item.findtext("risk_factor") or "",
                    "cvss_base":    _float(item.findtext("cvss_base_score")),
                    "cvss3_base":   _float(item.findtext("cvss3_base_score")),
                    "cve":          [c.text for c in item.findall("cve") if c.text],
                    "see_also":     (item.findtext("see_also")      or "").strip(),
                    "plugin_output":(item.findtext("plugin_output") or "").strip()[:1500],
                })

            hosts.append({
                "name": host_name,
                "ip":   props.get("host-ip", host_name),
                "os":   props.get("operating-system") or props.get("os") or "",
                "fqdn": props.get("host-fqdn", ""),
                **host_counts,
            })

    summary = _unique_summary(findings)
    summary["total_hosts"] = len(hosts)

    return {
        "scan_id":     str(uuid.uuid4()),
        "mfi":         mfi,
        "quarter":     quarter,
        "year":        year,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "filename":    filename,
        "summary":     summary,
        "hosts":       hosts,
        "findings":    findings,
    }


# ── Unified entry point ───────────────────────────────────────────────────────

def parse_file(content: bytes, mfi: str, quarter: str, year: int, filename: str) -> dict:
    lower = filename.lower()
    if lower.endswith(".csv"):
        return parse_nessus_csv(content, mfi, quarter, year, filename)
    elif lower.endswith(".nessus"):
        return parse_nessus_xml(content, mfi, quarter, year, filename)
    raise ValueError(f"Unsupported file type: {filename!r}. Use .csv or .nessus")


def _float(val):
    try:
        return float(val) if val else None
    except (ValueError, TypeError):
        return None
