SEV_COLORS = {
    "critical": "#da3633",
    "high":     "#d29922",
    "medium":   "#3b82f6",
    "low":      "#34d399",
    "info":     "#6b7280",
}
SEV_BG = {
    "critical": "#da363322",
    "high":     "#d2992222",
    "medium":   "#3b82f622",
    "low":      "#34d39922",
    "info":     "#6b728022",
}

_BASE_CSS = """
  body { font-family: Arial, sans-serif; color: #1f2937; max-width: 1100px; margin: 0 auto; padding: 40px; font-size: 13px; }
  h1 { color: #111827; border-bottom: 3px solid #da3633; padding-bottom: 10px; font-size: 22px; }
  h2 { color: #111827; margin-top: 32px; font-size: 16px; border-left: 4px solid #da3633; padding-left: 10px; }
  h3 { color: #374151; font-size: 14px; margin-top: 20px; }
  .meta { color: #6b7280; font-size: 13px; margin-bottom: 28px; }
  .meta strong { color: #111827; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th { background: #1f2937; color: #f9fafb; padding: 8px 10px; text-align: left; font-size: 12px; white-space: nowrap; }
  td { padding: 7px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; font-size: 12px; }
  tr:nth-child(even) td { background: #f9fafb; }
  tr:hover td { background: #f0f9ff; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .footer { margin-top: 48px; font-size: 11px; color: #9ca3af; border-top: 1px solid #e5e7eb; padding-top: 12px; }
  @media print { body { padding: 16px; } @page { margin: 1.5cm; } }
"""


def _badge(sev: str) -> str:
    c = SEV_COLORS.get(sev, "#6b7280")
    b = SEV_BG.get(sev, "#6b728022")
    return f'<span class="badge" style="background:{b};color:{c}">{sev.upper()}</span>'


def generate_executive_report(scan: dict) -> str:
    s        = scan["summary"]
    mfi      = scan["mfi"]
    period   = f"{scan['quarter']} {scan['year']}"
    date     = (scan.get("uploaded_at") or "")[:10]
    filename = scan.get("filename", "")

    top = sorted(
        [f for f in scan.get("findings", []) if f["severity"] in ("critical", "high")],
        key=lambda x: (-(x.get("cvss3_base") or x.get("cvss_base") or 0)),
    )[:15]

    rows = ""
    for f in top:
        score = f.get("cvss3_base") or f.get("cvss_base") or "—"
        cves  = ", ".join(f.get("cve", [])[:3]) or "—"
        sol   = (f.get("solution") or "—")[:180]
        rows += f"""<tr>
          <td>{_badge(f['severity'])}</td>
          <td>{f['host']}</td>
          <td>{f['plugin_name']}</td>
          <td>{score}</td>
          <td>{cves}</td>
          <td style="font-size:11px;color:#6b7280">{sol}</td>
        </tr>"""

    total_risk = s.get("critical", 0) * 10 + s.get("high", 0) * 5 + s.get("medium", 0)
    risk_label = "Critical" if total_risk > 50 else ("High" if total_risk > 20 else "Moderate")
    risk_color = "#da3633" if risk_label == "Critical" else ("#d29922" if risk_label == "High" else "#3b82f6")

    return f"""<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8"><title>Executive Vulnerability Report — {mfi} {period}</title>
<style>{_BASE_CSS}
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 14px; margin: 20px 0; }}
  .sev-card {{ text-align: center; padding: 16px 12px; border-radius: 8px; border: 1px solid #e5e7eb; }}
  .sev-card .num {{ font-size: 36px; font-weight: 800; line-height: 1; }}
  .sev-card .lbl {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-top: 6px; opacity: .8; }}
  .risk-banner {{ display: inline-flex; align-items: center; gap: 10px; padding: 10px 20px;
                  border-radius: 8px; margin: 16px 0; font-weight: 700; font-size: 14px; }}
</style></head>
<body>
<h1>Executive Vulnerability Report</h1>
<div class="meta">
  <strong>Organization:</strong> {mfi} &nbsp;|&nbsp;
  <strong>Period:</strong> {period} &nbsp;|&nbsp;
  <strong>Report Date:</strong> {date} &nbsp;|&nbsp;
  <strong>Hosts Scanned:</strong> {s.get("total_hosts", 0)} &nbsp;|&nbsp;
  <strong>Source File:</strong> {filename}
</div>

<h2>Overall Risk</h2>
<div class="risk-banner" style="background:{risk_color}22;color:{risk_color}">
  Overall Risk Level: {risk_label} &mdash; {s.get("total_findings", 0)} total findings across {s.get("total_hosts", 0)} hosts
</div>

<h2>Vulnerability Summary</h2>
<div class="summary-grid">
  <div class="sev-card" style="background:{SEV_BG['critical']};border-color:{SEV_COLORS['critical']}44">
    <div class="num" style="color:{SEV_COLORS['critical']}">{s.get("critical", 0)}</div>
    <div class="lbl" style="color:{SEV_COLORS['critical']}">Critical</div>
  </div>
  <div class="sev-card" style="background:{SEV_BG['high']};border-color:{SEV_COLORS['high']}44">
    <div class="num" style="color:{SEV_COLORS['high']}">{s.get("high", 0)}</div>
    <div class="lbl" style="color:{SEV_COLORS['high']}">High</div>
  </div>
  <div class="sev-card" style="background:{SEV_BG['medium']};border-color:{SEV_COLORS['medium']}44">
    <div class="num" style="color:{SEV_COLORS['medium']}">{s.get("medium", 0)}</div>
    <div class="lbl" style="color:{SEV_COLORS['medium']}">Medium</div>
  </div>
  <div class="sev-card" style="background:{SEV_BG['low']};border-color:{SEV_COLORS['low']}44">
    <div class="num" style="color:{SEV_COLORS['low']}">{s.get("low", 0)}</div>
    <div class="lbl" style="color:{SEV_COLORS['low']}">Low</div>
  </div>
  <div class="sev-card" style="background:{SEV_BG['info']};border-color:{SEV_COLORS['info']}44">
    <div class="num" style="color:{SEV_COLORS['info']}">{s.get("info", 0)}</div>
    <div class="lbl" style="color:{SEV_COLORS['info']}">Info</div>
  </div>
</div>

<h2>Top Critical &amp; High Findings</h2>
<table>
  <tr><th>Severity</th><th>Host</th><th>Vulnerability</th><th>CVSS</th><th>CVE</th><th>Recommended Fix</th></tr>
  {rows or '<tr><td colspan="6" style="text-align:center;color:#9ca3af;padding:20px">No critical or high findings</td></tr>'}
</table>

<h2>Remediation Priorities</h2>
<table>
  <tr><th>Category</th><th>Count</th><th>Target SLA</th></tr>
  <tr><td>{_badge("critical")} Critical</td><td>{s.get("critical", 0)}</td><td>Patch within 24–72 hours</td></tr>
  <tr><td>{_badge("high")} High</td><td>{s.get("high", 0)}</td><td>Patch within 7 days</td></tr>
  <tr><td>{_badge("medium")} Medium</td><td>{s.get("medium", 0)}</td><td>Patch within 30 days</td></tr>
  <tr><td>{_badge("low")} Low</td><td>{s.get("low", 0)}</td><td>Patch within 90 days</td></tr>
</table>

<div class="footer">
  Generated by ARMOR Security Dashboard &mdash; Confidential &mdash; {mfi} &mdash; {period}
</div>
</body></html>"""


def generate_technical_report(scan: dict) -> str:
    s        = scan["summary"]
    mfi      = scan["mfi"]
    period   = f"{scan['quarter']} {scan['year']}"
    date     = (scan.get("uploaded_at") or "")[:10]

    # Host table
    host_rows = ""
    for h in scan.get("hosts", []):
        total = sum(h.get(k, 0) for k in ["critical", "high", "medium", "low", "info"])
        host_rows += f"""<tr>
          <td><strong>{h['name']}</strong></td>
          <td style="color:#6b7280">{h.get('ip', '')}</td>
          <td style="font-size:11px">{h.get('os', '—')[:60]}</td>
          <td style="color:{SEV_COLORS['critical']};font-weight:700">{h.get('critical', 0) or '—'}</td>
          <td style="color:{SEV_COLORS['high']};font-weight:700">{h.get('high', 0) or '—'}</td>
          <td style="color:{SEV_COLORS['medium']}">{h.get('medium', 0) or '—'}</td>
          <td style="color:{SEV_COLORS['low']}">{h.get('low', 0) or '—'}</td>
          <td style="color:#6b7280">{total}</td>
        </tr>"""

    # Findings table (critical → low, skip info)
    findings = sorted(
        [f for f in scan.get("findings", []) if f["severity"] != "info"],
        key=lambda x: -x.get("severity_num", 0),
    )

    finding_rows = ""
    for f in findings:
        score  = f.get("cvss3_base") or f.get("cvss_base") or "—"
        cves   = ", ".join(f.get("cve", [])[:4]) or "—"
        sol    = (f.get("solution") or "—")[:250]
        port   = f"{f['port']}/{f['protocol']}" if f.get("port", "0") != "0" else "—"
        finding_rows += f"""<tr>
          <td style="white-space:nowrap">{_badge(f['severity'])}</td>
          <td style="color:#6b7280;white-space:nowrap">{f['plugin_id']}</td>
          <td>{f['plugin_name']}</td>
          <td style="white-space:nowrap"><strong>{f['host']}</strong></td>
          <td style="white-space:nowrap">{port}</td>
          <td style="white-space:nowrap">{score}</td>
          <td style="white-space:nowrap;font-size:11px">{cves}</td>
          <td style="font-size:11px;color:#4b5563">{sol}</td>
        </tr>"""

    return f"""<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8"><title>Technical Vulnerability Report — {mfi} {period}</title>
<style>{_BASE_CSS}
  .stat-row {{ display:flex; gap:20px; flex-wrap:wrap; margin:16px 0; }}
  .stat-box {{ padding:10px 16px; border-radius:6px; border:1px solid #e5e7eb; }}
  .stat-box .n {{ font-size:28px; font-weight:800; }}
  .stat-box .l {{ font-size:11px; text-transform:uppercase; opacity:.7; }}
</style></head>
<body>
<h1>Technical Vulnerability Assessment Report</h1>
<div class="meta">
  <strong>Organization:</strong> {mfi} &nbsp;|&nbsp;
  <strong>Period:</strong> {period} &nbsp;|&nbsp;
  <strong>Report Date:</strong> {date} &nbsp;|&nbsp;
  <strong>Hosts:</strong> {s.get("total_hosts", 0)} &nbsp;|&nbsp;
  <strong>Total Findings:</strong> {s.get("total_findings", 0)}
</div>

<div class="stat-row">
  <div class="stat-box" style="background:{SEV_BG['critical']}"><div class="n" style="color:{SEV_COLORS['critical']}">{s.get("critical",0)}</div><div class="l" style="color:{SEV_COLORS['critical']}">Critical</div></div>
  <div class="stat-box" style="background:{SEV_BG['high']}"><div class="n" style="color:{SEV_COLORS['high']}">{s.get("high",0)}</div><div class="l" style="color:{SEV_COLORS['high']}">High</div></div>
  <div class="stat-box" style="background:{SEV_BG['medium']}"><div class="n" style="color:{SEV_COLORS['medium']}">{s.get("medium",0)}</div><div class="l" style="color:{SEV_COLORS['medium']}">Medium</div></div>
  <div class="stat-box" style="background:{SEV_BG['low']}"><div class="n" style="color:{SEV_COLORS['low']}">{s.get("low",0)}</div><div class="l" style="color:{SEV_COLORS['low']}">Low</div></div>
  <div class="stat-box" style="background:{SEV_BG['info']}"><div class="n" style="color:{SEV_COLORS['info']}">{s.get("info",0)}</div><div class="l" style="color:{SEV_COLORS['info']}">Info</div></div>
</div>

<h2>Host Summary</h2>
<table>
  <tr><th>Hostname</th><th>IP Address</th><th>OS</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Total</th></tr>
  {host_rows or '<tr><td colspan="8" style="text-align:center;color:#9ca3af">No hosts</td></tr>'}
</table>

<h2>All Vulnerabilities (Critical → Low, Info excluded)</h2>
<table>
  <tr><th>Severity</th><th>Plugin ID</th><th>Vulnerability Name</th><th>Host</th><th>Port</th><th>CVSS</th><th>CVE(s)</th><th>Remediation</th></tr>
  {finding_rows or '<tr><td colspan="8" style="text-align:center;color:#9ca3af">No actionable findings</td></tr>'}
</table>

<div class="footer">
  Generated by ARMOR Security Dashboard &mdash; CONFIDENTIAL — For internal use only &mdash; {mfi} &mdash; {period}
</div>
</body></html>"""
