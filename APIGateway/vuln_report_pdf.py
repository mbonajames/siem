"""
Executive report generator — produces a PDF using reportlab.
Layout:
  1. Cover page  — MFI, quarter, year, date
  2. Executive summary — risk posture paragraph + severity table
  3. Key findings — top 10 critical/high with CVE and remediation
  4. Host exposure — per-host severity breakdown table
  5. Recommendations — top remediation actions derived from solutions
"""
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak,
)
from reportlab.platypus.flowables import KeepTogether

# ── Brand palette ─────────────────────────────────────────────────────────────
NAVY    = colors.HexColor("#1F3864")
RED     = colors.HexColor("#C00000")
ORANGE  = colors.HexColor("#E06C00")
YELLOW  = colors.HexColor("#E8A900")
BLUE    = colors.HexColor("#2E75B6")
GREY    = colors.HexColor("#666666")
LTGREY  = colors.HexColor("#F2F2F2")
WHITE   = colors.white
BLACK   = colors.black

SEV_COLOR = {
    "critical": RED,
    "high":     ORANGE,
    "medium":   YELLOW,
    "low":      BLUE,
    "info":     GREY,
}
SEV_BG = {
    "critical": colors.HexColor("#FFB3B3"),
    "high":     colors.HexColor("#FFD9B3"),
    "medium":   colors.HexColor("#FFF5B3"),
    "low":      colors.HexColor("#B3D9FF"),
    "info":     colors.HexColor("#E8E8E8"),
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Styles ────────────────────────────────────────────────────────────────────
_base = getSampleStyleSheet()

def _s(**kw):
    return ParagraphStyle(**kw)

S_TITLE   = _s(name="T",  fontName="Helvetica-Bold",   fontSize=28, textColor=NAVY,  spaceAfter=6)
S_SUBTITLE= _s(name="Su", fontName="Helvetica",         fontSize=14, textColor=GREY,  spaceAfter=4)
S_H1      = _s(name="H1", fontName="Helvetica-Bold",   fontSize=14, textColor=NAVY,  spaceBefore=14, spaceAfter=6)
S_H2      = _s(name="H2", fontName="Helvetica-Bold",   fontSize=11, textColor=NAVY,  spaceBefore=10, spaceAfter=4)
S_BODY    = _s(name="Bo", fontName="Helvetica",         fontSize=9,  leading=13,      spaceAfter=4)
S_CAPTION = _s(name="Ca", fontName="Helvetica-Oblique", fontSize=8, textColor=GREY,  spaceAfter=2)
S_CELL    = _s(name="Ce", fontName="Helvetica",         fontSize=8,  leading=11)
S_CELL_B  = _s(name="CeB",fontName="Helvetica-Bold",   fontSize=8)

W = A4[0] - 4*cm   # usable table width


# ── Helper ────────────────────────────────────────────────────────────────────

def _hr():
    return HRFlowable(width="100%", thickness=1, color=NAVY, spaceAfter=6)


def _sev_badge(sev: str) -> Paragraph:
    c = SEV_COLOR.get(sev, GREY)
    return Paragraph(
        f'<font color="{c.hexval()}"><b>{sev.upper()}</b></font>', S_CELL
    )


def _table_style(extra=None):
    base = [
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("BACKGROUND",  (0, 0), (-1, 0),  NAVY),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LTGREY]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
    ]
    if extra:
        base.extend(extra)
    return TableStyle(base)


def _merge_findings(scan_list: list) -> list:
    out = []
    for s in scan_list:
        for f in s.get("findings", []):
            out.append(f)
    return sorted(out, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))


def _sum_field(scans: list, field: str) -> int:
    return sum(s.get("summary", {}).get(field, 0) for s in scans)


def _risk_posture(critical: int, high: int, total: int) -> str:
    if critical > 0:
        return "CRITICAL"
    if high > 5:
        return "HIGH"
    if high > 0:
        return "MEDIUM"
    return "LOW"


# ── Page template ─────────────────────────────────────────────────────────────

def _make_doc(buf) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2.5*cm,
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="normal")

    def _header_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(GREY)
        canvas.drawString(2*cm, A4[1] - 1.5*cm, "CONFIDENTIAL — For Authorized Recipients Only")
        canvas.drawRightString(A4[0] - 2*cm, A4[1] - 1.5*cm,
                               f"Page {doc.page}")
        canvas.setStrokeColor(NAVY)
        canvas.setLineWidth(0.5)
        canvas.line(2*cm, A4[1] - 1.8*cm, A4[0] - 2*cm, A4[1] - 1.8*cm)
        canvas.line(2*cm, 2.2*cm, A4[0] - 2*cm, 2.2*cm)
        canvas.setFont("Helvetica", 7)
        canvas.drawCentredString(A4[0]/2, 1.5*cm,
                                 "This report is generated by Hope International SIEM Platform")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=frame,
                                       onPage=_header_footer)])
    return doc


# ── Section builders ──────────────────────────────────────────────────────────

def _cover(story, mfi, year, quarter, internal_scans, external_scans):
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("VULNERABILITY ASSESSMENT", S_TITLE))
    story.append(Paragraph("Executive Report", S_SUBTITLE))
    story.append(_hr())
    story.append(Spacer(1, 0.5*cm))

    meta = [
        ["Organisation / MFI", mfi],
        ["Assessment Period",  f"{quarter} {year}"],
        ["Report Date",        datetime.now().strftime("%B %d, %Y")],
        ["Scope",              "Internal & External Network"],
        ["Files Analysed",
         str(len(internal_scans) + len(external_scans))],
    ]
    t = Table(meta, colWidths=[5*cm, W - 5*cm])
    t.setStyle(_table_style())
    story.append(t)
    story.append(PageBreak())


def _executive_summary(story, mfi, year, quarter, internal_scans, external_scans):
    all_scans = internal_scans + external_scans
    c  = _sum_field(all_scans, "critical")
    h  = _sum_field(all_scans, "high")
    m  = _sum_field(all_scans, "medium")
    lo = _sum_field(all_scans, "low")
    inf= _sum_field(all_scans, "info")
    tf = _sum_field(all_scans, "total_findings")
    th = _sum_field(all_scans, "total_hosts")
    posture = _risk_posture(c, h, tf)

    story.append(Paragraph("1.  Executive Summary", S_H1))
    story.append(_hr())

    pc = f"{round(c/tf*100) if tf else 0}%"
    ph = f"{round(h/tf*100) if tf else 0}%"

    body = (
        f"A vulnerability assessment was conducted for <b>{mfi}</b> during <b>{quarter} {year}</b>. "
        f"A total of <b>{th} host(s)</b> were scanned across internal and external networks, "
        f"yielding <b>{tf} finding(s)</b>. "
        f"The overall risk posture is assessed as <b>{posture}</b>. "
        f"Critical vulnerabilities account for {pc} of total findings and High for {ph}. "
        f"Immediate remediation is recommended for all Critical and High severity items."
    )
    story.append(Paragraph(body, S_BODY))
    story.append(Spacer(1, 0.4*cm))

    # severity table — combined + per-type
    def _row(label, scans):
        c  = _sum_field(scans, "critical")
        h  = _sum_field(scans, "high")
        m  = _sum_field(scans, "medium")
        lo = _sum_field(scans, "low")
        inf= _sum_field(scans, "info")
        tf = _sum_field(scans, "total_findings")
        th = _sum_field(scans, "total_hosts")
        return [label, str(c), str(h), str(m), str(lo), str(inf), str(tf), str(th)]

    hdrs = ["Scope", "Critical", "High", "Medium", "Low", "Info", "Total", "Hosts"]
    data = [hdrs,
            _row("Internal", internal_scans),
            _row("External", external_scans),
            _row("Combined", all_scans)]

    cw = [3*cm] + [(W - 3*cm) / 7] * 7
    t  = Table(data, colWidths=cw)
    sev_extras = [
        ("BACKGROUND", (1, 1), (1, -1), colors.HexColor("#FFB3B3")),
        ("BACKGROUND", (2, 1), (2, -1), colors.HexColor("#FFD9B3")),
        ("BACKGROUND", (3, 1), (3, -1), colors.HexColor("#FFF5B3")),
        ("BACKGROUND", (4, 1), (4, -1), colors.HexColor("#B3D9FF")),
        ("FONTNAME",   (0, -1), (-1, -1), "Helvetica-Bold"),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#E8F0FE")),
    ]
    t.setStyle(_table_style(sev_extras))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))


def _key_findings(story, internal_scans, external_scans):
    all_findings = _merge_findings(internal_scans + [])
    all_findings += _merge_findings(external_scans)
    all_findings = sorted(all_findings, key=lambda f: _SEV_ORDER.get(f.get("severity","info"), 4))

    top = [f for f in all_findings if f.get("severity") in ("critical", "high")][:15]
    if not top:
        return

    story.append(Paragraph("2.  Key Findings", S_H1))
    story.append(_hr())
    story.append(Paragraph(
        f"The following {len(top)} Critical / High severity findings require immediate attention.",
        S_BODY))
    story.append(Spacer(1, 0.3*cm))

    hdrs = ["#", "Severity", "Vulnerability", "Host", "CVE", "CVSS v3", "Solution (excerpt)"]
    cw   = [0.6*cm, 1.8*cm, 5.5*cm, 3*cm, 2.8*cm, 1.5*cm, W - 15.2*cm]

    rows = [hdrs]
    for i, f in enumerate(top, 1):
        sev = f.get("severity", "")
        cves = ", ".join(f.get("cve") or []) or "—"
        sol  = (f.get("solution") or "")[:120]
        if len(f.get("solution") or "") > 120:
            sol += "…"
        rows.append([
            str(i),
            Paragraph(f'<font color="{SEV_COLOR.get(sev, GREY).hexval()}"><b>{sev.upper()}</b></font>', S_CELL),
            Paragraph(f.get("plugin_name", ""), S_CELL),
            Paragraph(f.get("host", ""), S_CELL),
            Paragraph(cves, S_CELL),
            str(f.get("cvss3_base") or f.get("cvss_base") or "—"),
            Paragraph(sol, S_CELL),
        ])

    sev_extras = []
    for r, f in enumerate(top, 1):
        bg = SEV_BG.get(f.get("severity", "info"), LTGREY)
        sev_extras.append(("BACKGROUND", (0, r), (-1, r), bg))

    t = Table(rows, colWidths=cw, repeatRows=1)
    t.setStyle(_table_style(sev_extras))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))


def _host_exposure(story, internal_scans, external_scans):
    # Build per-host aggregate
    host_map: dict = {}

    def _add(scans, stype):
        for scan in scans:
            for h in scan.get("hosts", []):
                key = h.get("ip") or h.get("name", "?")
                if key not in host_map:
                    host_map[key] = {
                        "host": key, "os": h.get("os", ""),
                        "type": stype,
                        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
                    }
                for s in ("critical", "high", "medium", "low", "info"):
                    host_map[key][s] += h.get(s, 0)

    _add(internal_scans, "Internal")
    _add(external_scans, "External")

    if not host_map:
        return

    hosts = sorted(host_map.values(),
                   key=lambda h: -(h["critical"]*10 + h["high"]*4 + h["medium"]))

    story.append(Paragraph("3.  Host Exposure Summary", S_H1))
    story.append(_hr())
    story.append(Spacer(1, 0.2*cm))

    hdrs = ["Host / IP", "Type", "OS", "Critical", "High", "Medium", "Low", "Info"]
    cw   = [3.5*cm, 1.8*cm, 4.5*cm] + [(W - 9.8*cm) / 5] * 5
    rows = [hdrs]
    for h in hosts:
        rows.append([
            h["host"], h["type"], h["os"] or "—",
            str(h["critical"]), str(h["high"]),
            str(h["medium"]),   str(h["low"]), str(h["info"]),
        ])

    sev_extras = [("BACKGROUND", (3, 1), (3, -1), colors.HexColor("#FFB3B3")),
                  ("BACKGROUND", (4, 1), (4, -1), colors.HexColor("#FFD9B3")),
                  ("BACKGROUND", (5, 1), (5, -1), colors.HexColor("#FFF5B3")),
                  ("BACKGROUND", (6, 1), (6, -1), colors.HexColor("#B3D9FF"))]
    t = Table(rows, colWidths=cw, repeatRows=1)
    t.setStyle(_table_style(sev_extras))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))


def _recommendations(story, internal_scans, external_scans):
    all_findings = _merge_findings(internal_scans) + _merge_findings(external_scans)
    crit_high = [f for f in all_findings if f.get("severity") in ("critical", "high")]

    # Deduplicate by plugin_name → keep unique solutions
    seen_plugins: set = set()
    recs = []
    for f in crit_high:
        pid = f.get("plugin_id", "")
        if pid and pid not in seen_plugins:
            seen_plugins.add(pid)
            sol = (f.get("solution") or "").strip()
            if sol and sol.lower() not in ("n/a", "none", ""):
                recs.append((f.get("severity"), f.get("plugin_name", ""), sol[:250]))
        if len(recs) >= 20:
            break

    if not recs:
        return

    story.append(Paragraph("4.  Remediation Recommendations", S_H1))
    story.append(_hr())
    story.append(Paragraph(
        "The following actions are recommended in priority order based on severity and prevalence.",
        S_BODY))
    story.append(Spacer(1, 0.3*cm))

    hdrs = ["Priority", "Severity", "Vulnerability", "Recommended Action"]
    cw   = [1.5*cm, 1.8*cm, 4.5*cm, W - 7.8*cm]
    rows = [hdrs]
    for i, (sev, name, sol) in enumerate(recs, 1):
        rows.append([
            str(i),
            Paragraph(f'<font color="{SEV_COLOR.get(sev, GREY).hexval()}"><b>{sev.upper()}</b></font>', S_CELL),
            Paragraph(name, S_CELL),
            Paragraph(sol, S_CELL),
        ])

    sev_extras = []
    for r, (sev, _, _s) in enumerate(recs, 1):
        bg = SEV_BG.get(sev, LTGREY)
        sev_extras.append(("BACKGROUND", (0, r), (-1, r), bg))

    t = Table(rows, colWidths=cw, repeatRows=1)
    t.setStyle(_table_style(sev_extras))
    story.append(t)


# ── Public API ────────────────────────────────────────────────────────────────

def generate_executive_pdf(mfi: str, year: int, quarter: str,
                            internal_scans: list, external_scans: list) -> bytes:
    buf = io.BytesIO()
    doc = _make_doc(buf)
    story = []

    _cover(story, mfi, year, quarter, internal_scans, external_scans)
    _executive_summary(story, mfi, year, quarter, internal_scans, external_scans)
    _key_findings(story, internal_scans, external_scans)
    _host_exposure(story, internal_scans, external_scans)
    _recommendations(story, internal_scans, external_scans)

    doc.build(story)
    return buf.getvalue()
