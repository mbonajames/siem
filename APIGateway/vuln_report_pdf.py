"""
Executive Vulnerability Assessment PDF Report
Matches the Hope International template exactly.
"""
import io
import os
import re
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate, Frame, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
import math
from reportlab.graphics.shapes import Drawing, Rect, String as GString, Line, Wedge, Circle, Group

# ── Colours (matched to template) ─────────────────────────────────────────────
C_BLUE   = colors.HexColor("#2E75B6")   # section headings
C_RED    = colors.HexColor("#C00000")   # Confidential / subheadings
C_DATE   = colors.HexColor("#C05A28")   # cover date
C_BLACK  = colors.black
C_WHITE  = colors.white
C_GREY   = colors.HexColor("#666666")
C_LGREY  = colors.HexColor("#F2F2F2")
C_NAVY   = colors.HexColor("#1F3864")

# Chart / severity colours (matching template charts)
SEV_COL = {
    "critical": colors.HexColor("#8B0000"),
    "high":     colors.HexColor("#FF0000"),
    "medium":   colors.HexColor("#E8A900"),
    "low":      colors.HexColor("#00BFFF"),
    "info":     colors.HexColor("#AAAAAA"),
}
SEV_CELL_BG = {
    "critical": colors.HexColor("#8B0000"),
    "high":     colors.HexColor("#FF0000"),
    "medium":   colors.HexColor("#E8A900"),
    "low":      colors.HexColor("#00BFFF"),
    "info":     colors.HexColor("#CCCCCC"),
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_LABEL = {"critical": "Critical", "high": "High",
              "medium": "Medium",  "low": "Low",  "info": "Info"}

# ── Page geometry ─────────────────────────────────────────────────────────────
PW, PH   = A4
ML = MR  = 2.5 * cm
MT = MB  = 2.5 * cm
CW       = PW - ML - MR

# ── Team (fixed per organisation) ─────────────────────────────────────────────
TEAM = [
    ("Erick Rozelle",    "Information systems and Security Manager"),
    ("Ashenafi Sebani",  "Senior Security Advisor"),
    ("James Mbonabucya", "Cybersecurity Analyst"),
]

# ── Paragraph styles ──────────────────────────────────────────────────────────
def _ps(**kw):
    return ParagraphStyle(**kw)

S_CONF  = _ps(name="Conf",  fontName="Helvetica",        fontSize=9,  textColor=C_RED,  alignment=2)
S_TITLE = _ps(name="Title", fontName="Helvetica-Bold",   fontSize=20, textColor=C_BLUE, spaceAfter=4, leading=24)
S_PREP  = _ps(name="Prep",  fontName="Helvetica-Oblique",fontSize=11, spaceAfter=4)
S_PREPB = _ps(name="PrepB", fontName="Helvetica-Bold",   fontSize=11)
S_MEMH  = _ps(name="MemH",  fontName="Helvetica",        fontSize=10, textColor=C_RED,  spaceBefore=14, spaceAfter=4)
S_MEM   = _ps(name="Mem",   fontName="Helvetica",        fontSize=10, leading=16)
S_DATE  = _ps(name="Date",  fontName="Helvetica",        fontSize=10, textColor=C_DATE, spaceBefore=30)
S_H1    = _ps(name="H1",    fontName="Helvetica-Bold",   fontSize=13, textColor=C_BLUE, spaceBefore=16, spaceAfter=6, borderPad=2)
S_H2    = _ps(name="H2",    fontName="Helvetica-Bold",   fontSize=11, textColor=C_RED,  spaceBefore=12, spaceAfter=4)
S_BODY  = _ps(name="Body",  fontName="Helvetica",        fontSize=10, leading=15, spaceAfter=6)
S_BUL   = _ps(name="Bul",   fontName="Helvetica",        fontSize=10, leading=15, leftIndent=20, bulletIndent=6, spaceAfter=3)
S_CELL  = _ps(name="Cell",  fontName="Helvetica",        fontSize=9,  leading=12)
S_CELLB = _ps(name="CellB", fontName="Helvetica-Bold",   fontSize=9,  leading=12)
S_CAP   = _ps(name="Cap",   fontName="Helvetica",        fontSize=10, spaceAfter=8, spaceBefore=4)
S_TOC   = _ps(name="Toc",   fontName="Helvetica",        fontSize=10, leading=18)
S_TOCH  = _ps(name="TocH",  fontName="Helvetica-Bold",   fontSize=11, textColor=C_BLUE, spaceAfter=4)
S_TOCS  = _ps(name="TocS",  fontName="Helvetica",        fontSize=10, leading=16, leftIndent=20)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hr(color=C_BLUE):
    return HRFlowable(width="100%", thickness=1, color=color, spaceAfter=4, spaceBefore=4)


def _sum(scans, field):
    return sum(s.get("summary", {}).get(field, 0) for s in scans)


def _dedup_findings(scans: list) -> list:
    """Deduplicate findings by plugin_id across all scans; merge affected hosts."""
    seen: dict = {}
    result: list = []
    for s in scans:
        branch = s.get("branch") or s.get("filename", "")
        for f in s.get("findings", []):
            key = f.get("plugin_id") or f.get("plugin_name", "unknown")
            if key not in seen:
                entry = {**f, "_branch": branch, "_hosts": set()}
                h = f.get("host", "")
                if h:
                    entry["_hosts"].add(h)
                seen[key] = len(result)
                result.append(entry)
            else:
                h = f.get("host", "")
                if h:
                    result[seen[key]]["_hosts"].add(h)
    for f in result:
        hosts = sorted(f.pop("_hosts", set()))
        f["host"] = ", ".join(hosts) if hosts else "—"
    return sorted(result, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))


def _dedup_sev_counts(scans: list) -> dict:
    """Count unique vulnerabilities by severity (not per-host occurrences)."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in _dedup_findings(scans):
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    return counts


def _merge_findings(scans):
    out = []
    for s in scans:
        for f in s.get("findings", []):
            out.append({**f, "_branch": s.get("branch") or s.get("filename", "")})
    return sorted(out, key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))


def _risk_label(c, h, tf):
    if c > 0:  return "CRITICAL"
    if h > 5:  return "HIGH"
    if h > 0:  return "MODERATE"
    return "LOW"


# ── Charts ────────────────────────────────────────────────────────────────────

def _nice_ticks(max_val: int, target_steps: int = 5):
    """Return a list of tick values from 0 to a round number >= max_val."""
    if max_val == 0:
        return [0, 1, 2]
    raw_step = max_val / target_steps
    magnitude = 10 ** math.floor(math.log10(raw_step)) if raw_step > 0 else 1
    step = max(1, round(raw_step / magnitude) * magnitude)
    top  = math.ceil(max_val / step) * step
    return list(range(0, top + step, step))


def _bar_chart(sev_counts: dict, width=CW, height=8*cm,
               title="Total vulnerabilities by Level") -> Drawing:
    """Fully manual bar chart — zero label overlap guaranteed."""
    levels = [k for k in ("critical","high","medium","low","info")
              if sev_counts.get(k, 0) > 0]
    if not levels:
        return Drawing(float(width), 20)

    W = float(width);  H = float(height)
    LM = 38;  RM = 12;  TM = 22;  BM = 36

    ax_x = LM;  ax_y = BM
    ax_w = W - LM - RM;  ax_h = H - TM - BM

    vals    = [sev_counts[k] for k in levels]
    max_val = max(vals)
    ticks   = _nice_ticks(max_val)
    top_val = ticks[-1]

    d = Drawing(W, H)

    # ── Title ────────────────────────────────────────────────────────────────
    d.add(GString(W/2, H - 10, title, textAnchor="middle",
                  fontName="Helvetica-Bold", fontSize=10, fillColor=C_BLACK))

    # ── Y-axis grid + tick labels ─────────────────────────────────────────────
    for tick in ticks:
        y = ax_y + (tick / top_val) * ax_h if top_val else ax_y
        d.add(Line(ax_x, y, ax_x + ax_w, y,
                   strokeColor=colors.HexColor("#DDDDDD"), strokeWidth=0.5))
        d.add(GString(ax_x - 4, y - 4, str(tick), textAnchor="end",
                      fontName="Helvetica", fontSize=8, fillColor=C_GREY))

    # ── Bars ──────────────────────────────────────────────────────────────────
    n       = len(levels)
    slot_w  = ax_w / n
    bar_w   = slot_w * 0.55

    for i, (level, val) in enumerate(zip(levels, vals)):
        bar_x = ax_x + i * slot_w + (slot_w - bar_w) / 2
        bar_h = (val / top_val) * ax_h if top_val else 0

        d.add(Rect(bar_x, ax_y, bar_w, bar_h,
                   fillColor=SEV_COL[level], strokeWidth=0))

        # value above bar — never inside bar
        label_y = ax_y + bar_h + 4
        d.add(GString(bar_x + bar_w / 2, label_y, str(val),
                      textAnchor="middle", fontName="Helvetica-Bold",
                      fontSize=9, fillColor=C_BLACK))

        # category name centred below bar slot
        d.add(GString(bar_x + bar_w / 2, ax_y - 20, _SEV_LABEL[level],
                      textAnchor="middle", fontName="Helvetica",
                      fontSize=9, fillColor=C_BLACK))

    # ── Axes ──────────────────────────────────────────────────────────────────
    d.add(Line(ax_x, ax_y, ax_x, ax_y + ax_h,
               strokeColor=C_BLACK, strokeWidth=0.8))
    d.add(Line(ax_x, ax_y, ax_x + ax_w, ax_y,
               strokeColor=C_BLACK, strokeWidth=0.8))

    d.add(GString(W / 2, 6, "Risk Level", textAnchor="middle",
                  fontName="Helvetica", fontSize=9, fillColor=C_GREY))
    d.add(GString(9, ax_y + ax_h / 2, "Count", textAnchor="middle",
                  fontName="Helvetica", fontSize=9, fillColor=C_GREY,
                  transform=(1, 0, 0, 1, 0, 0)))

    return d


def _pie_chart(sev_counts: dict, width=CW, height=8*cm) -> Drawing:
    """Fully manual pie chart — legend on right, no overlapping slice labels."""
    levels = [k for k in ("critical","high","medium","low","info")
              if sev_counts.get(k, 0) > 0]
    if not levels:
        return Drawing(float(width), 20)

    vals  = [sev_counts[k] for k in levels]
    total = sum(vals)
    if total == 0:
        return Drawing(float(width), 20)

    W = float(width);  H = float(height)
    d = Drawing(W, H)

    # ── Title ─────────────────────────────────────────────────────────────────
    d.add(GString(W / 2, H - 12, "Vulnerabilities Distribution (%)",
                  textAnchor="middle", fontName="Helvetica-Bold",
                  fontSize=10, fillColor=C_BLACK))

    # Pie occupies left 60% of the drawing
    pie_cx = W * 0.30
    pie_cy = (H - 20) / 2 + 10
    pie_r  = min(W * 0.25, (H - 30) / 2)

    # ── Slices ────────────────────────────────────────────────────────────────
    start_deg = 90.0      # start at top, go clockwise
    for level, val in zip(levels, vals):
        sweep     = 360.0 * val / total
        end_deg   = start_deg - sweep

        # Wedge takes: cx, cy, r, startangledegrees, endangledegrees
        d.add(Wedge(pie_cx, pie_cy, pie_r, end_deg, start_deg,
                    fillColor=SEV_COL[level],
                    strokeColor=C_WHITE, strokeWidth=1.2))

        # Percentage label inside slice (only if slice big enough to fit text)
        if sweep >= 18:
            mid_rad = math.radians((start_deg + end_deg) / 2)
            lx = pie_cx + pie_r * 0.60 * math.cos(mid_rad)
            ly = pie_cy + pie_r * 0.60 * math.sin(mid_rad) - 4
            pct_txt = f"{round(val / total * 100, 1)}%"
            d.add(GString(lx, ly, pct_txt, textAnchor="middle",
                          fontName="Helvetica-Bold", fontSize=8,
                          fillColor=C_WHITE))

        start_deg = end_deg

    # ── Legend (right 40%) ────────────────────────────────────────────────────
    leg_x   = W * 0.62
    row_h   = 18
    n_items = len(levels)
    leg_top = pie_cy + (n_items * row_h) / 2

    for i, (level, val) in enumerate(zip(levels, vals)):
        y     = leg_top - i * row_h
        pct   = round(val / total * 100, 1)
        label = f"{_SEV_LABEL[level]}  {pct}%"

        # Colour swatch
        d.add(Rect(leg_x, y, 12, 11,
                   fillColor=SEV_COL[level], strokeWidth=0))
        # Text — never overlaps swatch
        d.add(GString(leg_x + 17, y + 2, label,
                      fontName="Helvetica", fontSize=9, fillColor=C_BLACK))

    return d


def _fmt_branch(scan: dict) -> str:
    """Return a clean display name for a scan: prefer branch field, fall back to filename.
    Strips the upload-noise suffix (_xxxxxx.ext) added by the storage layer."""
    name = scan.get("branch") or scan.get("filename") or "scan"
    # Remove trailing _<6-char-hash>.{csv,nessus} added on upload
    name = re.sub(r'_[A-Za-z0-9]{4,}\.(csv|nessus)$', '', name, flags=re.IGNORECASE)
    # Remove any remaining bare extension
    name = re.sub(r'\.(csv|nessus)$', '', name, flags=re.IGNORECASE)
    return name.strip() or "scan"


def _branch_bar_chart(scans: list, width=CW, height=9*cm) -> Drawing:
    """Grouped bar chart by branch — one cluster per severity level."""
    branches = []
    seen: set = set()
    for s in scans:
        b = _fmt_branch(s)
        if b not in seen:
            branches.append(b);  seen.add(b)
    if not branches:
        return Drawing(float(width), 20)

    sev_levels = [k for k in ("critical","high","medium","low")
                  if any(
                      sum(1 for f in s.get("findings", []) if f.get("severity") == k) > 0
                      for s in scans)]
    if not sev_levels:
        return Drawing(float(width), 20)

    # counts[branch_label][sev]
    counts = {}
    for s in scans:
        b = _fmt_branch(s)
        counts.setdefault(b, {k: 0 for k in sev_levels})
        for f in s.get("findings", []):
            sev = f.get("severity", "")
            if sev in counts[b]:
                counts[b][sev] += 1

    W = float(width);  H = float(height)
    LM = 38;  RM = 90;  TM = 22;  BM = 85   # BM enlarged for 45° branch labels

    ax_x = LM;  ax_y = BM
    ax_w = W - LM - RM;  ax_h = H - TM - BM

    all_vals = [v for b in branches for sev in sev_levels for v in [counts[b][sev]]]
    max_val  = max(all_vals) if all_vals else 1
    ticks    = _nice_ticks(max_val)
    top_val  = ticks[-1]

    d = Drawing(W, H)

    # ── Title ─────────────────────────────────────────────────────────────────
    d.add(GString(ax_x + ax_w / 2, H - 10, "Internal findings by branches",
                  textAnchor="middle", fontName="Helvetica-Bold",
                  fontSize=10, fillColor=C_BLACK))

    # ── Y grid + labels ───────────────────────────────────────────────────────
    for tick in ticks:
        y = ax_y + (tick / top_val) * ax_h if top_val else ax_y
        d.add(Line(ax_x, y, ax_x + ax_w, y,
                   strokeColor=colors.HexColor("#DDDDDD"), strokeWidth=0.5))
        d.add(GString(ax_x - 4, y - 4, str(tick), textAnchor="end",
                      fontName="Helvetica", fontSize=8, fillColor=C_GREY))

    # ── Clustered bars ────────────────────────────────────────────────────────
    n_branches  = len(branches)
    n_sev       = len(sev_levels)
    cluster_w   = ax_w / n_branches
    bar_w       = cluster_w * 0.8 / n_sev
    cluster_gap = cluster_w * 0.1

    for bi, branch in enumerate(branches):
        cluster_x = ax_x + bi * cluster_w + cluster_gap
        for si, sev in enumerate(sev_levels):
            val   = counts[branch][sev]
            bar_x = cluster_x + si * bar_w
            bar_h = (val / top_val) * ax_h if top_val and val else 0

            if bar_h > 0:
                d.add(Rect(bar_x, ax_y, bar_w - 1, bar_h,
                           fillColor=SEV_COL[sev], strokeWidth=0))
                if val > 0 and bar_h > 10:
                    d.add(GString(bar_x + (bar_w - 1) / 2, ax_y + bar_h + 3,
                                  str(val), textAnchor="middle",
                                  fontName="Helvetica-Bold", fontSize=7,
                                  fillColor=C_BLACK))

        # Branch label at -45° — left end at cluster centre, text goes down-right (below axis)
        label = branch[:22] + ("…" if len(branch) > 22 else "")
        _a45 = -math.pi / 4
        _cos, _sin = math.cos(_a45), math.sin(_a45)
        lbl_g = Group(transform=(_cos, _sin, -_sin, _cos,
                                 cluster_x + (n_sev * bar_w) / 2, ax_y - 6))
        lbl_g.add(GString(0, 0, label, textAnchor="start",
                          fontName="Helvetica", fontSize=8, fillColor=C_BLACK))
        d.add(lbl_g)

    # ── Axes ──────────────────────────────────────────────────────────────────
    d.add(Line(ax_x, ax_y, ax_x, ax_y + ax_h,
               strokeColor=C_BLACK, strokeWidth=0.8))
    d.add(Line(ax_x, ax_y, ax_x + ax_w, ax_y,
               strokeColor=C_BLACK, strokeWidth=0.8))

    # ── Legend (right margin) ──────────────────────────────────────────────────
    leg_x   = W - RM + 8
    leg_top = ax_y + ax_h
    for i, sev in enumerate(sev_levels):
        y = leg_top - i * 16
        d.add(Rect(leg_x, y, 10, 9, fillColor=SEV_COL[sev], strokeWidth=0))
        d.add(GString(leg_x + 14, y + 1, _SEV_LABEL[sev],
                      fontName="Helvetica", fontSize=8, fillColor=C_BLACK))

    return d


# ── Page template (header/footer) ─────────────────────────────────────────────

def _make_doc(buf) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        buf, pagesize=A4,
        leftMargin=ML, rightMargin=MR,
        topMargin=MT, bottomMargin=MB,
    )
    frame = Frame(ML, MB, CW, PH - MT - MB, id="normal")

    def _on_page(canvas, doc):
        canvas.saveState()
        # "Confidential" top right — red
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(C_RED)
        canvas.drawRightString(PW - MR, PH - 1.5*cm, "Confidential")
        canvas.restoreState()

    doc.addPageTemplates([PageTemplate(id="main", frames=frame, onPage=_on_page)])
    return doc


# ── Section builders ──────────────────────────────────────────────────────────

def _cover(story, mfi, year, quarter):
    story.append(Spacer(1, 3*cm))

    # Hope International logo — search in several locations so both dev and prod work
    _base = os.path.dirname(__file__)
    _candidates = [
        os.path.join(_base, "assets", "images", "HOPE_H_black_screen_R.png"),
        os.path.join(_base, "assets", "hope_logo.png"),
        os.path.join(_base, "..", "siem-dashboard", "src", "assets", "images", "HOPE_H_black_screen_R.png"),
    ]
    logo_path = next((p for p in _candidates if os.path.exists(p)), None)

    if logo_path:
        from reportlab.platypus import Image as RLImage
        # Logo is 1057×404 px (≈2.62:1). Fix width at 7 cm, height proportional.
        story.append(RLImage(logo_path, width=7*cm, height=2.67*cm, hAlign="CENTER"))
    else:
        # Stylised text fallback
        t = Table(
            [[Paragraph('<font color="#E8A900" size="22">&#9737;</font>'
                        '<font color="#1F3864" size="18"> <b>HOPE</b></font>'
                        '<br/><font color="#1F3864" size="8">INTERNATIONAL</font>', S_BODY)]],
            colWidths=[CW],
        )
        t.setStyle(TableStyle([("ALIGN", (0,0), (-1,-1), "CENTER"),
                                ("VALIGN",(0,0), (-1,-1), "MIDDLE")]))
        story.append(t)

    story.append(Spacer(1, 2.5*cm))

    # Title + underline rule
    story.append(Paragraph(
        f"{mfi} Vulnerability Assessment Report {quarter}", S_TITLE
    ))
    story.append(_hr(C_BLUE))
    story.append(Spacer(1, 1.5*cm))

    # Prepared by
    story.append(Paragraph(
        '<i>Prepared by:</i>  <b>Hope International Security Team</b>', S_BODY
    ))
    story.append(Spacer(1, 0.5*cm))

    # Members
    story.append(Paragraph("Members", S_MEMH))
    for name, role in TEAM:
        story.append(Paragraph(f"{name}&nbsp;&nbsp;&nbsp;&nbsp;{role}", S_MEM))

    # Date
    story.append(Paragraph(
        datetime.now().strftime("%A, %B %d, %Y"), S_DATE
    ))
    story.append(PageBreak())


def _toc(story):
    story.append(Paragraph("Contents", S_TOCH))
    story.append(_hr())
    toc_items = [
        ("1. Introduction", False),
        ("2. Executive Summary", False),
        ("3. Scope", False),
        ("4. Security Assessment Overview", False),
        ("4.1 External Assessment", True),
        ("4.2 Internal Assessment", True),
        ("5. Summary of Findings", False),
        ("6. Overall Assessment & Recommendations", False),
        ("7. Remediation Plan & SLA", False),
        ("8. Appendix", False),
    ]
    for label, sub in toc_items:
        s = S_TOCS if sub else S_TOC
        story.append(Paragraph(label, s))
    story.append(PageBreak())


def _intro(story, mfi, year, quarter):
    story.append(Paragraph("1. Introduction", S_H1))
    story.append(_hr())
    story.append(Paragraph(
        f"This report presents the findings of the {quarter} {year} vulnerability assessment conducted on "
        f"{mfi}'s applications and infrastructure. The objective is to provide IT Management "
        f"with a clear overview of the current security posture of their network and actionable recommendations.",
        S_BODY,
    ))
    story.append(Paragraph("The assessment aimed at:", S_BODY))
    bullets = [
        "Identify new security vulnerabilities across {mfi}'s applications and infrastructure.".format(mfi=mfi),
        "Assess the effectiveness of existing security controls put in place",
        "Highlight strengths and areas for improvement",
        "Provide actionable recommendations",
    ]
    for b in bullets:
        story.append(Paragraph(f"❖  {b}", S_BUL))


def _exec_summary(story, mfi, year, quarter, internal_scans, external_scans):
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("2. Executive Summary", S_H1))
    story.append(_hr())

    # Determine date range from uploaded_at if available
    all_scans = internal_scans + external_scans
    story.append(Paragraph(
        f"The Hope International Security Team conducted a comprehensive vulnerability assessment "
        f"of {mfi} applications and infrastructure during <b>{quarter} {year}</b>. "
        f"The goal was to evaluate the security posture and to identify any new or persisting vulnerabilities.",
        S_BODY,
    ))


def _scope(story, mfi):
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("3. Scope", S_H1))
    story.append(_hr())
    story.append(Paragraph(
        f"The assessment covered both the internal and external network environments of {mfi}. "
        f"The scope included:",
        S_BODY,
    ))
    for b in [
        "Vulnerability assessment using automated scanning tools",
        "Internal and external vulnerability scans using Nessus",
        "Reporting and analysis of identified vulnerabilities",
    ]:
        story.append(Paragraph(f"❖  {b}", S_BUL))


def _overview(story, mfi, internal_scans, external_scans):
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph("4. Security Assessment Overview", S_H1))
    story.append(_hr())

    # ── 4.1 External ──────────────────────────────────────────────────────────
    story.append(Paragraph("4.1 External Assessment", S_H2))

    if external_scans:
        ext_sev = _dedup_sev_counts(external_scans)
        ext_total = sum(v for k, v in ext_sev.items() if k != "total_findings")

        if ext_total > 0:
            story.append(Spacer(1, 0.3*cm))
            story.append(_bar_chart(ext_sev, title="Total vulnerabilities by Level"))
            story.append(Paragraph(
                f"The above chart depicts the findings of the scans for {mfi}'s internet facing "
                f"applications and server machines.", S_CAP
            ))
            story.append(Spacer(1, 0.3*cm))
            story.append(_pie_chart(ext_sev))
            story.append(Paragraph(
                "The above chart shows the distribution of total vulnerabilities by level.", S_CAP
            ))
        else:
            story.append(Paragraph("No external vulnerabilities were identified.", S_BODY))
    else:
        story.append(Paragraph("No external scan data is available for this period.", S_BODY))

    story.append(Spacer(1, 0.5*cm))

    # ── 4.2 Internal ──────────────────────────────────────────────────────────
    story.append(Paragraph("4.2 Internal Assessment", S_H2))

    if internal_scans:
        int_sev = _dedup_sev_counts(internal_scans)
        int_total = sum(v for k, v in int_sev.items() if k != "total_findings")

        if int_total > 0:
            story.append(Spacer(1, 0.3*cm))
            story.append(_bar_chart(int_sev, title="Total vulnerabilities by Level"))
            story.append(Spacer(1, 0.3*cm))
            story.append(_pie_chart(int_sev))
            story.append(Paragraph(
                "The above chart shows the distribution of total vulnerabilities by the level of "
                "Risk of exposure of {mfi}'s applications or infrastructure.".format(mfi=mfi), S_CAP
            ))

            # Branch breakdown chart (only if multiple scans / branches)
            if len(internal_scans) > 1 or any(s.get("branch") for s in internal_scans):
                story.append(Spacer(1, 0.3*cm))
                story.append(_branch_bar_chart(internal_scans))
                story.append(Paragraph(
                    "The above chart shows the distribution of vulnerabilities by the applications "
                    "and server machines.", S_CAP
                ))
        else:
            story.append(Paragraph("No internal vulnerabilities were identified.", S_BODY))
    else:
        story.append(Paragraph("No internal scan data is available for this period.", S_BODY))


def _findings_table(story, internal_scans, external_scans):
    story.append(PageBreak())
    story.append(Paragraph("5. Summary of Findings", S_H1))
    story.append(_hr())
    story.append(Paragraph(
        "The table below summarizes the critical & high-severity vulnerabilities identified during the assessment.",
        S_BODY,
    ))

    def _vuln_table(label, scans):
        # Deduplicated findings; host field already merges all affected hosts
        deduped = _dedup_findings(scans)
        crit_high = [f for f in deduped if f.get("severity") in ("critical", "high")]

        rows_data = [{"f": f, "hosts": f.get("host", "—").split(", ")} for f in crit_high]
        if not rows_data:
            return

        # ── Table header ── label spanning all cols
        col_w = [CW * 0.62, CW * 0.24, CW * 0.14]

        header_span = Table(
            [[Paragraph(label, _ps(name=f"Hdr_{label}", fontName="Helvetica-Bold",
                                   fontSize=10, textColor=C_WHITE))]],
            colWidths=[CW],
        )
        header_span.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), C_BLACK),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
            ("TOPPADDING",   (0,0), (-1,-1), 4),
            ("BOTTOMPADDING",(0,0), (-1,-1), 4),
        ]))
        story.append(header_span)

        col_hdr = Table(
            [[Paragraph("Vulnerability Name", S_CELLB),
              Paragraph("Affected Host", S_CELLB),
              Paragraph("Risk", S_CELLB)]],
            colWidths=col_w,
        )
        col_hdr.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), C_BLACK),
            ("TEXTCOLOR",    (0,0), (-1,-1), C_WHITE),
            ("LEFTPADDING",  (0,0), (-1,-1), 5),
            ("TOPPADDING",   (0,0), (-1,-1), 3),
            ("BOTTOMPADDING",(0,0), (-1,-1), 3),
            ("GRID",         (0,0), (-1,-1), 0.5, C_GREY),
        ]))
        story.append(col_hdr)

        for item in rows_data:
            f   = item["f"]
            sev = f.get("severity", "info")
            hosts_str = ", ".join(item["hosts"])
            name      = f.get("plugin_name", "—")
            desc      = (f.get("description") or "")[:200]
            cve_str   = ""
            cves = f.get("cve") or []
            if cves:
                cve_str = "\nReference:\n" + ", ".join(cves[:3])

            cell_text = f"<b>{name}</b>\n{desc}{cve_str}"

            risk_bg   = SEV_CELL_BG.get(sev, C_GREY)
            risk_text = _SEV_LABEL.get(sev, sev.title())

            row = Table(
                [[Paragraph(cell_text, S_CELL),
                  Paragraph(hosts_str, S_CELL),
                  Paragraph(f'<font color="white"><b>{risk_text}</b></font>',
                            _ps(name=f"Rsk_{sev}", fontName="Helvetica-Bold",
                                fontSize=9, textColor=C_WHITE))]],
                colWidths=col_w,
            )
            row.setStyle(TableStyle([
                ("BACKGROUND",   (2, 0), (2, 0), risk_bg),
                ("GRID",         (0, 0), (-1,-1), 0.5, C_GREY),
                ("VALIGN",       (0, 0), (-1,-1), "TOP"),
                ("LEFTPADDING",  (0, 0), (-1,-1), 5),
                ("TOPPADDING",   (0, 0), (-1,-1), 4),
                ("BOTTOMPADDING",(0, 0), (-1,-1), 4),
            ]))
            story.append(row)

        story.append(Paragraph(
            f"Table — {label.title()} Findings",
            _ps(name=f"TblCap_{label}", fontName="Helvetica-Oblique", fontSize=8,
                textColor=C_BLUE, spaceAfter=12, spaceBefore=2)
        ))

    _vuln_table("EXTERNAL", external_scans)
    story.append(Spacer(1, 0.4*cm))
    _vuln_table("INTERNAL", internal_scans)
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "Note: Medium-level vulnerabilities are not listed in the tables above.", S_BODY
    ))


def _recommendations(story, internal_scans, external_scans):
    story.append(PageBreak())
    story.append(Paragraph("6. Overall Assessment & Recommendations", S_H1))
    story.append(_hr())

    all_scans = internal_scans + external_scans
    all_dedup = _dedup_findings(all_scans)
    c  = sum(1 for f in all_dedup if f.get("severity") == "critical")
    h  = sum(1 for f in all_dedup if f.get("severity") == "high")
    tf = len(all_dedup)
    posture = _risk_label(c, h, tf)

    story.append(Paragraph(
        f"The assessment identified <b>{'critical and h' if c else 'h'}igh-severity vulnerabilities</b> "
        f"that should be addressed promptly following the vendor's best practices. "
        f"Several medium-level vulnerabilities were also detected and should be resolved as part of "
        f"the ongoing security improvement plan.",
        S_BODY,
    ))

    # Derive recommendations from critical/high findings (already deduplicated)
    crit_high = [f for f in _dedup_findings(all_scans) if f.get("severity") in ("critical", "high")]
    recs = []
    for f in crit_high:
        sol = (f.get("solution") or "").strip()
        if sol and sol.lower() not in ("n/a", "none"):
            recs.append(sol[:200])

    story.append(Paragraph("Recommendations:", S_CELLB))
    story.append(Spacer(1, 0.2*cm))
    for rec in recs[:8]:
        story.append(Paragraph(f"❖  {rec}", S_BUL))
    # Always include standard recommendations
    for standard in [
        "Address medium-level vulnerabilities in a timely manner",
        "Maintain regular vulnerability assessments and patch management",
    ]:
        if not any(standard.lower()[:30] in r.lower() for r in recs):
            story.append(Paragraph(f"❖  {standard}", S_BUL))


_SLA = [
    ("critical", "Critical", "15 days",  "Immediate — patch or apply compensating control within 15 days"),
    ("high",     "High",     "30 days",  "Urgent — schedule patching within 30 days"),
    ("medium",   "Medium",   "90 days",  "Planned — include in next maintenance cycle (90 days)"),
    ("low",      "Low",      "180 days", "Scheduled — address within 6 months or accept risk"),
    ("info",     "Info",     "Best effort", "Review finding; document risk acceptance if not actioned"),
]


def _remediation_sla(story, internal_scans, external_scans):
    story.append(PageBreak())
    story.append(Paragraph("7. Remediation Plan & SLA", S_H1))
    story.append(_hr())
    story.append(Paragraph(
        "The following Service Level Agreements (SLAs) define the maximum time allowed to remediate "
        "identified vulnerabilities based on their severity. All timelines are measured from the date "
        "of this report.",
        S_BODY,
    ))
    story.append(Spacer(1, 0.3*cm))

    # ── SLA reference table ───────────────────────────────────────────────────
    col_w = [CW * 0.12, CW * 0.13, CW * 0.55, CW * 0.20]
    hdr_style = TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING",    (0, 0), (-1, 0), 6),
        ("LEFTPADDING",   (0, 0), (-1,-1), 7),
        ("RIGHTPADDING",  (0, 0), (-1,-1), 7),
        ("GRID",          (0, 0), (-1,-1), 0.4, colors.HexColor("#CCCCCC")),
        ("VALIGN",        (0, 0), (-1,-1), "MIDDLE"),
        ("FONTNAME",      (0, 1), (-1,-1), "Helvetica"),
        ("FONTSIZE",      (0, 1), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_WHITE, C_LGREY]),
    ])

    rows = [[
        Paragraph("<b>Severity</b>", S_CELLB),
        Paragraph("<b>SLA</b>", S_CELLB),
        Paragraph("<b>Required Action</b>", S_CELLB),
        Paragraph("<b>Priority</b>", S_CELLB),
    ]]
    priority_label = {"critical": "P1 — Critical", "high": "P2 — High",
                      "medium": "P3 — Medium", "low": "P4 — Low", "info": "P5 — Info"}
    for sev, label, sla, action in _SLA:
        bg  = SEV_CELL_BG[sev]
        fg  = C_WHITE
        sev_para = Paragraph(
            f'<font color="white"><b>{label}</b></font>',
            _ps(name=f"SLA_{sev}", fontName="Helvetica-Bold", fontSize=9, textColor=fg),
        )
        rows.append([
            sev_para,
            Paragraph(sla, S_CELL),
            Paragraph(action, S_CELL),
            Paragraph(priority_label[sev], S_CELL),
        ])

    tbl = Table(rows, colWidths=col_w, repeatRows=1)
    # Apply severity background to the Severity cell only (column 0, rows 1–5)
    cell_cmds = []
    for row_i, (sev, *_) in enumerate(_SLA, start=1):
        cell_cmds.append(("BACKGROUND", (0, row_i), (0, row_i), SEV_CELL_BG[sev]))
    tbl.setStyle(TableStyle(hdr_style._cmds + cell_cmds))
    story.append(tbl)
    story.append(Spacer(1, 0.5*cm))

    # ── Per-finding remediation table (critical & high only) ─────────────────
    all_deduped = _dedup_findings(internal_scans + external_scans)
    crit_high   = [f for f in all_deduped if f.get("severity") in ("critical", "high")]

    if crit_high:
        story.append(Paragraph("Critical & High Findings — Remediation Targets", S_H2))
        story.append(Paragraph(
            "The table below lists all unique Critical and High vulnerabilities with their "
            "required remediation deadline based on the SLA above.",
            S_BODY,
        ))
        story.append(Spacer(1, 0.2*cm))

        sla_days = {"critical": 15, "high": 30}
        col_w2 = [CW * 0.36, CW * 0.12, CW * 0.24, CW * 0.14, CW * 0.14]
        rows2 = [[
            Paragraph("<b>Vulnerability</b>", S_CELLB),
            Paragraph("<b>Severity</b>", S_CELLB),
            Paragraph("<b>Affected Host(s)</b>", S_CELLB),
            Paragraph("<b>SLA</b>", S_CELLB),
            Paragraph("<b>Deadline</b>", S_CELLB),
        ]]
        today = datetime.now()
        for f in crit_high:
            sev  = f.get("severity", "high")
            days = sla_days.get(sev, 30)
            from datetime import timedelta
            deadline = (today + timedelta(days=days)).strftime("%d %b %Y")
            rows2.append([
                Paragraph(f.get("plugin_name", "—")[:60], S_CELL),
                Paragraph(
                    f'<font color="white"><b>{sev.upper()}</b></font>',
                    _ps(name=f"D_{f.get('plugin_id','x')}",
                        fontName="Helvetica-Bold", fontSize=8, textColor=C_WHITE),
                ),
                Paragraph((f.get("host") or "—")[:50], S_CELL),
                Paragraph(f"{days} days", S_CELL),
                Paragraph(deadline, S_CELL),
            ])

        tbl2 = Table(rows2, colWidths=col_w2, repeatRows=1)
        sev_cmds2 = [
            ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0), 9),
            ("GRID",          (0, 0), (-1,-1), 0.4, colors.HexColor("#CCCCCC")),
            ("LEFTPADDING",   (0, 0), (-1,-1), 6),
            ("RIGHTPADDING",  (0, 0), (-1,-1), 6),
            ("TOPPADDING",    (0, 0), (-1,-1), 4),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
            ("VALIGN",        (0, 0), (-1,-1), "TOP"),
            ("FONTNAME",      (0, 1), (-1,-1), "Helvetica"),
            ("FONTSIZE",      (0, 1), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_WHITE, C_LGREY]),
        ]
        for row_i, f in enumerate(crit_high, start=1):
            sev = f.get("severity", "high")
            sev_cmds2.append(("BACKGROUND", (1, row_i), (1, row_i), SEV_CELL_BG[sev]))
        tbl2.setStyle(TableStyle(sev_cmds2))
        story.append(tbl2)


def _appendix(story):
    story.append(PageBreak())
    story.append(Paragraph("8. Appendix", S_H1))
    story.append(_hr())
    story.append(Paragraph("❖  External Findings", S_BUL))
    story.append(Paragraph("❖  Internal Findings", S_BUL))


# ── Public API ────────────────────────────────────────────────────────────────

def generate_executive_pdf(
    mfi: str, year: int, quarter: str,
    internal_scans: list, external_scans: list,
) -> bytes:
    buf = io.BytesIO()
    doc = _make_doc(buf)
    story: list = []

    _cover(story, mfi, year, quarter)
    _toc(story)
    _intro(story, mfi, year, quarter)
    _exec_summary(story, mfi, year, quarter, internal_scans, external_scans)
    _scope(story, mfi)
    _overview(story, mfi, internal_scans, external_scans)
    _findings_table(story, internal_scans, external_scans)
    _recommendations(story, internal_scans, external_scans)
    _remediation_sla(story, internal_scans, external_scans)
    _appendix(story)

    doc.build(story)
    return buf.getvalue()
