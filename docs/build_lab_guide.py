"""Generates ContainIQ_Lab_Guide.pdf using ReportLab."""
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus.flowables import Flowable

# ── Brand colors ──────────────────────────────────────────────────────────────
NAVY      = colors.HexColor("#0d1b2a")
BLUE      = colors.HexColor("#1565c0")
BLUE_LT   = colors.HexColor("#1976d2")
ACCENT    = colors.HexColor("#42a5f5")
TEAL      = colors.HexColor("#00acc1")
WHITE     = colors.white
GRAY_DARK = colors.HexColor("#37474f")
GRAY_MID  = colors.HexColor("#607d8b")
GRAY_LT   = colors.HexColor("#eceff1")
RED       = colors.HexColor("#e53935")
GREEN     = colors.HexColor("#43a047")
ORANGE    = colors.HexColor("#fb8c00")
CODE_BG   = colors.HexColor("#1e2a38")
CODE_FG   = colors.HexColor("#a8d8f0")

W, H = letter

# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    base = getSampleStyleSheet()
    s = {}

    s["cover_title"] = ParagraphStyle("cover_title",
        fontName="Helvetica-Bold", fontSize=38, textColor=WHITE,
        leading=46, spaceAfter=8, alignment=TA_LEFT)

    s["cover_sub"] = ParagraphStyle("cover_sub",
        fontName="Helvetica", fontSize=15, textColor=ACCENT,
        leading=22, spaceAfter=6, alignment=TA_LEFT)

    s["cover_tag"] = ParagraphStyle("cover_tag",
        fontName="Helvetica", fontSize=12, textColor=colors.HexColor("#b0bec5"),
        leading=18, alignment=TA_LEFT)

    s["cover_ver"] = ParagraphStyle("cover_ver",
        fontName="Helvetica", fontSize=10, textColor=GRAY_MID,
        alignment=TA_LEFT)

    s["toc_title"] = ParagraphStyle("toc_title",
        fontName="Helvetica-Bold", fontSize=22, textColor=NAVY,
        spaceAfter=16, alignment=TA_LEFT)

    s["toc_h1"] = ParagraphStyle("toc_h1",
        fontName="Helvetica-Bold", fontSize=12, textColor=BLUE,
        spaceBefore=6, spaceAfter=2, leftIndent=0)

    s["toc_h2"] = ParagraphStyle("toc_h2",
        fontName="Helvetica", fontSize=10, textColor=GRAY_DARK,
        spaceBefore=1, spaceAfter=1, leftIndent=16)

    s["section_label"] = ParagraphStyle("section_label",
        fontName="Helvetica-Bold", fontSize=9, textColor=ACCENT,
        spaceBefore=20, spaceAfter=4, letterSpacing=2)

    s["h1"] = ParagraphStyle("h1",
        fontName="Helvetica-Bold", fontSize=22, textColor=NAVY,
        spaceBefore=4, spaceAfter=10, leading=28)

    s["h2"] = ParagraphStyle("h2",
        fontName="Helvetica-Bold", fontSize=14, textColor=BLUE,
        spaceBefore=14, spaceAfter=6, leading=18)

    s["h3"] = ParagraphStyle("h3",
        fontName="Helvetica-Bold", fontSize=11, textColor=GRAY_DARK,
        spaceBefore=10, spaceAfter=4, leading=15)

    s["body"] = ParagraphStyle("body",
        fontName="Helvetica", fontSize=10, textColor=GRAY_DARK,
        leading=16, spaceBefore=4, spaceAfter=4)

    s["body_bold"] = ParagraphStyle("body_bold",
        fontName="Helvetica-Bold", fontSize=10, textColor=GRAY_DARK,
        leading=16, spaceBefore=2, spaceAfter=2)

    s["bullet"] = ParagraphStyle("bullet",
        fontName="Helvetica", fontSize=10, textColor=GRAY_DARK,
        leading=16, spaceBefore=2, spaceAfter=2,
        leftIndent=20, bulletIndent=8)

    s["step"] = ParagraphStyle("step",
        fontName="Helvetica-Bold", fontSize=10, textColor=BLUE,
        leading=15, spaceBefore=8, spaceAfter=2, leftIndent=0)

    s["step_body"] = ParagraphStyle("step_body",
        fontName="Helvetica", fontSize=10, textColor=GRAY_DARK,
        leading=15, spaceBefore=2, spaceAfter=4, leftIndent=20)

    s["code"] = ParagraphStyle("code",
        fontName="Courier", fontSize=8, textColor=CODE_FG,
        leading=13, spaceBefore=2, spaceAfter=2,
        leftIndent=8, rightIndent=8, backColor=CODE_BG,
        borderPad=6)

    s["outcome"] = ParagraphStyle("outcome",
        fontName="Helvetica-BoldOblique", fontSize=10, textColor=GREEN,
        leading=14, spaceBefore=6, spaceAfter=6, leftIndent=12)

    s["explain_title"] = ParagraphStyle("explain_title",
        fontName="Helvetica-Bold", fontSize=10, textColor=TEAL,
        leading=14, spaceBefore=4, spaceAfter=2)

    s["explain_body"] = ParagraphStyle("explain_body",
        fontName="Helvetica-Oblique", fontSize=9.5, textColor=GRAY_DARK,
        leading=14, spaceBefore=2, spaceAfter=4, leftIndent=12)

    s["scenario"] = ParagraphStyle("scenario",
        fontName="Helvetica-BoldOblique", fontSize=10, textColor=WHITE,
        leading=15, spaceBefore=4, spaceAfter=4)

    s["appendix_h"] = ParagraphStyle("appendix_h",
        fontName="Helvetica-Bold", fontSize=13, textColor=BLUE,
        spaceBefore=16, spaceAfter=6)

    s["table_h"] = ParagraphStyle("table_h",
        fontName="Helvetica-Bold", fontSize=9, textColor=WHITE, leading=13)

    s["table_c"] = ParagraphStyle("table_c",
        fontName="Helvetica", fontSize=9, textColor=GRAY_DARK, leading=13)

    s["table_code"] = ParagraphStyle("table_code",
        fontName="Courier", fontSize=8, textColor=BLUE, leading=12)

    s["back_big"] = ParagraphStyle("back_big",
        fontName="Helvetica-Bold", fontSize=28, textColor=WHITE,
        leading=36, spaceAfter=12, alignment=TA_CENTER)

    s["back_sub"] = ParagraphStyle("back_sub",
        fontName="Helvetica", fontSize=14, textColor=ACCENT,
        leading=20, spaceAfter=8, alignment=TA_CENTER)

    s["back_tag"] = ParagraphStyle("back_tag",
        fontName="Helvetica-Oblique", fontSize=12,
        textColor=colors.HexColor("#b0bec5"),
        leading=18, alignment=TA_CENTER)

    s["footer"] = ParagraphStyle("footer",
        fontName="Helvetica", fontSize=8, textColor=GRAY_MID,
        alignment=TA_CENTER)

    return s


# ── Page template (header/footer on body pages) ───────────────────────────────
class PageDecorator:
    def __init__(self, title=""):
        self.title = title
        self._page = 0

    def __call__(self, canv, doc):
        self._page += 1
        canv.saveState()
        # Top bar
        canv.setFillColor(NAVY)
        canv.rect(0, H - 36, W, 36, fill=1, stroke=0)
        canv.setFillColor(ACCENT)
        canv.rect(0, H - 38, W, 2, fill=1, stroke=0)
        # Brand
        canv.setFillColor(WHITE)
        canv.setFont("Helvetica-Bold", 11)
        canv.drawString(0.5 * inch, H - 24, "ContainIQ")
        canv.setFillColor(ACCENT)
        canv.setFont("Helvetica", 9)
        canv.drawString(1.35 * inch, H - 24, "| AI-Powered Incident Response")
        # Page title
        if self.title:
            canv.setFillColor(colors.HexColor("#b0bec5"))
            canv.setFont("Helvetica", 8)
            canv.drawRightString(W - 0.5 * inch, H - 24, self.title)
        # Footer bar
        canv.setFillColor(GRAY_LT)
        canv.rect(0, 0, W, 28, fill=1, stroke=0)
        canv.setFillColor(BLUE)
        canv.rect(0, 27, W, 1, fill=1, stroke=0)
        canv.setFillColor(GRAY_MID)
        canv.setFont("Helvetica", 8)
        canv.drawString(0.5 * inch, 9, "ContainIQ Customer Onboarding Lab Guide  |  Version 1.0")
        canv.drawRightString(W - 0.5 * inch, 9, f"Page {self._page}")
        canv.restoreState()


# ── Code block helper ─────────────────────────────────────────────────────────
def code_block(text, styles):
    """Returns a list of code-styled Paragraphs."""
    lines = text.strip().split("\n")
    result = []
    code_style = ParagraphStyle("code_line",
        fontName="Courier", fontSize=8, textColor=CODE_FG,
        leading=13, spaceBefore=0, spaceAfter=0,
        leftIndent=10, rightIndent=10, backColor=CODE_BG, borderPad=4)
    first_style = ParagraphStyle("code_first",
        fontName="Courier", fontSize=8, textColor=CODE_FG,
        leading=13, spaceBefore=6, spaceAfter=0,
        leftIndent=10, rightIndent=10, backColor=CODE_BG, borderPad=4)
    last_style = ParagraphStyle("code_last",
        fontName="Courier", fontSize=8, textColor=CODE_FG,
        leading=13, spaceBefore=0, spaceAfter=8,
        leftIndent=10, rightIndent=10, backColor=CODE_BG, borderPad=4)
    for i, line in enumerate(lines):
        safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if not safe:
            safe = " "
        st = first_style if i == 0 else (last_style if i == len(lines)-1 else code_style)
        result.append(Paragraph(safe, st))
    return result


def scenario_box(text, styles):
    sty = ParagraphStyle("scenario_p",
        fontName="Helvetica-BoldOblique", fontSize=10, textColor=WHITE,
        leading=16, spaceBefore=8, spaceAfter=8,
        leftIndent=12, rightIndent=12, backColor=colors.HexColor("#0d2137"),
        borderColor=BLUE_LT, borderWidth=1, borderPad=10)
    return Paragraph(text, sty)


def outcome_box(text, styles):
    sty = ParagraphStyle("outcome_p",
        fontName="Helvetica-BoldOblique", fontSize=10, textColor=colors.HexColor("#2e7d32"),
        leading=16, spaceBefore=8, spaceAfter=8,
        leftIndent=12, rightIndent=12, backColor=colors.HexColor("#e8f5e9"),
        borderColor=GREEN, borderWidth=1, borderPad=10)
    return Paragraph(f"<b>Expected Outcome:</b> {text}", sty)


def explain_box(title, text, styles):
    """Returns a list of two Paragraphs styled as an info box."""
    title_sty = ParagraphStyle("explain_t",
        fontName="Helvetica-Bold", fontSize=10, textColor=TEAL,
        leading=15, spaceBefore=8, spaceAfter=2,
        leftIndent=12, rightIndent=12, backColor=colors.HexColor("#e0f7fa"),
        borderColor=TEAL, borderWidth=1, borderPad=8)
    body_sty = ParagraphStyle("explain_b",
        fontName="Helvetica-Oblique", fontSize=9.5, textColor=GRAY_DARK,
        leading=14, spaceBefore=0, spaceAfter=10,
        leftIndent=12, rightIndent=12, backColor=colors.HexColor("#e0f7fa"),
        borderColor=TEAL, borderWidth=1, borderPad=8)
    return [Paragraph(title, title_sty), Paragraph(text, body_sty)]


def step(n, title, body, styles):
    """Returns a list of flowables for a numbered step."""
    combined_style = ParagraphStyle("step_combined",
        fontName="Helvetica-Bold", fontSize=10, textColor=BLUE,
        leading=15, spaceBefore=10, spaceAfter=2)
    body_style = ParagraphStyle("step_body2",
        fontName="Helvetica", fontSize=10, textColor=GRAY_DARK,
        leading=15, spaceBefore=0, spaceAfter=6, leftIndent=20)
    return [
        Paragraph(f'<font color="#1565c0"><b>Step {n} — {title}</b></font>', combined_style),
        Paragraph(body, body_style),
    ]


def divider(styles):
    return HRFlowable(width="100%", thickness=1, color=GRAY_LT,
                      spaceAfter=10, spaceBefore=10)


# ── Cover page ────────────────────────────────────────────────────────────────
def build_cover(canv, doc):
    canv.saveState()
    # Background
    canv.setFillColor(NAVY)
    canv.rect(0, 0, W, H, fill=1, stroke=0)
    # Blue accent band bottom
    canv.setFillColor(BLUE)
    canv.rect(0, 0, W, 0.12 * H, fill=1, stroke=0)
    # Teal left stripe
    canv.setFillColor(TEAL)
    canv.rect(0, 0.12 * H, 6, H * 0.62, fill=1, stroke=0)
    # Accent top stripe
    canv.setFillColor(ACCENT)
    canv.rect(0, H - 4, W, 4, fill=1, stroke=0)
    # Shield outline (decorative)
    canv.setStrokeColor(colors.HexColor("#1565c0"))
    canv.setLineWidth(1.5)
    for i in range(1, 5):
        canv.setFillColorRGB(0, 0, 0, 0)
        cx, cy, r = W * 0.82, H * 0.6, 90 + i * 28
        canv.circle(cx, cy, r, fill=0, stroke=1)
    # Logo text
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 42)
    canv.drawString(0.65 * inch, H * 0.76, "ContainIQ")
    canv.setFillColor(ACCENT)
    canv.setFont("Helvetica", 14)
    canv.drawString(0.65 * inch, H * 0.72, "AI-Powered Incident Response Platform")
    # Divider
    canv.setStrokeColor(ACCENT)
    canv.setLineWidth(1)
    canv.line(0.65 * inch, H * 0.705, W - 0.65 * inch, H * 0.705)
    # Guide title
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 28)
    canv.drawString(0.65 * inch, H * 0.63, "Customer Onboarding")
    canv.drawString(0.65 * inch, H * 0.585, "Lab Guide")
    # Subtitle
    canv.setFillColor(colors.HexColor("#90caf9"))
    canv.setFont("Helvetica", 13)
    canv.drawString(0.65 * inch, H * 0.545, "Hands-on exercises for SOC analysts and security teams")
    # Version + badges
    canv.setFillColor(BLUE_LT)
    canv.roundRect(0.65*inch, H*0.46, 0.8*inch, 0.22*inch, 4, fill=1, stroke=0)
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 9)
    canv.drawCentredString(0.65*inch + 0.4*inch, H*0.476, "Version 1.0")

    canv.setFillColor(colors.HexColor("#1b5e20"))
    canv.roundRect(1.55*inch, H*0.46, 1.0*inch, 0.22*inch, 4, fill=1, stroke=0)
    canv.setFillColor(WHITE)
    canv.drawCentredString(1.55*inch + 0.5*inch, H*0.476, "3 Hands-on Labs")

    canv.setFillColor(colors.HexColor("#b71c1c"))
    canv.roundRect(2.65*inch, H*0.46, 1.1*inch, 0.22*inch, 4, fill=1, stroke=0)
    canv.setFillColor(WHITE)
    canv.drawCentredString(2.65*inch + 0.55*inch, H*0.476, "~30 Min Total")

    # Bottom area
    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 11)
    canv.drawString(0.65 * inch, H * 0.09, "containiq.io")
    canv.setFont("Helvetica", 9)
    canv.setFillColor(colors.HexColor("#90caf9"))
    canv.drawString(0.65 * inch, H * 0.065,
                    "Open-source  |  AI-native  |  Audit-ready  |  Free vs $50k+/yr enterprise tools")
    canv.restoreState()


# ── Back page ─────────────────────────────────────────────────────────────────
def build_back(canv, doc):
    canv.saveState()
    canv.setFillColor(NAVY)
    canv.rect(0, 0, W, H, fill=1, stroke=0)
    canv.setFillColor(BLUE)
    canv.rect(0, H * 0.38, W, H * 0.25, fill=1, stroke=0)
    canv.setFillColor(ACCENT)
    canv.rect(0, H - 4, W, 4, fill=1, stroke=0)
    canv.setFillColor(TEAL)
    canv.rect(0, 0, W, 4, fill=1, stroke=0)

    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 30)
    cy = H * 0.56
    canv.drawCentredString(W / 2, cy, "Ready to deploy ContainIQ")
    canv.drawCentredString(W / 2, cy - 38, "for your team?")

    canv.setFillColor(ACCENT)
    canv.setFont("Helvetica", 13)
    canv.drawCentredString(W / 2, H * 0.43,
                           "Start free. Scale when you need it. No vendor lock-in.")

    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 14)
    canv.drawCentredString(W / 2, H * 0.29, "containiq.io")
    canv.setFont("Helvetica", 11)
    canv.setFillColor(colors.HexColor("#90caf9"))
    canv.drawCentredString(W / 2, H * 0.265, "hello@containiq.io  |  github.com/containiq")

    canv.setFillColor(colors.HexColor("#b0bec5"))
    canv.setFont("Helvetica-Oblique", 11)
    canv.drawCentredString(W / 2, H * 0.18,
                           '"ContainIQ — AI-Native Incident Response. Built for teams who move fast."')

    canv.setFillColor(WHITE)
    canv.setFont("Helvetica-Bold", 22)
    canv.drawCentredString(W / 2, H * 0.1, "ContainIQ")
    canv.setFillColor(ACCENT)
    canv.setFont("Helvetica", 10)
    canv.drawCentredString(W / 2, H * 0.08, "AI-Powered Incident Response Platform")
    canv.restoreState()


# ── Build document ────────────────────────────────────────────────────────────
def build_pdf(output_path):
    S = make_styles()

    decorator = PageDecorator("Customer Onboarding Lab Guide")
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.55 * inch,
        title="ContainIQ Customer Onboarding Lab Guide",
        author="ContainIQ",
        subject="Hands-on lab exercises for SOC analysts and security teams",
    )

    story = []

    # ── COVER (blank page driven by onPage) ──────────────────────────────────
    story.append(Paragraph("", ParagraphStyle("blank")))
    story.append(PageBreak())

    # ── TABLE OF CONTENTS ────────────────────────────────────────────────────
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph("Table of Contents", S["toc_title"]))
    story.append(HRFlowable(width="100%", thickness=2, color=BLUE, spaceAfter=12))

    toc_data = [
        ("Introduction", None),
        ("What is ContainIQ", True),
        ("Prerequisites", True),
        ("Lab Environment Overview", True),
        ("Lab 1 — Alert Ingestion & Case Creation", None),
        ("Scenario: Phishing / Inbox Forwarding", True),
        ("Steps 1–5: Ingest alert, view case, review entities", True),
        ("What Just Happened?", True),
        ("Lab 2 — AI Investigation & Playbook Execution", None),
        ("Scenario: Ransomware Containment", True),
        ("Steps 1–6: Create case, AI analyze, run playbook", True),
        ("What Just Happened?", True),
        ("Lab 3 — Reporting & Compliance", None),
        ("Scenario: Incident Closure", True),
        ("Steps 1–6: Close case, report, MTTR metrics", True),
        ("What Just Happened?", True),
        ("Appendix A — API Reference", None),
        ("Appendix B — Supported Alert Formats", None),
        ("Appendix C — Environment Variables", None),
    ]

    for label, is_sub in toc_data:
        sty = S["toc_h2"] if is_sub else S["toc_h1"]
        prefix = "    " if is_sub else ""
        story.append(Paragraph(f"{prefix}{'· ' if is_sub else ''}{label}", sty))

    story.append(PageBreak())

    # ── INTRODUCTION ─────────────────────────────────────────────────────────
    story.append(Paragraph("INTRODUCTION", S["section_label"]))
    story.append(Paragraph("Getting Started with ContainIQ", S["h1"]))
    story.append(divider(S))

    story.append(Paragraph("What is ContainIQ?", S["h2"]))
    story.append(Paragraph(
        "ContainIQ is an open-source, AI-native Security Orchestration, Automation, and Response (SOAR) "
        "platform built for SOC teams and MSSPs who need enterprise-grade incident response without the "
        "$50,000+/year price tag of tools like CrowdStrike Falcon Fusion or Cortex XSOAR.",
        S["body"]))
    story.append(Paragraph(
        "At its core, ContainIQ combines intelligent alert ingestion, AI-powered case analysis (via "
        "Claude), structured playbook execution with approval gates, NIST CSF 2.0 compliance mapping, "
        "IOC enrichment, and a full immutable audit trail — all in one unified platform.",
        S["body"]))

    story.append(Paragraph("Who This Guide Is For", S["h2"]))
    for item in [
        "SOC Analysts who investigate and respond to security incidents",
        "MSSP engineers onboarding new clients onto ContainIQ",
        "Security engineers evaluating ContainIQ for their organization",
        "Anyone learning modern AI-assisted incident response workflows",
    ]:
        story.append(Paragraph(f"• {item}", S["bullet"]))

    story.append(Paragraph("Prerequisites", S["h2"]))
    prereqs = [
        ["Requirement", "Details"],
        ["Python", "3.11 or higher"],
        ["ContainIQ", "Running locally (python run.py) on port 5001, or hosted"],
        ["Browser", "Any modern browser (Chrome, Firefox, Edge)"],
        ["curl", "For Lab 1 API exercise (or use Postman / Python requests)"],
        ["API Keys (optional)", "VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY for IOC enrichment"],
        ["ANTHROPIC_API_KEY", "Required for AI analysis features (Labs 2 & 3)"],
    ]
    pt = Table(prereqs, colWidths=[2.0 * inch, 4.5 * inch],
               style=TableStyle([
                   ("BACKGROUND",    (0,0), (-1,0), BLUE),
                   ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
                   ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                   ("FONTSIZE",      (0,0), (-1,-1), 9),
                   ("BACKGROUND",    (0,1), (-1,-1), GRAY_LT),
                   ("BACKGROUND",    (0,2), (-1,2), WHITE),
                   ("BACKGROUND",    (0,4), (-1,4), WHITE),
                   ("BACKGROUND",    (0,6), (-1,6), WHITE),
                   ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, GRAY_LT]),
                   ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#cfd8dc")),
                   ("TOPPADDING",    (0,0), (-1,-1), 6),
                   ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                   ("LEFTPADDING",   (0,0), (-1,-1), 8),
                   ("RIGHTPADDING",  (0,0), (-1,-1), 8),
               ]))
    story.append(pt)

    story.append(Paragraph("Lab Environment Overview", S["h2"]))
    story.append(Paragraph(
        "Each lab builds on the last. You will ingest an alert, investigate it with AI, contain it with "
        "a playbook, and document it for compliance — completing the full SOC workflow from detection "
        "to closure in about 30 minutes.", S["body"]))

    env_data = [
        ["Lab", "Scenario", "Skills Practiced", "Time"],
        ["Lab 1", "Phishing / Inbox Forwarding", "Alert ingestion, IOC enrichment", "~8 min"],
        ["Lab 2", "Ransomware Containment", "AI analysis, playbook execution", "~12 min"],
        ["Lab 3", "Incident Closure", "Reporting, NIST CSF, MTTR metrics", "~10 min"],
    ]
    et = Table(env_data, colWidths=[0.6*inch, 1.8*inch, 2.8*inch, 1.0*inch],
               style=TableStyle([
                   ("BACKGROUND",    (0,0), (-1,0), NAVY),
                   ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
                   ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                   ("FONTSIZE",      (0,0), (-1,-1), 9),
                   ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, GRAY_LT]),
                   ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#cfd8dc")),
                   ("TOPPADDING",    (0,0), (-1,-1), 7),
                   ("BOTTOMPADDING", (0,0), (-1,-1), 7),
                   ("LEFTPADDING",   (0,0), (-1,-1), 8),
                   ("RIGHTPADDING",  (0,0), (-1,-1), 8),
                   ("ALIGN",         (3,0), (3,-1), "CENTER"),
               ]))
    story.append(et)
    story.append(PageBreak())

    # ── LAB 1 ────────────────────────────────────────────────────────────────
    story.append(Paragraph("LAB 1", S["section_label"]))
    story.append(Paragraph("Alert Ingestion & Case Creation", S["h1"]))
    story.append(divider(S))

    story.append(scenario_box(
        "SCENARIO: Your SIEM fires on a suspicious inbox forwarding rule created on the CEO's account. "
        "The login originated from a known TOR exit node and the rule forwards all email to an external "
        "domain. You need to get this into ContainIQ fast and start the investigation.", S))
    story.append(Spacer(1, 10))

    story.extend(step(1, "Start ContainIQ and Log In",
        "Open your terminal and run: <b>python run.py</b> from the ContainIQ directory. "
        "Then navigate to <b>http://localhost:5001</b> and log in with: "
        "admin@containiq.local / changeme", S))

    story.extend(step(2, "Ingest the Simulated Alert via API",
        "Open a new terminal and run the following curl command to simulate a Microsoft Sentinel alert "
        "firing on the inbox forwarding rule:", S))

    story.extend(code_block(
        'curl -X POST http://localhost:5001/api/v1/alerts \\\n'
        '  -H "X-API-Key: your-ingest-key" \\\n'
        '  -H "Content-Type: application/json" \\\n'
        '  -d \'{\n'
        '    "title": "Suspicious Inbox Forwarding Rule Detected",\n'
        '    "severity": "high",\n'
        '    "source": "microsoft_sentinel",\n'
        '    "user": "ceo@company.com",\n'
        '    "src_ip": "185.220.101.45",\n'
        '    "domain": "evil-exfil.ru",\n'
        '    "description": "Inbox forwarding rule created to external address "\n'
        '                   "after suspicious login from TOR exit node"\n'
        '  }\'', S))

    story.append(Paragraph(
        "You should receive a JSON response with <b>status: created</b> and a <b>case_id</b>.", S["step_body"]))

    story.extend(step(3, "Navigate to the Created Case",
        "In ContainIQ, click <b>Cases</b> in the nav bar. The new case will appear at the top "
        "with severity <b>HIGH</b>. Click <b>Investigate</b> to open it.", S))

    story.extend(step(4, "Review Auto-Extracted Entities",
        "In the Entities panel on the right, you will see ContainIQ automatically extracted three "
        "IOCs from the alert payload:", S))

    for e in [
        "user: ceo@company.com",
        "ip: 185.220.101.45  (TOR exit node)",
        "domain: evil-exfil.ru  (exfiltration domain)",
    ]:
        story.append(Paragraph(f"    → {e}", S["step_body"]))

    story.extend(step(5, "Observe IOC Enrichment (if API keys configured)",
        "If you have VIRUSTOTAL_API_KEY or ABUSEIPDB_API_KEY set in your .env file, enrichment runs "
        "automatically in the background. Within a few seconds, the entities will show color-coded "
        "threat badges:", S))

    badge_data = [
        ["Badge", "Meaning"],
        ["High Risk (red)", "5+ VT detections OR AbuseIPDB score ≥ 75%"],
        ["Suspicious (yellow)", "1+ VT detections OR AbuseIPDB score ≥ 25%"],
        ["Clean (green)", "No detections found"],
        ["VT X/N", "VirusTotal: X malicious engines out of N total"],
        ["Abuse XX%", "AbuseIPDB confidence score"],
        ["TOR", "IP is a known TOR exit node"],
    ]
    bt = Table(badge_data, colWidths=[2.0*inch, 4.5*inch],
               style=TableStyle([
                   ("BACKGROUND",    (0,0), (-1,0), NAVY),
                   ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
                   ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                   ("FONTSIZE",      (0,0), (-1,-1), 9),
                   ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, GRAY_LT]),
                   ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#cfd8dc")),
                   ("TOPPADDING",    (0,0), (-1,-1), 6),
                   ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                   ("LEFTPADDING",   (0,0), (-1,-1), 8),
                   ("RIGHTPADDING",  (0,0), (-1,-1), 8),
               ]))
    story.append(bt)
    story.append(Spacer(1, 8))

    story.append(outcome_box(
        "Case created automatically with severity HIGH. Three entities extracted (user, IP, domain). "
        "IOC enrichment badges visible if API keys are configured. Timeline shows 'alert_fired' event.", S))

    story.extend(explain_box(
        "What Just Happened?",
        "ContainIQ's ingestion API auto-detected the alert as a generic JSON payload, extracted IOC "
        "entities from known field names (src_ip, user, domain), created a case record, logged an "
        "immutable audit entry, and fired notifications for high-severity cases — all in under a second. "
        "The IOC enrichment runs in a background thread so it never slows down ingestion. Every action "
        "is recorded in the audit trail for compliance.", S))

    story.append(PageBreak())

    # ── LAB 2 ────────────────────────────────────────────────────────────────
    story.append(Paragraph("LAB 2", S["section_label"]))
    story.append(Paragraph("AI Investigation & Playbook Execution", S["h1"]))
    story.append(divider(S))

    story.append(scenario_box(
        "SCENARIO: Ransomware execution is detected on workstation DESKTOP-4A2X. File encryption has "
        "started. You have minutes to contain it before it spreads to network shares. ContainIQ's AI "
        "analyst and automated playbooks will help you move at machine speed.", S))
    story.append(Spacer(1, 10))

    story.extend(step(1, "Create the Ransomware Case",
        "Click <b>New Case</b> from the dashboard. Fill in the following details:", S))
    story.extend(code_block(
        "Title:       Ransomware Execution — DESKTOP-4A2X\n"
        "Severity:    Critical\n"
        "Source:      crowdstrike\n"
        "Description: Ransomware detected. File encryption in progress on DESKTOP-4A2X.\n"
        "Entities (one per line):\n"
        "  device:DESKTOP-4A2X\n"
        "  hash:4d1740485713a2ab3a4f5822a01f645ff13dca5\n"
        "  ip:10.0.1.44", S))

    story.extend(step(2, "Run AI Analysis",
        "Click the <b>AI Analyze</b> button in the case detail header. Claude will analyze the case and return:", S))
    for item in [
        "Attack summary and stage classification",
        "MITRE ATT&CK technique mapping (e.g. T1486 Data Encrypted for Impact)",
        "Severity rationale",
        "Immediate recommended actions",
        "Investigation gaps to fill",
    ]:
        story.append(Paragraph(f"    • {item}", S["step_body"]))

    story.extend(step(3, "Generate Threat Hunt Queries",
        "In the <b>AI Threat Hunting</b> panel, type a question and select your SIEM:", S))
    story.extend(code_block(
        "Question: Hunt for lateral movement from 10.0.1.44 in the last 48 hours\n"
        "SIEM:     Splunk SPL", S))
    story.append(Paragraph(
        "Claude will generate a ready-to-run SPL query you can paste directly into Splunk.", S["step_body"]))

    story.extend(step(4, "Run the Ransomware Playbook (Dry Run)",
        "In the <b>Run a Playbook</b> panel, select <b>Ransomware Execution Response</b>. "
        "The playbook runner will open with <b>Dry Run</b> mode enabled by default.", S))

    story.extend(step(5, "Review Blast Radius and Approve Execution",
        "Review the dry run output — it shows every action the playbook will take, which hosts "
        "it will touch, and the blast radius limit. When satisfied, click <b>Run Live</b> and "
        "approve each step that requires an approval gate. Steps include:", S))
    for item in [
        "Isolate endpoint DESKTOP-4A2X from network",
        "Disable user account associated with the case",
        "Snapshot disk for forensic preservation",
        "Block the malicious hash across all endpoints",
    ]:
        story.append(Paragraph(f"    → {item}", S["step_body"]))

    story.extend(step(6, "Verify Rollback Capability",
        "In the playbook run detail, click <b>Rollback</b> to see the rollback plan. "
        "ContainIQ maintains a full rollback manifest so every automated action can be reversed "
        "if needed — critical for audit compliance.", S))

    story.append(Spacer(1, 8))
    story.append(outcome_box(
        "Case analyzed with MITRE mapping. Splunk hunt query generated. Ransomware playbook executed "
        "with approval gates passed. Rollback manifest available. All steps logged in audit trail.", S))

    story.extend(explain_box(
        "What Just Happened?",
        "The AI analyst sent the full case context to Claude with prompt caching for efficiency. "
        "The playbook engine validated each step against the blast radius limit before executing. "
        "Approval gates ensure no automated action runs without human sign-off — a core requirement "
        "for SOC compliance frameworks. The rollback manifest is generated at run time so reversibility "
        "is guaranteed before the first action fires.", S))

    story.append(PageBreak())

    # ── LAB 3 ────────────────────────────────────────────────────────────────
    story.append(Paragraph("LAB 3", S["section_label"]))
    story.append(Paragraph("Reporting & Compliance", S["h1"]))
    story.append(divider(S))

    story.append(scenario_box(
        "SCENARIO: The ransomware incident is contained. Your CISO needs a full incident report by "
        "end of day, the compliance team needs a NIST CSF 2.0 mapping, and your manager wants to "
        "know the MTTR for this quarter. ContainIQ generates all of this in minutes.", S))
    story.append(Spacer(1, 10))

    story.extend(step(1, "Close the Case",
        "Open the ransomware case from Lab 2. Click <b>Set Status</b> and move it through: "
        "<b>Investigating → Contained → Closed</b>. "
        "ContainIQ automatically records the closed_at timestamp for MTTR calculation.", S))

    story.extend(step(2, "Generate an Incident Report",
        "In the <b>Generate Report</b> panel on the case detail page, click <b>Incident Report</b>. "
        "The AI analyst produces a structured report including: executive summary, timeline of events, "
        "affected assets, containment actions taken, and recommendations.", S))

    story.extend(step(3, "Generate NIST CSF 2.0 Mapping",
        "Click <b>NIST CSF Mapping</b>. ContainIQ maps every response action taken during the case "
        "to NIST CSF 2.0 functions: Govern (GV), Identify (ID), Protect (PR), Detect (DE), "
        "Respond (RS), Recover (RC). This is what compliance auditors want to see.", S))

    story.extend(step(4, "Export as PDF",
        "Click <b>Export PDF</b>. ContainIQ generates a formatted PDF combining the incident report "
        "and NIST mapping — ready to send to your CISO or attach to a compliance submission.", S))

    story.extend(step(5, "Review the Immutable Audit Trail",
        "Navigate to <b>Reports → Audit Packet</b>. Every action taken during the case is recorded "
        "with: timestamp, user, action type, outcome, and IP address. This log is append-only and "
        "cannot be modified — meeting SOC 2, ISO 27001, and NIST requirements.", S))

    story.extend(step(6, "Check MTTR on the Metrics Dashboard",
        "Click <b>Metrics</b> in the nav bar. The MTTR dashboard shows:", S))
    for item in [
        "Overall average MTTR (hours) across all closed cases",
        "p50 and p95 response times",
        "Breakdown by severity (critical, high, medium, low)",
        "8-week trend chart",
        "SLA benchmark comparison (e.g. critical cases: target 1h)",
        "Stale open cases breaching the 24h SLA threshold",
    ]:
        story.append(Paragraph(f"    • {item}", S["step_body"]))

    story.append(Spacer(1, 8))
    story.append(outcome_box(
        "Case closed with full timestamp. Incident report generated. NIST CSF 2.0 mapping produced. "
        "PDF exported. Immutable audit packet ready. MTTR recorded and visible in metrics dashboard.", S))

    story.extend(explain_box(
        "What Just Happened?",
        "ContainIQ's NIST mapper analyzed every action in the case timeline and audit log, then "
        "classified each one against the six NIST CSF 2.0 functions automatically — no manual "
        "tagging required. The MTTR engine calculated response time from the moment the case was "
        "created to the moment it was closed, giving you real data for SLA reporting, team performance "
        "reviews, and compliance audits. The immutable audit log ensures you can prove — not just "
        "claim — what happened and when.", S))

    story.append(PageBreak())

    # ── APPENDICES ───────────────────────────────────────────────────────────
    story.append(Paragraph("APPENDICES", S["section_label"]))
    story.append(Paragraph("Reference Material", S["h1"]))
    story.append(divider(S))

    story.append(Paragraph("Appendix A — API Quick Reference", S["appendix_h"]))
    api_data = [
        ["Method", "Endpoint", "Description"],
        ["POST", "/api/v1/alerts", "Ingest an alert (auto-detect format)"],
        ["POST", "/api/v1/alerts?format=sentinel", "Ingest with explicit format override"],
        ["POST", "/api/v1/alerts/test", "Validate payload without creating a case"],
        ["GET",  "/api/v1/health", "Health check — returns service status"],
    ]
    at = Table(api_data, colWidths=[0.7*inch, 2.4*inch, 3.4*inch],
               style=TableStyle([
                   ("BACKGROUND",    (0,0), (-1,0), NAVY),
                   ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
                   ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                   ("FONTSIZE",      (0,0), (-1,-1), 9),
                   ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, GRAY_LT]),
                   ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#cfd8dc")),
                   ("TOPPADDING",    (0,0), (-1,-1), 7),
                   ("BOTTOMPADDING", (0,0), (-1,-1), 7),
                   ("LEFTPADDING",   (0,0), (-1,-1), 8),
                   ("RIGHTPADDING",  (0,0), (-1,-1), 8),
               ]))
    story.append(at)

    story.append(Paragraph("Authentication Header:", S["h3"]))
    story.extend(code_block("X-API-Key: <your-INGEST_API_KEY>", S))

    story.append(Paragraph("Appendix B — Supported Alert Formats", S["appendix_h"]))
    fmt_data = [
        ["Format", "Auto-Detection Signal", "format= value"],
        ["Microsoft Sentinel", "alertDisplayName in properties", "sentinel"],
        ["Splunk", "search_name or result field present", "splunk"],
        ["CrowdStrike Falcon", "behaviors or detection_id present", "crowdstrike"],
        ["Elastic SIEM", "signal.rule nested object present", "elastic"],
        ["Generic JSON", "All other payloads (always works)", "generic"],
    ]
    ft = Table(fmt_data, colWidths=[1.7*inch, 2.7*inch, 2.1*inch],
               style=TableStyle([
                   ("BACKGROUND",    (0,0), (-1,0), NAVY),
                   ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
                   ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                   ("FONTSIZE",      (0,0), (-1,-1), 9),
                   ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, GRAY_LT]),
                   ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#cfd8dc")),
                   ("TOPPADDING",    (0,0), (-1,-1), 7),
                   ("BOTTOMPADDING", (0,0), (-1,-1), 7),
                   ("LEFTPADDING",   (0,0), (-1,-1), 8),
                   ("RIGHTPADDING",  (0,0), (-1,-1), 8),
               ]))
    story.append(ft)

    story.append(Paragraph("Appendix C — Environment Variables", S["appendix_h"]))
    env_data2 = [
        ["Variable", "Required?", "Purpose"],
        ["ANTHROPIC_API_KEY", "Yes (AI features)", "Powers AI analysis, hunt queries, threat intel synthesis"],
        ["INGEST_API_KEY", "Yes (API ingest)", "Authenticates external alert sources"],
        ["VIRUSTOTAL_API_KEY", "Optional", "IOC enrichment for IPs, domains, file hashes"],
        ["ABUSEIPDB_API_KEY", "Optional", "IP reputation and abuse confidence scoring"],
        ["SHODAN_API_KEY", "Optional", "Internet-exposed asset intelligence"],
        ["OTX_API_KEY", "Optional", "AlienVault OTX threat intelligence feed"],
        ["DATABASE_URL", "Optional", "PostgreSQL URI (defaults to SQLite for dev)"],
        ["SECRET_KEY", "Production", "Flask session signing key — change in production"],
    ]
    envt = Table(env_data2, colWidths=[1.9*inch, 1.1*inch, 3.5*inch],
               style=TableStyle([
                   ("BACKGROUND",    (0,0), (-1,0), NAVY),
                   ("TEXTCOLOR",     (0,0), (-1,0), WHITE),
                   ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                   ("FONTSIZE",      (0,0), (-1,-1), 9),
                   ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, GRAY_LT]),
                   ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#cfd8dc")),
                   ("TOPPADDING",    (0,0), (-1,-1), 7),
                   ("BOTTOMPADDING", (0,0), (-1,-1), 7),
                   ("LEFTPADDING",   (0,0), (-1,-1), 8),
                   ("RIGHTPADDING",  (0,0), (-1,-1), 8),
               ]))
    story.append(envt)

    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=GRAY_LT))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "For the latest documentation, changelog, and community support: "
        "<b>github.com/containiq</b>  |  <b>containiq.io/docs</b>",
        S["footer"]))

    story.append(PageBreak())

    # ── BACK COVER ───────────────────────────────────────────────────────────
    story.append(Paragraph("", ParagraphStyle("blank2")))

    # ── Build ─────────────────────────────────────────────────────────────────
    # Track page numbers via a mutable container so closures can update it
    state = {"page": 0, "total": None}

    def on_page(canv, doc):
        state["page"] += 1
        n = state["page"]
        total = state["total"]
        if n == 1:
            build_cover(canv, doc)
        elif total is not None and n == total:
            build_back(canv, doc)
        else:
            decorator(canv, doc)

    # First pass — count pages using a null canvas
    from io import BytesIO
    from reportlab.pdfgen.canvas import Canvas as _Canvas

    buf = BytesIO()
    count_doc = SimpleDocTemplate(buf, pagesize=letter,
        leftMargin=0.65*inch, rightMargin=0.65*inch,
        topMargin=0.9*inch, bottomMargin=0.7*inch)

    _counter = [0]
    def _count(canv, doc): _counter[0] += 1
    count_doc.build(list(story), onFirstPage=_count, onLaterPages=_count)
    state["total"] = _counter[0]

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f"PDF built: {output_path}  ({state['total']} pages)")


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "ContainIQ_Lab_Guide.pdf")
    build_pdf(out)
