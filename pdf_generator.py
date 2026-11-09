
import os
import re
import html
import sqlite3
import uuid

from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

# ==========================================================
# CONFIGURATION
# ==========================================================

DB_PATH = "soc_monitor.db"
REPORT_DIR = "reports"

PAGE_WIDTH, PAGE_HEIGHT = A4

NAVY = colors.HexColor("#101827")
DARK_NAVY = colors.HexColor("#172338")

RED = colors.HexColor("#DC2626")
DARK_RED = colors.HexColor("#991B1B")

LIGHT_RED = colors.HexColor("#FEF2F2")
PALE_RED = colors.HexColor("#FEE2E2")

BLUE = colors.HexColor("#2563EB")
LIGHT_BLUE = colors.HexColor("#EFF6FF")

WHITE = colors.white
BLACK = colors.HexColor("#111827")
GREY = colors.HexColor("#64748B")
LIGHT_GREY = colors.HexColor("#F1F5F9")
BORDER = colors.HexColor("#E2E8F0")
BODY_TEXT = colors.HexColor("#334155")


# ==========================================================
# SAFE TEXT HANDLING
# ==========================================================

def safe(value):
    if value is None:
        return "Not available"

    return html.escape(str(value))


# ==========================================================
# PDF STYLES
# ==========================================================

def get_styles():

    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="SOCHeader",
        fontName="Helvetica-Bold",
        fontSize=21,
        leading=27,
        textColor=WHITE,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name="SOCHeaderSub",
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#CBD5E1"),
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name="SOCBanner",
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=30,
        textColor=WHITE,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name="SOCBannerSub",
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=14,
        textColor=WHITE,
        alignment=TA_CENTER
    ))

    styles.add(ParagraphStyle(
        name="SOCSeverityLabel",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=12,
        textColor=GREY
    ))

    styles.add(ParagraphStyle(
        name="SOCSeverityNumber",
        fontName="Helvetica-Bold",
        fontSize=27,
        leading=34,
        textColor=RED
    ))

    styles.add(ParagraphStyle(
        name="SOCSeverityValue",
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=19,
        textColor=NAVY,
        wordWrap="CJK"
    ))

    styles.add(ParagraphStyle(
        name="SOCSection",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=NAVY,
        spaceBefore=12,
        spaceAfter=7,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name="SOCRedSection",
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=DARK_RED,
        spaceBefore=12,
        spaceAfter=7,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name="SOCBody",
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=BODY_TEXT,
        spaceAfter=5,
        wordWrap="CJK"
    ))

    styles.add(ParagraphStyle(
        name="SOCMetadata",
        fontName="Helvetica",
        fontSize=8,
        leading=12,
        textColor=BLACK,
        wordWrap="CJK"
    ))

    styles.add(ParagraphStyle(
        name="SOCMetadataLabel",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=12,
        textColor=NAVY
    ))

    styles.add(ParagraphStyle(
        name="SOCDisclaimer",
        fontName="Helvetica",
        fontSize=8,
        leading=12,
        textColor=BODY_TEXT
    ))

    return styles


# ==========================================================
# PAGE HEADER AND FOOTER
# ==========================================================

def draw_page(canvas, doc):

    canvas.saveState()

    width, height = A4

    # Red top border
    canvas.setFillColor(RED)
    canvas.rect(
        0,
        height - 5,
        width,
        5,
        fill=1,
        stroke=0
    )

    # Footer separator
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.7)

    canvas.line(
        18 * mm,
        16 * mm,
        width - 18 * mm,
        16 * mm
    )

    # Footer text
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(GREY)

    canvas.drawString(
        18 * mm,
        10 * mm,
        "CONFIDENTIAL | SECURITY OPERATIONS CENTER"
    )

    canvas.drawRightString(
        width - 18 * mm,
        10 * mm,
        f"PAGE {doc.page}"
    )

    canvas.restoreState()


# ==========================================================
# METADATA TABLE
# ==========================================================

def create_metadata_table(metadata, styles):

    rows = []

    for label, value in metadata:

        rows.append([
            Paragraph(
                safe(label),
                styles["SOCMetadataLabel"]
            ),
            Paragraph(
                safe(value),
                styles["SOCMetadata"]
            )
        ])

    table = Table(
        rows,
        colWidths=[48 * mm, 126 * mm],
        repeatRows=0
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT_GREY),
        ("BACKGROUND", (1, 0), (1, -1), WHITE),

        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),

        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),

        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),

        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    return table


# ==========================================================
# SEVERITY PANEL
# ==========================================================

def create_severity_panel(alert, styles, critical):

    rule_level = int(alert["rule_level"] or 0)

    level_color = RED if critical else BLUE
    panel_background = LIGHT_RED if critical else LIGHT_BLUE

    level_style = ParagraphStyle(
        name="CurrentLevel",
        parent=styles["SOCSeverityNumber"],
        textColor=level_color
    )

    level_card = [
        Paragraph(
            "WAZUH RULE LEVEL",
            styles["SOCSeverityLabel"]
        ),
        Paragraph(
            str(rule_level),
            level_style
        )
    ]

    rule_card = [
        Paragraph(
            "WAZUH RULE ID",
            styles["SOCSeverityLabel"]
        ),
        Paragraph(
            safe(alert["rule_id"]),
            styles["SOCSeverityValue"]
        )
    ]

    agent_card = [
        Paragraph(
            "MONITORED AGENT",
            styles["SOCSeverityLabel"]
        ),
        Paragraph(
            safe(alert["agent_name"]),
            styles["SOCSeverityValue"]
        )
    ]

    table = Table(
        [[level_card, rule_card, agent_card]],
        colWidths=[
            58 * mm,
            53 * mm,
            63 * mm
        ]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), panel_background),

        ("BOX", (0, 0), (-1, -1), 1, PALE_RED if critical else BORDER),

        ("INNERGRID", (0, 0), (-1, -1), 0.6, BORDER),

        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),

        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 11),

        ("TOPPADDING", (0, 0), (-1, -1), 13),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 13),
    ]))

    return table


# ==========================================================
# AI ANALYSIS FORMATTER
# ==========================================================

def add_ai_analysis(story, analysis, styles):

    section_styles = {
        "ALERT SUMMARY": "SOCSection",
        "CONFIRMED FACTS": "SOCSection",
        "POTENTIAL RISKS": "SOCRedSection",
        "RECOMMENDED INVESTIGATION": "SOCSection",
        "WAZUH REMEDIATION GUIDANCE": "SOCSection",
        "CONCLUSION": "SOCSection"
    }

    for raw_line in (analysis or "").splitlines():

        line = raw_line.strip()

        if not line:
            story.append(Spacer(1, 3))
            continue

        heading = re.match(
            r"^([A-Z][A-Z ]+):?$",
            line
        )

        if heading:

            heading_text = heading.group(1)

            if heading_text in section_styles:

                style_name = section_styles[heading_text]

                story.append(
                    Paragraph(
                        safe(heading_text),
                        styles[style_name]
                    )
                )

                continue

        if line.startswith(("- ", "* ")):

            story.append(
                Paragraph(
                    "&#8226; " + safe(line[2:]),
                    styles["SOCBody"]
                )
            )

        else:

            story.append(
                Paragraph(
                    safe(line),
                    styles["SOCBody"]
                )
            )


# ==========================================================
# MAIN PDF GENERATOR
# ==========================================================

def generate_report(alert=None):

    os.makedirs(REPORT_DIR, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    try:

        if alert is None:

            alert = connection.execute("""
                SELECT *
                FROM processed_alerts
                WHERE status = 'analyzed'
                  AND ai_analysis IS NOT NULL
                ORDER BY ai_analyzed_at DESC
                LIMIT 1
            """).fetchone()

        if not alert:

            print("[ERROR] No analysed alert found.")
            return None

        report_id = (
            "SOC-" +
            uuid.uuid4().hex[:10].upper()
        )

        filename = f"{report_id}.pdf"

        filepath = os.path.join(
            REPORT_DIR,
            filename
        )

        rule_level = int(alert["rule_level"] or 0)

        critical = rule_level >= 7

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=23 * mm,
            title="SOC Security Incident Report",
            author="SOC AI Monitoring System",
            subject=f"Wazuh Rule {alert['rule_id']}"
        )

        styles = get_styles()

        story = []

        # --------------------------------------------------
        # 1. SOC HEADER
        # --------------------------------------------------

        header_content = [
            Paragraph(
                "SECURITY OPERATIONS CENTER",
                styles["SOCHeader"]
            ),
            Spacer(1, 5),
            Paragraph(
                "AI-ASSISTED SECURITY INCIDENT REPORT",
                styles["SOCHeaderSub"]
            )
        ]

        header = Table(
            [[header_content]],
            colWidths=[174 * mm]
        )

        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), NAVY),
            ("BOX", (0, 0), (-1, -1), 0.8, NAVY),

            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),

            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),

            ("TOPPADDING", (0, 0), (-1, -1), 21),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 21),
        ]))

        story.append(header)
        story.append(Spacer(1, 12))

        # --------------------------------------------------
        # 2. ALERT BANNER
        # --------------------------------------------------

        if critical:

            banner_title = "CRITICAL ALERT"
            banner_subtitle = "IMMEDIATE ANALYST ATTENTION REQUIRED"
            banner_color = RED

        else:

            banner_title = "SECURITY ALERT"
            banner_subtitle = "SECURITY EVENT REQUIRING REVIEW"
            banner_color = BLUE

        banner_content = [
            Paragraph(
                safe(banner_title),
                styles["SOCBanner"]
            ),
            Spacer(1, 4),
            Paragraph(
                safe(banner_subtitle),
                styles["SOCBannerSub"]
            )
        ]

        banner = Table(
            [[banner_content]],
            colWidths=[174 * mm]
        )

        banner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), banner_color),

            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),

            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),

            ("TOPPADDING", (0, 0), (-1, -1), 18),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ]))

        story.append(banner)
        story.append(Spacer(1, 13))

        # --------------------------------------------------
        # 3. SEVERITY PANEL
        # --------------------------------------------------

        story.append(
            create_severity_panel(
                alert,
                styles,
                critical
            )
        )

        story.append(Spacer(1, 13))

        # --------------------------------------------------
        # 4. INCIDENT INFORMATION
        # --------------------------------------------------

        story.append(
            Paragraph(
                "INCIDENT INFORMATION",
                styles["SOCSection"]
            )
        )

        generated_time = datetime.now().astimezone().strftime(
            "%d %B %Y, %I:%M:%S %p %Z"
        )

        metadata = [
            ["Report ID", report_id],
            ["Unique Alert ID", alert["alert_id"]],
            ["Wazuh Index", alert["index_name"]],
            ["Alert Timestamp", alert["alert_timestamp"]],
            ["Report Generated", generated_time],
            ["Processing Status", "AI ANALYSED"]
        ]

        story.append(
            create_metadata_table(
                metadata,
                styles
            )
        )

        story.append(Spacer(1, 8))

        # --------------------------------------------------
        # 5. AI ANALYSIS
        # --------------------------------------------------

        story.append(
            Paragraph(
                "AI SECURITY ANALYSIS",
                styles["SOCSection"]
            )
        )

        add_ai_analysis(
            story,
            alert["ai_analysis"],
            styles
        )

        # --------------------------------------------------
        # 6. DISCLAIMER
        # --------------------------------------------------

        story.append(Spacer(1, 13))

        disclaimer_text = (
            "<b>IMPORTANT SECURITY DISCLAIMER</b><br/><br/>"
            "This report contains AI-assisted analysis of original "
            "Wazuh alert evidence. The original Wazuh rule ID and "
            "rule level are preserved. AI recommendations are "
            "advisory and must be verified by a qualified analyst "
            "before remediation. No security action is automatically "
            "executed by this report generator."
        )

        disclaimer = Table(
            [[
                Paragraph(
                    disclaimer_text,
                    styles["SOCDisclaimer"]
                )
            ]],
            colWidths=[174 * mm]
        )

        disclaimer.setStyle(TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                LIGHT_RED if critical else LIGHT_BLUE
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.9,
                RED if critical else BLUE
            ),

            ("VALIGN", (0, 0), (-1, -1), "TOP"),

            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),

            ("TOPPADDING", (0, 0), (-1, -1), 11),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
        ]))

        story.append(disclaimer)

        # --------------------------------------------------
        # 7. BUILD PDF
        # --------------------------------------------------

        doc.build(
            story,
            onFirstPage=draw_page,
            onLaterPages=draw_page
        )

        print("\n========== SOC PDF GENERATED ==========")
        print(f"Report ID : {report_id}")
        print(f"Alert ID  : {alert['alert_id']}")
        print(f"Rule ID   : {alert['rule_id']}")
        print(f"Rule Level: {rule_level}")

        if critical:
            print("Design    : RED CRITICAL ALERT")
        else:
            print("Design    : BLUE SECURITY REPORT")

        print(f"PDF       : {filepath}")
        print("Status    : SUCCESS")
        print("=======================================\n")

        return filepath

    finally:

        connection.close()


# ==========================================================
# EXECUTION
# ==========================================================

if __name__ == "__main__":

    try:

        generate_report()

    except Exception as error:

        print("\n[PDF GENERATION ERROR]")
        print(f"{type(error).__name__}: {error}")
