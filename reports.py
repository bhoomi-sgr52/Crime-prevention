"""
Sentinel Watch - Report Generation Module
==========================================
Generates PDF reports for individual selected incidents.

Features:
- Incident details and detected objects
- Confidence and potential security risk score
- Alert status
- Evidence screenshot embedding
- Compatibility with generate_activity_pdf()
"""

import os
import re
import json
import logging
from io import BytesIO
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image as PILImage, ImageStat

from config import Config
import database

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    Table,
    TableStyle,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


logger = logging.getLogger("sentinel.reports")


# ============================================================
# Helpers
# ============================================================

def _safe_filename(text):
    cleaned = re.sub(r"[^\w\s-]", "", str(text or ""))
    cleaned = re.sub(r"\s+", "_", cleaned.strip())
    return cleaned[:60] or "incident"


def _row_val(row, key, default=""):
    """Read a value from sqlite3.Row or a dictionary."""
    try:
        value = row[key]
        return default if value is None else value
    except (KeyError, IndexError, TypeError):
        return default


def _pdf_text(value):
    """Escape text for safe insertion into ReportLab paragraphs."""
    return escape(str(value if value is not None else ""))


def _parse_objects(value):
    """Convert the detected_objects database value to a readable string."""
    if value is None:
        return "N/A"

    try:
        if isinstance(value, str):
            stripped = value.strip()

            if not stripped:
                return "N/A"

            if stripped.startswith("["):
                parsed = json.loads(stripped)
                return ", ".join(map(str, parsed)) if parsed else "N/A"

            if stripped.startswith("{"):
                parsed = json.loads(stripped)
                return ", ".join(map(str, parsed.values())) if parsed else "N/A"

            return stripped

        if isinstance(value, (list, tuple, set)):
            return ", ".join(map(str, value)) if value else "N/A"

        return str(value)

    except (ValueError, TypeError):
        return str(value)


# ============================================================
# PDF Styles
# ============================================================

def _build_styles():
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SWTitle",
        parent=styles["Heading1"],
        fontSize=21,
        leading=26,
        textColor=colors.HexColor("#8B0000"),
        alignment=1,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "SWSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.grey,
        alignment=1,
        spaceAfter=18,
    )

    section_style = ParagraphStyle(
        "SWSection",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#17365D"),
        spaceBefore=12,
        spaceAfter=7,
    )

    return styles, title_style, subtitle_style, section_style


# ============================================================
# Detection Details Table
# ============================================================

def _detection_table(incident):
    objects_text = _parse_objects(
        _row_val(incident, "detected_objects", "[]")
    )

    raw_confidence = _row_val(incident, "confidence", None)

    try:
        confidence_text = (
            f"{float(raw_confidence) * 100:.2f}%"
            if raw_confidence is not None
            else "N/A"
        )
    except (TypeError, ValueError):
        confidence_text = "N/A"

    raw_score = _row_val(incident, "threat_score", None)

    try:
        score_text = f"{float(raw_score):.0f}/100" if raw_score is not None else "N/A"
    except (TypeError, ValueError):
        score_text = "N/A"

    data = [
        ["Detection ID", _pdf_text(_row_val(incident, "id", "N/A"))],
        ["Date", _pdf_text(_row_val(incident, "date", "N/A"))],
        ["Time", _pdf_text(_row_val(incident, "time", "N/A"))],
        ["Activity", _pdf_text(_row_val(incident, "activity", "N/A"))],
        ["Detected Objects", _pdf_text(objects_text)],
        ["Confidence", _pdf_text(confidence_text)],
        ["Potential Security Risk Score", _pdf_text(score_text)],
        ["Threat Level", _pdf_text(_row_val(incident, "threat_level", "N/A"))],
        ["Alert Status", _pdf_text(_row_val(incident, "alert_status", "N/A"))],
    ]

    table = Table(data, colWidths=[175, 325], repeatRows=0)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF0F6")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("LEADING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B8C2CC")),
    ]))

    return table


# ============================================================
# Screenshot Path Resolution
# ============================================================

def _resolve_screenshot_path(screenshot_path):
    if not screenshot_path:
        return None

    raw_path = str(screenshot_path).strip()

    if not raw_path:
        return None

    try:
        path = Path(raw_path)

        # Absolute path stored in the database.
        if path.is_absolute():
            return path.resolve()

        # Relative path such as screenshots/incident.jpg.
        normalized = raw_path.replace("\\", os.sep).replace("/", os.sep)
        candidate = (Path(Config.BASE_DIR) / normalized).resolve()

        if candidate.is_file():
            return candidate

        # Some older records may store only the filename.
        filename_candidate = (
            Path(Config.SCREENSHOTS_DIR) / Path(normalized).name
        ).resolve()

        if filename_candidate.is_file():
            return filename_candidate

        return candidate

    except (TypeError, ValueError, OSError):
        logger.exception("Unable to resolve screenshot path: %s", raw_path)
        return None


# ============================================================
# Evidence Screenshot
# ============================================================

def _screenshot_elements(incident, styles):
    elements = []

    stored_path = _row_val(incident, "screenshot_path", "")
    image_path = _resolve_screenshot_path(stored_path)

    elements.append(
        Paragraph("Evidence Screenshot", styles["Heading2"])
    )

    if image_path is None or not image_path.is_file():
        logger.warning("Screenshot is missing for incident %s", _row_val(incident, "id", "?"))
        elements.append(
            Paragraph(
                "<i>Evidence screenshot is not available for this incident.</i>",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 12))
        return elements

    image_buffer = None

    try:
        # Fully decode the original screenshot and normalize its mode.
        with PILImage.open(image_path) as source:
            source.load()
            rgb_image = source.convert("RGB")

        if rgb_image.width < 1 or rgb_image.height < 1:
            raise ValueError("Screenshot has invalid dimensions.")

        # Log black images so the original capture problem can be investigated.
        stats = ImageStat.Stat(rgb_image)
        if max(stats.mean) < 2:
            logger.warning(
                "Screenshot is nearly black. The issue may be in camera capture: %s",
                image_path,
            )

        # Re-encode to a standard JPEG in memory for ReportLab.
        image_buffer = BytesIO()
        rgb_image.save(image_buffer, format="JPEG", quality=95)
        image_buffer.seek(0)

        pdf_image = Image(image_buffer, hAlign="CENTER")

        max_width = 6.2 * inch
        max_height = 6.0 * inch

        aspect_ratio = pdf_image.imageWidth / float(pdf_image.imageHeight)

        draw_width = max_width
        draw_height = draw_width / aspect_ratio

        if draw_height > max_height:
            draw_height = max_height
            draw_width = draw_height * aspect_ratio

        pdf_image.drawWidth = draw_width
        pdf_image.drawHeight = draw_height

        elements.append(
            Paragraph(
                f"<font size='8'>File: {_pdf_text(image_path.name)}</font>",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 6))
        elements.append(pdf_image)

        # Retain the in-memory image data until doc.build() completes.
        pdf_image._sentinelwatch_buffer = image_buffer

        logger.info(
            "Evidence screenshot embedded for incident %s: %s",
            _row_val(incident, "id", "?"),
            image_path,
        )

    except Exception:
        logger.exception("Failed to embed screenshot: %s", image_path)
        elements.append(
            Paragraph(
                "<i>The screenshot could not be decoded or embedded.</i>",
                styles["Normal"],
            )
        )

    elements.append(Spacer(1, 15))
    return elements


# ============================================================
# Generate PDF for One Selected Incident
# ============================================================

def generate_incident_pdf(incident_id, generated_by="System"):
    """
    Generate a PDF for one selected incident.

    Returns the absolute path to the generated PDF.
    """

    conn = None

    try:
        incident = database.get_incident_by_id(incident_id)

        if not incident:
            raise ValueError(f"Incident {incident_id} was not found.")

        # Retrieve the latest alert status if available.
        alert_status = "N/A"

        try:
            conn = database.get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT alert_status
                FROM alerts
                WHERE detection_id = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (incident_id,),
            )

            alert_row = cursor.fetchone()

            if alert_row:
                alert_status = _row_val(alert_row, "alert_status", "N/A")

        except Exception:
            logger.exception(
                "Could not retrieve alert status for incident %s",
                incident_id,
            )

        finally:
            if conn is not None:
                try:
                    database.close_connection(conn)
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass

        # Add alert status to the report data without modifying the database.
        class IncidentView:
            def __init__(self, source, status):
                self.source = source
                self.status = status

            def __getitem__(self, key):
                if key == "alert_status":
                    return self.status
                return self.source[key]

        report_incident = IncidentView(incident, alert_status)

        reports_dir = Path(Config.REPORTS_DIR)
        reports_dir.mkdir(parents=True, exist_ok=True)

        incident_date = _safe_filename(
            _row_val(incident, "date", datetime.now().strftime("%Y-%m-%d"))
        )

        filename = (
            f"SentinelWatch_Incident_{_safe_filename(incident_id)}_"
            f"{incident_date}.pdf"
        )

        filepath = reports_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=45,
            bottomMargin=45,
            title=f"Sentinel Watch Incident {incident_id}",
            author="Sentinel Watch",
        )

        styles, title_style, subtitle_style, section_style = _build_styles()

        elements = [
            Paragraph("SENTINEL WATCH", title_style),
            Paragraph(
                "POTENTIAL SECURITY RISK ESTIMATE REPORT",
                subtitle_style,
            ),
            Spacer(1, 8),
            Paragraph(
                f"<b>Incident ID:</b> {_pdf_text(incident_id)}",
                styles["Normal"],
            ),
            Paragraph(
                f"<b>Generated by:</b> {_pdf_text(generated_by)}",
                styles["Normal"],
            ),
            Paragraph(
                f"<b>Report generated:</b> "
                f"{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
                styles["Normal"],
            ),
            Spacer(1, 14),
            Paragraph("Incident Details", section_style),
            _detection_table(report_incident),
            Spacer(1, 10),
        ]

        elements.extend(_screenshot_elements(report_incident, styles))

        elements.extend([
            Paragraph("Important Note", section_style),
            Paragraph(
                "This report records a potential security risk identified by "
                "the Sentinel Watch system. Detection of an object does not "
                "establish criminal intent or prove that a crime has occurred. "
                "The incident should be reviewed by authorized personnel.",
                styles["Normal"],
            ),
        ])

        doc.build(elements)

        if not filepath.is_file() or filepath.stat().st_size == 0:
            raise RuntimeError("The PDF report was not created successfully.")

        logger.info("Incident PDF generated: %s", filepath)
        return str(filepath.resolve())

    except Exception:
        logger.exception(
            "Report generation failed for incident %s",
            incident_id,
        )
        raise


# ============================================================
# Compatibility Function Expected by the Website
# ============================================================

def generate_activity_pdf(incident_id, generated_by="System", **kwargs):
    """
    Compatibility wrapper for the existing website.

    Despite the legacy function name, this generates a PDF for
    one selected incident, not a report of all activity.
    """
    if incident_id is None:
        incident_id = kwargs.get("detection_id")

    if incident_id is None:
        raise ValueError("A selected incident ID is required.")

    return generate_incident_pdf(
        incident_id=incident_id,
        generated_by=generated_by,
    )