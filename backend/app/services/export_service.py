"""Export service for generating CSV and PDF reports."""

import csv
import io
from datetime import datetime
from typing import Any

import structlog
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = structlog.get_logger()


class ExportService:
    """Service for exporting data to CSV and PDF formats."""

    @staticmethod
    def to_csv(
        data: list[dict[str, Any]],
        columns: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        """Convert data to CSV format.

        Args:
            data: List of dictionaries to export.
            columns: Optional list of columns to include (in order).
            headers: Optional mapping of column names to display headers.

        Returns:
            CSV string.
        """
        if not data:
            return ""

        # Determine columns
        if columns is None:
            columns = list(data[0].keys())

        # Determine headers
        if headers is None:
            headers = {col: col for col in columns}

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header row
        writer.writerow([headers.get(col, col) for col in columns])

        # Write data rows
        for row in data:
            writer.writerow([
                ExportService._format_value(row.get(col))
                for col in columns
            ])

        return output.getvalue()

    @staticmethod
    def to_pdf(
        data: list[dict[str, Any]],
        title: str,
        columns: list[str] | None = None,
        headers: dict[str, str] | None = None,
        subtitle: str | None = None,
    ) -> bytes:
        """Convert data to PDF format.

        Args:
            data: List of dictionaries to export.
            title: PDF document title.
            columns: Optional list of columns to include (in order).
            headers: Optional mapping of column names to display headers.
            subtitle: Optional subtitle (e.g., date range, filters).

        Returns:
            PDF bytes.
        """
        buffer = io.BytesIO()

        # Use landscape for tables with many columns
        page_size = landscape(letter) if columns and len(columns) > 5 else letter

        doc = SimpleDocTemplate(
            buffer,
            pagesize=page_size,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        # Build content
        elements = []
        styles = getSampleStyleSheet()

        # Title
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=18,
            spaceAfter=6,
            textColor=colors.HexColor("#1e40af"),
        )
        elements.append(Paragraph(title, title_style))

        # Subtitle
        if subtitle:
            subtitle_style = ParagraphStyle(
                "CustomSubtitle",
                parent=styles["Normal"],
                fontSize=10,
                textColor=colors.gray,
                spaceAfter=12,
            )
            elements.append(Paragraph(subtitle, subtitle_style))

        # Generation timestamp
        timestamp_style = ParagraphStyle(
            "Timestamp",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.gray,
            spaceAfter=20,
        )
        elements.append(
            Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                timestamp_style,
            )
        )

        if not data:
            elements.append(Paragraph("No data available.", styles["Normal"]))
        else:
            # Determine columns
            if columns is None:
                columns = list(data[0].keys())

            # Determine headers
            if headers is None:
                headers = {col: col for col in columns}

            # Build table data
            table_data = [
                [headers.get(col, col) for col in columns]
            ]
            for row in data:
                table_data.append([
                    ExportService._format_value(row.get(col), max_length=50)
                    for col in columns
                ])

            # Calculate column widths
            available_width = page_size[0] - 1 * inch
            col_width = available_width / len(columns)

            # Create table
            table = Table(table_data, colWidths=[col_width] * len(columns))
            table.setStyle(TableStyle([
                # Header style
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("TOPPADDING", (0, 0), (-1, 0), 8),

                # Data style
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 1), (-1, -1), 6),
                ("TOPPADDING", (0, 1), (-1, -1), 6),

                # Grid
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),

                # Alternating row colors
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),

                # Alignment
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))

            elements.append(table)

            # Row count
            elements.append(Spacer(1, 12))
            count_style = ParagraphStyle(
                "RowCount",
                parent=styles["Normal"],
                fontSize=8,
                textColor=colors.gray,
            )
            elements.append(
                Paragraph(f"Total: {len(data)} records", count_style)
            )

        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer.read()

    @staticmethod
    def _format_value(value: Any, max_length: int | None = None) -> str:
        """Format a value for export.

        Args:
            value: Value to format.
            max_length: Optional maximum string length.

        Returns:
            Formatted string.
        """
        if value is None:
            return ""
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(value, bool):
            return "Yes" if value else "No"
        if isinstance(value, (list, dict)):
            result = str(value)
        else:
            result = str(value)

        if max_length and len(result) > max_length:
            result = result[: max_length - 3] + "..."

        return result


# Pre-defined column configurations for common exports
EVENTS_COLUMNS = ["timestamp", "event_type", "source_ip", "domain", "severity", "blocked"]
EVENTS_HEADERS = {
    "timestamp": "Timestamp",
    "event_type": "Type",
    "source_ip": "Source IP",
    "domain": "Domain",
    "severity": "Severity",
    "blocked": "Blocked",
}

ALERTS_COLUMNS = ["created_at", "title", "severity", "status", "device_hostname", "rule_name"]
ALERTS_HEADERS = {
    "created_at": "Created",
    "title": "Title",
    "severity": "Severity",
    "status": "Status",
    "device_hostname": "Device",
    "rule_name": "Rule",
}

DEVICES_COLUMNS = ["hostname", "mac_address", "ip_addresses", "device_type", "status", "first_seen", "last_seen"]
DEVICES_HEADERS = {
    "hostname": "Hostname",
    "mac_address": "MAC Address",
    "ip_addresses": "IP Addresses",
    "device_type": "Type",
    "status": "Status",
    "first_seen": "First Seen",
    "last_seen": "Last Seen",
}

AUDIT_COLUMNS = ["timestamp", "action", "username", "target_type", "target_name", "description", "success"]
AUDIT_HEADERS = {
    "timestamp": "Timestamp",
    "action": "Action",
    "username": "User",
    "target_type": "Target Type",
    "target_name": "Target",
    "description": "Description",
    "success": "Success",
}

ANOMALIES_COLUMNS = ["detected_at", "anomaly_type", "device_hostname", "severity", "description", "status"]
ANOMALIES_HEADERS = {
    "detected_at": "Detected",
    "anomaly_type": "Type",
    "device_hostname": "Device",
    "severity": "Severity",
    "description": "Description",
    "status": "Status",
}
