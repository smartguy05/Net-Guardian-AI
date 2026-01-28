"""Email notification service using SMTP."""

from datetime import UTC, datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import aiosmtplib
import structlog

from app.config import settings

logger = structlog.get_logger()


class EmailService:
    """Service for sending email notifications.

    Uses async SMTP to send email notifications for alerts,
    anomalies, and device quarantine events.
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        use_tls: bool | None = None,
        sender_email: str | None = None,
        sender_name: str | None = None,
    ):
        """Initialize the email service.

        Args:
            host: SMTP server hostname.
            port: SMTP server port.
            username: SMTP username.
            password: SMTP password.
            use_tls: Whether to use TLS.
            sender_email: Sender email address.
            sender_name: Sender display name.
        """
        self.host = host or settings.smtp_host
        self.port = port or settings.smtp_port
        self.username = username or settings.smtp_username
        self.password = password or settings.smtp_password
        self.use_tls = use_tls if use_tls is not None else settings.smtp_use_tls
        self.sender_email = sender_email or settings.smtp_sender_email
        self.sender_name = sender_name or settings.smtp_sender_name

    @property
    def is_configured(self) -> bool:
        """Check if SMTP is properly configured."""
        return bool(self.host and self.sender_email)

    async def send_email(
        self,
        to_email: str,
        subject: str,
        body_html: str,
        body_text: str | None = None,
    ) -> bool:
        """Send an email.

        Args:
            to_email: Recipient email address.
            subject: Email subject.
            body_html: HTML body content.
            body_text: Plain text body (optional fallback).

        Returns:
            True if email was sent successfully.
        """
        if not self.is_configured:
            logger.warning("SMTP not configured, skipping email")
            return False

        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.sender_name} <{self.sender_email}>" if self.sender_name else self.sender_email
            msg["To"] = to_email

            # Add plain text part
            if body_text:
                msg.attach(MIMEText(body_text, "plain"))

            # Add HTML part
            msg.attach(MIMEText(body_html, "html"))

            # Send email
            smtp_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "use_tls": self.use_tls,
            }

            if self.username and self.password:
                smtp_kwargs["username"] = self.username
                smtp_kwargs["password"] = self.password

            await aiosmtplib.send(msg, **smtp_kwargs)

            logger.info(
                "Email sent",
                to=to_email,
                subject=subject,
            )
            return True

        except Exception as e:
            logger.error(
                "Failed to send email",
                to=to_email,
                subject=subject,
                error=str(e),
            )
            return False

    async def send_alert_notification(
        self,
        to_email: str,
        alert_title: str,
        alert_description: str,
        severity: str,
        device_name: str | None = None,
        alert_id: str | None = None,
    ) -> bool:
        """Send an alert notification email.

        Args:
            to_email: Recipient email address.
            alert_title: Title of the alert.
            alert_description: Description of the alert.
            severity: Alert severity (critical, high, medium, low).
            device_name: Name of the affected device.
            alert_id: ID of the alert.

        Returns:
            True if email was sent successfully.
        """
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#2563eb",
        }
        color = severity_colors.get(severity.lower(), "#6b7280")

        subject = f"[NetGuardian {severity.upper()}] {alert_title}"

        body_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: {color}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }}
                .severity {{ display: inline-block; padding: 4px 12px; border-radius: 20px; color: white; background: {color}; font-size: 12px; font-weight: bold; }}
                .detail {{ margin: 10px 0; }}
                .label {{ font-weight: bold; color: #6b7280; }}
                .footer {{ margin-top: 20px; font-size: 12px; color: #9ca3af; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0;">NetGuardian AI Alert</h1>
                </div>
                <div class="content">
                    <div style="margin-bottom: 15px;">
                        <span class="severity">{severity.upper()}</span>
                    </div>
                    <h2 style="margin-top: 0;">{alert_title}</h2>
                    <p>{alert_description}</p>
                    {f'<div class="detail"><span class="label">Device:</span> {device_name}</div>' if device_name else ''}
                    {f'<div class="detail"><span class="label">Alert ID:</span> {alert_id}</div>' if alert_id else ''}
                    <div class="detail"><span class="label">Time:</span> {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
                </div>
                <div class="footer">
                    This is an automated message from NetGuardian AI.
                </div>
            </div>
        </body>
        </html>
        """

        body_text = f"""
NetGuardian AI Alert - {severity.upper()}

{alert_title}

{alert_description}

{'Device: ' + device_name if device_name else ''}
{'Alert ID: ' + alert_id if alert_id else ''}
Time: {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}

This is an automated message from NetGuardian AI.
        """

        return await self.send_email(to_email, subject, body_html, body_text)

    async def send_anomaly_notification(
        self,
        to_email: str,
        anomaly_type: str,
        description: str,
        device_name: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> bool:
        """Send an anomaly detection notification email."""
        subject = f"[NetGuardian] Anomaly Detected: {anomaly_type}"

        details_html = ""
        if details:
            details_html = "<ul>"
            for key, value in details.items():
                details_html += f"<li><strong>{key}:</strong> {value}</li>"
            details_html += "</ul>"

        body_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: #f59e0b; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }}
                .footer {{ margin-top: 20px; font-size: 12px; color: #9ca3af; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0;">Anomaly Detected</h1>
                </div>
                <div class="content">
                    <h2 style="margin-top: 0;">{anomaly_type}</h2>
                    <p>{description}</p>
                    {f'<p><strong>Device:</strong> {device_name}</p>' if device_name else ''}
                    {details_html}
                    <p><strong>Time:</strong> {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
                </div>
                <div class="footer">
                    This is an automated message from NetGuardian AI.
                </div>
            </div>
        </body>
        </html>
        """

        return await self.send_email(to_email, subject, body_html)

    async def send_quarantine_notification(
        self,
        to_email: str,
        device_name: str,
        action: str,  # "quarantined" or "released"
        reason: str | None = None,
        performed_by: str | None = None,
    ) -> bool:
        """Send a device quarantine/release notification email."""
        is_quarantine = action.lower() == "quarantined"
        subject = f"[NetGuardian] Device {action.title()}: {device_name}"

        color = "#dc2626" if is_quarantine else "#16a34a"
        action_text = "quarantined" if is_quarantine else "released from quarantine"

        body_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: {color}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }}
                .footer {{ margin-top: 20px; font-size: 12px; color: #9ca3af; text-align: center; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0;">Device {action.title()}</h1>
                </div>
                <div class="content">
                    <p>The device <strong>{device_name}</strong> has been {action_text}.</p>
                    {f'<p><strong>Reason:</strong> {reason}</p>' if reason else ''}
                    {f'<p><strong>Performed by:</strong> {performed_by}</p>' if performed_by else ''}
                    <p><strong>Time:</strong> {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
                </div>
                <div class="footer">
                    This is an automated message from NetGuardian AI.
                </div>
            </div>
        </body>
        </html>
        """

        return await self.send_email(to_email, subject, body_html)

    async def test_connection(self) -> dict[str, Any]:
        """Test SMTP connection.

        Returns:
            Dict with success status and any error message.
        """
        if not self.is_configured:
            return {
                "success": False,
                "error": "SMTP not configured",
            }

        try:
            smtp_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "use_tls": self.use_tls,
            }

            if self.username and self.password:
                smtp_kwargs["username"] = self.username
                smtp_kwargs["password"] = self.password

            async with aiosmtplib.SMTP(**smtp_kwargs) as smtp:
                await smtp.noop()

            return {
                "success": True,
                "message": f"Successfully connected to {self.host}:{self.port}",
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }


# Global service instance
_email_service: EmailService | None = None


def get_email_service() -> EmailService:
    """Get the global email service instance."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
