"""ntfy.sh notification service for push notifications."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()


class NtfyService:
    """Service for sending push notifications via ntfy.sh.

    Supports both the public ntfy.sh server and self-hosted instances.
    """

    def __init__(
        self,
        server_url: Optional[str] = None,
        default_topic: Optional[str] = None,
        auth_token: Optional[str] = None,
    ):
        """Initialize the ntfy service.

        Args:
            server_url: ntfy server URL (e.g., https://ntfy.sh).
            default_topic: Default topic for notifications.
            auth_token: Optional authentication token for private topics.
        """
        self.server_url = (server_url or settings.ntfy_server_url).rstrip("/")
        self.default_topic = default_topic or settings.ntfy_default_topic
        self.auth_token = auth_token or settings.ntfy_auth_token

    @property
    def is_configured(self) -> bool:
        """Check if ntfy is properly configured."""
        return bool(self.server_url and self.default_topic)

    async def send_notification(
        self,
        message: str,
        title: Optional[str] = None,
        topic: Optional[str] = None,
        priority: int = 3,
        tags: Optional[list[str]] = None,
        click_url: Optional[str] = None,
        actions: Optional[list[Dict[str, Any]]] = None,
    ) -> bool:
        """Send a notification via ntfy.

        Args:
            message: Notification message body.
            title: Optional notification title.
            topic: Topic to send to (uses default if not specified).
            priority: Priority 1-5 (1=min, 3=default, 5=max/urgent).
            tags: List of emoji tags (e.g., ["warning", "skull"]).
            click_url: URL to open when notification is clicked.
            actions: List of action buttons.

        Returns:
            True if notification was sent successfully.
        """
        if not self.is_configured:
            logger.warning("ntfy not configured, skipping notification")
            return False

        topic = topic or self.default_topic
        url = f"{self.server_url}/{topic}"

        headers = {
            "Content-Type": "text/plain",
        }

        if title:
            headers["Title"] = title

        if priority != 3:
            headers["Priority"] = str(priority)

        if tags:
            headers["Tags"] = ",".join(tags)

        if click_url:
            headers["Click"] = click_url

        if actions:
            # Format actions as per ntfy spec
            action_strs = []
            for action in actions:
                action_type = action.get("type", "view")
                label = action.get("label", "Open")
                action_url = action.get("url", "")
                action_strs.append(f"{action_type}, {label}, {action_url}")
            headers["Actions"] = "; ".join(action_strs)

        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    content=message,
                    headers=headers,
                    timeout=10,
                )
                response.raise_for_status()

            logger.info(
                "ntfy notification sent",
                topic=topic,
                title=title,
            )
            return True

        except Exception as e:
            logger.error(
                "Failed to send ntfy notification",
                topic=topic,
                error=str(e),
            )
            return False

    async def send_alert_notification(
        self,
        alert_title: str,
        alert_description: str,
        severity: str,
        topic: Optional[str] = None,
        device_name: Optional[str] = None,
        alert_id: Optional[str] = None,
    ) -> bool:
        """Send an alert notification.

        Args:
            alert_title: Title of the alert.
            alert_description: Description of the alert.
            severity: Alert severity (critical, high, medium, low).
            topic: Override topic.
            device_name: Name of the affected device.
            alert_id: ID of the alert.

        Returns:
            True if notification was sent successfully.
        """
        # Map severity to priority and emoji
        severity_config = {
            "critical": {"priority": 5, "tags": ["rotating_light", "skull"]},
            "high": {"priority": 4, "tags": ["warning", "exclamation"]},
            "medium": {"priority": 3, "tags": ["orange_circle"]},
            "low": {"priority": 2, "tags": ["information_source"]},
        }
        config = severity_config.get(severity.lower(), {"priority": 3, "tags": []})

        title = f"[{severity.upper()}] {alert_title}"

        message_parts = [alert_description]
        if device_name:
            message_parts.append(f"Device: {device_name}")
        if alert_id:
            message_parts.append(f"Alert ID: {alert_id}")
        message_parts.append(f"Time: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")

        message = "\n".join(message_parts)

        return await self.send_notification(
            message=message,
            title=title,
            topic=topic,
            priority=config["priority"],
            tags=config["tags"],
        )

    async def send_anomaly_notification(
        self,
        anomaly_type: str,
        description: str,
        topic: Optional[str] = None,
        device_name: Optional[str] = None,
    ) -> bool:
        """Send an anomaly detection notification."""
        title = f"Anomaly Detected: {anomaly_type}"

        message_parts = [description]
        if device_name:
            message_parts.append(f"Device: {device_name}")
        message_parts.append(f"Time: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")

        message = "\n".join(message_parts)

        return await self.send_notification(
            message=message,
            title=title,
            topic=topic,
            priority=4,
            tags=["mag", "warning"],
        )

    async def send_quarantine_notification(
        self,
        device_name: str,
        action: str,  # "quarantined" or "released"
        topic: Optional[str] = None,
        reason: Optional[str] = None,
        performed_by: Optional[str] = None,
    ) -> bool:
        """Send a device quarantine/release notification."""
        is_quarantine = action.lower() == "quarantined"

        if is_quarantine:
            title = f"Device Quarantined: {device_name}"
            tags = ["no_entry", "lock"]
            priority = 4
        else:
            title = f"Device Released: {device_name}"
            tags = ["white_check_mark", "unlock"]
            priority = 3

        message_parts = [f"Device {device_name} has been {action}."]
        if reason:
            message_parts.append(f"Reason: {reason}")
        if performed_by:
            message_parts.append(f"By: {performed_by}")
        message_parts.append(f"Time: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")

        message = "\n".join(message_parts)

        return await self.send_notification(
            message=message,
            title=title,
            topic=topic,
            priority=priority,
            tags=tags,
        )

    async def test_connection(self, topic: Optional[str] = None) -> Dict[str, Any]:
        """Test ntfy connection by sending a test notification.

        Args:
            topic: Topic to test (uses default if not specified).

        Returns:
            Dict with success status and any error message.
        """
        if not self.is_configured:
            return {
                "success": False,
                "error": "ntfy not configured",
            }

        try:
            success = await self.send_notification(
                message="This is a test notification from NetGuardian AI.",
                title="NetGuardian Test",
                topic=topic,
                priority=2,
                tags=["test_tube", "white_check_mark"],
            )

            if success:
                return {
                    "success": True,
                    "message": f"Test notification sent to topic: {topic or self.default_topic}",
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to send test notification",
                }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }


# Global service instance
_ntfy_service: Optional[NtfyService] = None


def get_ntfy_service() -> NtfyService:
    """Get the global ntfy service instance."""
    global _ntfy_service
    if _ntfy_service is None:
        _ntfy_service = NtfyService()
    return _ntfy_service
