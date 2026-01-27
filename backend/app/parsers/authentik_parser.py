"""Authentik event log parser for /api/v3/events/ API responses."""

from datetime import datetime, timezone
from typing import Any, Dict, List

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("authentik")
class AuthentikParser(BaseParser):
    """Parser for Authentik /api/v3/events/ API responses.

    Handles both paginated responses {"results": [...]} and direct event lists.
    """

    # Map Authentik action types to severity levels
    ACTION_SEVERITY_MAP: Dict[str, EventSeverity] = {
        # Info-level events
        "login": EventSeverity.INFO,
        "logout": EventSeverity.INFO,
        "authorize_application": EventSeverity.INFO,
        "user_write": EventSeverity.INFO,
        "model_created": EventSeverity.INFO,
        "model_updated": EventSeverity.INFO,
        "model_deleted": EventSeverity.INFO,
        "token_view": EventSeverity.INFO,
        "invitation_used": EventSeverity.INFO,
        "password_set": EventSeverity.INFO,
        "secret_view": EventSeverity.INFO,
        "secret_rotate": EventSeverity.INFO,
        "flow_execution": EventSeverity.INFO,
        "policy_execution": EventSeverity.INFO,
        "stage_execution": EventSeverity.INFO,

        # Warning-level events
        "login_failed": EventSeverity.WARNING,
        "policy_exception": EventSeverity.WARNING,
        "property_mapping_exception": EventSeverity.WARNING,
        "impersonation_started": EventSeverity.WARNING,
        "impersonation_ended": EventSeverity.WARNING,
        "reputation_calculation": EventSeverity.WARNING,
        "configuration_error": EventSeverity.WARNING,
        "email_sent": EventSeverity.INFO,

        # Error-level events
        "suspicious_request": EventSeverity.ERROR,
        "update_available": EventSeverity.WARNING,
        "source_linked": EventSeverity.INFO,
        "source_unlinked": EventSeverity.INFO,
        "system_exception": EventSeverity.ERROR,
        "system_task_exception": EventSeverity.ERROR,
    }

    # Actions that indicate potential security issues
    SECURITY_ACTIONS = {
        "login_failed",
        "suspicious_request",
        "impersonation_started",
        "policy_exception",
    }

    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse Authentik timestamp format."""
        if isinstance(timestamp, datetime):
            return timestamp

        if isinstance(timestamp, str):
            try:
                # Authentik uses ISO 8601 format
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        return datetime.now(timezone.utc)

    def _determine_severity(self, action: str) -> EventSeverity:
        """Determine event severity based on action type."""
        return self.ACTION_SEVERITY_MAP.get(action, EventSeverity.INFO)

    def _extract_client_ip(self, event: Dict) -> str | None:
        """Extract client IP from event context."""
        context = event.get("context", {})

        # Try different context paths where IP might be stored
        http_request = context.get("http_request", {})
        if http_request:
            ip = http_request.get("client_ip") or http_request.get("args", {}).get("client_ip")
            if ip:
                return ip

        # Direct context field
        if context.get("client_ip"):
            return context["client_ip"]

        # Check geo context
        geo = context.get("geo", {})
        if geo.get("ip"):
            return geo["ip"]

        return None

    def _build_message(self, event: Dict) -> str:
        """Build a descriptive message from the event."""
        action = event.get("action", "unknown")
        user = event.get("user", {})
        username = user.get("username", "system") if user else "system"
        context = event.get("context", {})

        # Build descriptive message based on action type
        if action == "login":
            return f"User {username} logged in"
        elif action == "login_failed":
            reason = context.get("message", "authentication failed")
            return f"Login failed for {username}: {reason}"
        elif action == "logout":
            return f"User {username} logged out"
        elif action == "authorize_application":
            app = context.get("authorized_application", {}).get("name", "unknown")
            return f"User {username} authorized application: {app}"
        elif action == "impersonation_started":
            target = context.get("user", {}).get("username", "unknown")
            return f"User {username} started impersonating {target}"
        elif action == "impersonation_ended":
            return f"User {username} ended impersonation"
        elif action == "suspicious_request":
            return f"Suspicious request detected from {username}"
        elif action == "policy_exception":
            policy = context.get("expression", context.get("message", "unknown"))
            return f"Policy exception for {username}: {policy}"
        elif action.startswith("model_"):
            model = context.get("model", {}).get("app", "unknown")
            return f"{action.replace('_', ' ').title()}: {model}"
        elif action == "password_set":
            return f"Password set for user {username}"
        else:
            # Generic message
            return f"Authentik {action.replace('_', ' ')}: {username}"

    def _extract_action_result(self, event: Dict) -> str:
        """Extract action result (success/failure)."""
        action = event.get("action", "")
        context = event.get("context", {})

        # Failed actions
        if action in ("login_failed", "suspicious_request", "policy_exception"):
            return "blocked"

        # Check for explicit result in context
        result = context.get("result", context.get("status"))
        if result:
            return str(result).lower()

        # Assume success for completed events
        return "success"

    def parse(self, raw_data: Any) -> List[ParseResult]:
        """Parse Authentik event log data.

        Args:
            raw_data: Either the full API response dict or list of events.
        """
        results = []

        # Handle different input formats
        if isinstance(raw_data, dict):
            # Paginated API response: {"results": [...], "pagination": {...}}
            entries = raw_data.get("results", [])
        elif isinstance(raw_data, list):
            entries = raw_data
        else:
            logger.warning("authentik_invalid_data", data_type=type(raw_data).__name__)
            return []

        for event in entries:
            if not isinstance(event, dict):
                continue

            try:
                action = event.get("action", "unknown")
                timestamp = self._parse_timestamp(event.get("created", event.get("timestamp")))
                client_ip = self._extract_client_ip(event)

                # Extract user info
                user = event.get("user", {})
                username = user.get("username") if user else None

                # Build parsed fields with all event data
                parsed_fields = {
                    "action": action,
                    "pk": event.get("pk"),
                    "app": event.get("app"),
                    "user": user,
                    "context": event.get("context", {}),
                    "client_ip": client_ip,
                    "username": username,
                    "is_security_event": action in self.SECURITY_ACTIONS,
                }

                # Add geo data if present
                geo = event.get("context", {}).get("geo", {})
                if geo:
                    parsed_fields["geo"] = geo

                result = ParseResult(
                    timestamp=timestamp,
                    event_type=EventType.AUTH,
                    severity=self._determine_severity(action),
                    raw_message=self._build_message(event),
                    client_ip=client_ip,
                    target_ip=None,
                    domain=None,
                    port=None,
                    protocol="HTTPS",
                    action=self._extract_action_result(event),
                    response_status=action,
                    parsed_fields=parsed_fields,
                )
                results.append(result)

            except Exception as e:
                logger.warning(
                    "authentik_entry_parse_error",
                    error=str(e),
                    entry=str(event)[:200],
                )

        return results
