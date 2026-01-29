"""AdGuard Home query log parser."""

from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("adguard")
class AdGuardParser(BaseParser):
    """Parser for AdGuard Home query log API responses.

    Handles the JSON response from /control/querylog endpoint.
    """

    def _parse_timestamp(self, time_str: str) -> datetime:
        """Parse AdGuard timestamp format."""
        try:
            # AdGuard uses RFC 3339 / ISO 8601 format
            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.now(UTC)

    def _determine_severity(self, entry: dict[str, Any]) -> EventSeverity:
        """Determine event severity based on the query result."""
        reason = entry.get("reason", "")

        # Blocked queries are warnings
        if reason in ("FilteredBlackList", "FilteredSafeBrowsing",
                      "FilteredParental", "FilteredBlockedService"):
            return EventSeverity.WARNING

        # Safe search rewrites are informational
        if reason == "FilteredSafeSearch":
            return EventSeverity.INFO

        return EventSeverity.INFO

    def _determine_action(self, entry: dict[str, Any]) -> str:
        """Determine the action taken on the query."""
        reason = entry.get("reason", "")

        reason_actions = {
            "NotFilteredNotFound": "allowed",
            "NotFilteredWhiteList": "allowed",
            "NotFilteredError": "error",
            "FilteredBlackList": "blocked",
            "FilteredSafeBrowsing": "blocked",
            "FilteredParental": "blocked",
            "FilteredInvalid": "blocked",
            "FilteredSafeSearch": "rewritten",
            "FilteredBlockedService": "blocked",
            "Rewrite": "rewritten",
            "RewriteEtcHosts": "rewritten",
            "RewriteRule": "rewritten",
        }

        return reason_actions.get(reason, "unknown")

    def _get_response_status(self, entry: dict[str, Any]) -> str:
        """Get the response status for the query."""
        reason = entry.get("reason", "")

        if reason.startswith("Filtered"):
            return "blocked"
        elif reason.startswith("Rewrite"):
            return "rewritten"
        elif reason.startswith("NotFiltered"):
            return "allowed"

        return "unknown"

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse AdGuard Home query log data.

        Args:
            raw_data: Either the full API response dict or list of log entries.
        """
        results = []

        # Handle different input formats
        if isinstance(raw_data, dict):
            # Full API response
            entries = raw_data.get("data", [])
        elif isinstance(raw_data, list):
            entries = raw_data
        else:
            logger.warning("adguard_invalid_data", data_type=type(raw_data).__name__)
            return []

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            try:
                # Extract core fields
                timestamp = self._parse_timestamp(entry.get("time", ""))
                question = entry.get("question", {})
                answer = entry.get("answer", [])

                domain = question.get("name", "").rstrip(".")
                query_type = question.get("type", "")
                client_ip = entry.get("client", "")

                # Extract answer IPs if present
                answer_ips = []
                for ans in answer:
                    if isinstance(ans, dict):
                        value = ans.get("value", "")
                        if value:
                            answer_ips.append(value)

                # Build parsed fields
                parsed_fields = {
                    "query_type": query_type,
                    "answer": answer,
                    "answer_ips": answer_ips,
                    "reason": entry.get("reason", ""),
                    "upstream": entry.get("upstream", ""),
                    "elapsed_ms": entry.get("elapsedMs"),
                    "cached": entry.get("cached", False),
                    "rules": entry.get("rules", []),
                    "service_name": entry.get("serviceName"),
                    "client_info": entry.get("client_info", {}),
                }

                # Determine target IP (first answer IP if available)
                target_ip = answer_ips[0] if answer_ips else None

                result = ParseResult(
                    timestamp=timestamp,
                    event_type=EventType.DNS,
                    severity=self._determine_severity(entry),
                    raw_message=f"{client_ip} -> {domain} ({query_type})",
                    client_ip=client_ip,
                    target_ip=target_ip,
                    domain=domain,
                    port=53,
                    protocol="DNS",
                    action=self._determine_action(entry),
                    response_status=self._get_response_status(entry),
                    parsed_fields=parsed_fields,
                )
                results.append(result)

            except Exception as e:
                logger.warning(
                    "adguard_entry_parse_error",
                    error=str(e),
                    entry=str(entry)[:200],
                )

        return results
