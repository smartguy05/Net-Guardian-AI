"""Custom regex-based parser for arbitrary log formats."""

import re
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("custom")
class CustomParser(BaseParser):
    """Regex-based parser for custom log formats.

    Configuration options:
        pattern: Regex pattern with named capture groups
        patterns: List of patterns to try (used if pattern not set)
        timestamp_field: Name of capture group containing timestamp
        timestamp_format: strptime format for timestamp
        event_type: Default event type
        severity_field: Name of capture group for severity
        severity_map: Map of severity strings to EventSeverity values
        field_map: Map of ParseResult fields to capture group names
        multiline_content_field: Field name to append continuation lines to (e.g., "message").
            When set and the input contains newlines after the first line, appends them
            to this field. Useful with file watcher's multiline_start_pattern.
    """

    DEFAULT_SEVERITY_MAP = {
        "debug": EventSeverity.DEBUG,
        "info": EventSeverity.INFO,
        "notice": EventSeverity.INFO,
        "warn": EventSeverity.WARNING,
        "warning": EventSeverity.WARNING,
        "error": EventSeverity.ERROR,
        "err": EventSeverity.ERROR,
        "crit": EventSeverity.CRITICAL,
        "critical": EventSeverity.CRITICAL,
        "alert": EventSeverity.CRITICAL,
        "emerg": EventSeverity.CRITICAL,
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)

        # Compile patterns
        self.patterns: list[re.Pattern[str]] = []

        if "pattern" in self.config:
            self.patterns.append(re.compile(self.config["pattern"]))
        elif "patterns" in self.config:
            for p in self.config["patterns"]:
                self.patterns.append(re.compile(p))
        else:
            # Default pattern that captures anything
            self.patterns.append(re.compile(r"^(?P<message>.*)$"))

        self.timestamp_field = self.config.get("timestamp_field", "timestamp")
        self.timestamp_format = self.config.get("timestamp_format")
        self.default_event_type = EventType(self.config.get("event_type", EventType.UNKNOWN.value))
        self.severity_field = self.config.get("severity_field", "severity")
        self.severity_map: dict[str, EventSeverity] = {
            **self.DEFAULT_SEVERITY_MAP,
            **self.config.get("severity_map", {}),
        }
        self.field_map = self.config.get("field_map", {})
        # For multi-line log support: append continuation lines to this field
        self.multiline_content_field = self.config.get("multiline_content_field")

    def _parse_timestamp(self, value: str | None) -> datetime:
        """Parse timestamp string to datetime."""
        if not value:
            return datetime.now(UTC)

        try:
            if self.timestamp_format:
                dt = datetime.strptime(value, self.timestamp_format)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            else:
                # Try ISO format
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass

        # Try common formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            except ValueError:
                continue

        return datetime.now(UTC)

    def _get_severity(self, groups: dict[str, Any]) -> EventSeverity:
        """Get severity from captured groups."""
        severity_value = groups.get(self.severity_field)
        if severity_value:
            severity_str = str(severity_value).lower()
            severity = self.severity_map.get(severity_str)
            if severity is not None:
                return severity
        return EventSeverity.INFO

    def _map_field(self, groups: dict[str, Any], field: str) -> Any | None:
        """Get a field value using the field map."""
        # Check field map first
        if field in self.field_map:
            mapped_name = self.field_map[field]
            if mapped_name in groups:
                return groups[mapped_name]

        # Fall back to direct group name
        return groups.get(field)

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse log lines using configured regex patterns.

        For multi-line entries (containing newlines), the regex is matched against
        the first line. If multiline_content_field is configured, continuation
        lines are appended to that field.
        """
        results = []

        # Handle string or list input
        if isinstance(raw_data, str):
            lines = raw_data.strip().split("\n")
        elif isinstance(raw_data, list):
            lines = raw_data
        else:
            lines = [str(raw_data)]

        for entry in lines:
            entry = entry.strip()
            if not entry:
                continue

            # Split entry into first line and continuation lines
            # This handles multi-line log entries (e.g., with stack traces)
            if "\n" in entry:
                first_line, continuation = entry.split("\n", 1)
                first_line = first_line.strip()
                continuation = continuation.rstrip()
            else:
                first_line = entry
                continuation = None

            # Try each pattern until one matches (against first line only)
            matched = False
            for pattern in self.patterns:
                match = pattern.match(first_line)
                if match:
                    try:
                        groups = match.groupdict()

                        # Parse timestamp
                        timestamp_str = groups.get(self.timestamp_field)
                        timestamp = self._parse_timestamp(timestamp_str)

                        # Append continuation lines to specified field if configured
                        if continuation and self.multiline_content_field:
                            field_value = groups.get(self.multiline_content_field, "")
                            if field_value:
                                groups[self.multiline_content_field] = (
                                    f"{field_value}\n{continuation}"
                                )
                            else:
                                groups[self.multiline_content_field] = continuation

                        # Get optional integer fields
                        port = self._map_field(groups, "port")
                        if port is not None:
                            try:
                                port = int(port)
                            except (ValueError, TypeError):
                                port = None

                        result = ParseResult(
                            timestamp=timestamp,
                            event_type=self.default_event_type,
                            severity=self._get_severity(groups),
                            raw_message=entry,  # Full entry including continuation
                            client_ip=self._map_field(groups, "client_ip"),
                            target_ip=self._map_field(groups, "target_ip"),
                            domain=self._map_field(groups, "domain"),
                            port=port,
                            protocol=self._map_field(groups, "protocol"),
                            action=self._map_field(groups, "action"),
                            response_status=self._map_field(groups, "response_status"),
                            parsed_fields=groups,
                        )
                        results.append(result)
                        matched = True
                        break

                    except Exception as e:
                        logger.warning(
                            "custom_parse_error",
                            error=str(e),
                            line=first_line[:200],
                        )

            if not matched:
                # No pattern matched - create fallback result
                result = ParseResult(
                    timestamp=datetime.now(UTC),
                    event_type=self.default_event_type,
                    severity=EventSeverity.INFO,
                    raw_message=entry,
                    parsed_fields={"message": entry},
                )
                results.append(result)

        return results
