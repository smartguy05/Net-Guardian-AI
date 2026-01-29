"""JSON log parser with configurable field mappings."""

import json
from datetime import UTC, datetime
from typing import Any

import structlog
from jsonpath_ng import parse as jsonpath_parse

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("json")
class JsonParser(BaseParser):
    """Parser for JSON-formatted log data.

    Configuration options:
        events_path: JSONPath to events array (default: "$" for root)
        timestamp_field: Field name for timestamp
        timestamp_format: strptime format string (default: ISO format)
        field_mappings: Dict mapping ParseResult fields to JSONPaths
        event_type: Default event type if not mappable
        severity_field: Field name for severity
        severity_map: Dict mapping log severity values to EventSeverity
    """

    DEFAULT_SEVERITY_MAP = {
        "debug": EventSeverity.DEBUG,
        "info": EventSeverity.INFO,
        "information": EventSeverity.INFO,
        "warn": EventSeverity.WARNING,
        "warning": EventSeverity.WARNING,
        "error": EventSeverity.ERROR,
        "err": EventSeverity.ERROR,
        "critical": EventSeverity.CRITICAL,
        "crit": EventSeverity.CRITICAL,
        "fatal": EventSeverity.CRITICAL,
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.events_path = self.config.get("events_path", "$")
        self.timestamp_field = self.config.get("timestamp_field", "timestamp")
        self.timestamp_format = self.config.get("timestamp_format")
        self.field_mappings = self.config.get("field_mappings", {})
        self.default_event_type = EventType(
            self.config.get("event_type", EventType.UNKNOWN.value)
        )
        self.severity_field = self.config.get("severity_field", "severity")
        self.severity_map = {
            **self.DEFAULT_SEVERITY_MAP,
            **self.config.get("severity_map", {}),
        }

        # Pre-compile JSONPath expressions
        self._events_expr = jsonpath_parse(self.events_path)
        self._field_exprs = {
            field: jsonpath_parse(path)
            for field, path in self.field_mappings.items()
        }

    def _extract_value(self, data: dict[str, Any], path: str) -> Any:
        """Extract a value using JSONPath."""
        expr = jsonpath_parse(path)
        matches = expr.find(data)
        if matches:
            return matches[0].value
        return None

    def _extract_mapped_value(self, data: dict[str, Any], field: str) -> Any:
        """Extract a value using pre-compiled field mapping."""
        expr = self._field_exprs.get(field)
        if expr:
            matches = expr.find(data)
            if matches:
                return matches[0].value
        return None

    def _parse_timestamp(self, value: Any) -> datetime:
        """Parse a timestamp value to datetime."""
        if value is None:
            return datetime.now(UTC)

        if isinstance(value, datetime):
            return value

        if isinstance(value, (int, float)):
            # Unix timestamp
            return datetime.fromtimestamp(value, tz=UTC)

        if isinstance(value, str):
            if self.timestamp_format:
                dt = datetime.strptime(value, self.timestamp_format)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            else:
                # Try ISO format
                return datetime.fromisoformat(value.replace("Z", "+00:00"))

        return datetime.now(UTC)

    def _parse_severity(self, data: dict[str, Any]) -> EventSeverity:
        """Parse severity from data."""
        severity_value = data.get(self.severity_field)
        if severity_value is None:
            # Try field mapping
            severity_value = self._extract_mapped_value(data, "severity")

        if severity_value is None:
            return EventSeverity.INFO

        # Normalize to lowercase string
        severity_str = str(severity_value).lower()
        return self.severity_map.get(severity_str) or EventSeverity.INFO

    def _get_field(self, data: dict[str, Any], field: str, default: Any = None) -> Any:
        """Get a field value, checking mappings first."""
        # Check field mappings
        mapped_value = self._extract_mapped_value(data, field)
        if mapped_value is not None:
            return mapped_value

        # Fall back to direct field access
        return data.get(field, default)

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse JSON log data."""
        results = []

        # Handle string input
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except json.JSONDecodeError as e:
                logger.warning("json_parse_error", error=str(e))
                return []

        # Extract events array
        if isinstance(raw_data, list):
            events = raw_data
        else:
            matches = self._events_expr.find(raw_data)
            if matches:
                events = matches[0].value
                if not isinstance(events, list):
                    events = [events]
            else:
                events = [raw_data]

        for event in events:
            if not isinstance(event, dict):
                continue

            try:
                # Extract timestamp
                timestamp_value = self._get_field(event, self.timestamp_field)
                timestamp = self._parse_timestamp(timestamp_value)

                # Get raw message
                raw_message = self._get_field(event, "message") or json.dumps(event)

                result = ParseResult(
                    timestamp=timestamp,
                    event_type=self.default_event_type,
                    severity=self._parse_severity(event),
                    raw_message=raw_message if isinstance(raw_message, str) else json.dumps(raw_message),
                    client_ip=self._get_field(event, "client_ip"),
                    target_ip=self._get_field(event, "target_ip"),
                    domain=self._get_field(event, "domain"),
                    port=self._get_field(event, "port"),
                    protocol=self._get_field(event, "protocol"),
                    action=self._get_field(event, "action"),
                    response_status=self._get_field(event, "response_status"),
                    parsed_fields=event,
                )
                results.append(result)

            except Exception as e:
                logger.warning(
                    "json_event_parse_error",
                    error=str(e),
                    event=str(event)[:200],
                )

        return results
