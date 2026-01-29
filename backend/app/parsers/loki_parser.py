"""Grafana Loki log parser."""

import re
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()

# Common patterns for extracting IP addresses from log lines
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


@register_parser("loki")
class LokiParser(BaseParser):
    """Parser for Grafana Loki log query results.

    Handles both the query API response format and the push API format.

    Query API format (from /loki/api/v1/query_range):
    {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"label": "value", ...},
                    "values": [["<unix_nano>", "<log_line>"], ...]
                }
            ]
        }
    }

    Push API format:
    {
        "streams": [
            {
                "stream": {"label": "value", ...},
                "values": [["<unix_nano>", "<log_line>"], ...]
            }
        ]
    }

    Configuration options:
        severity_label: Label name containing severity (default: "level")
        event_type_label: Label name containing event type (default: "job")
        client_ip_label: Label name containing client IP (default: None)
        target_ip_label: Label name containing target IP (default: None)
        event_type_mapping: Dict mapping label values to EventType
        extract_ips_from_message: Whether to extract IPs from log line (default: True)
    """

    # Default severity mapping from common log levels
    SEVERITY_MAPPING = {
        "trace": EventSeverity.DEBUG,
        "debug": EventSeverity.DEBUG,
        "info": EventSeverity.INFO,
        "information": EventSeverity.INFO,
        "notice": EventSeverity.INFO,
        "warn": EventSeverity.WARNING,
        "warning": EventSeverity.WARNING,
        "error": EventSeverity.ERROR,
        "err": EventSeverity.ERROR,
        "critical": EventSeverity.CRITICAL,
        "fatal": EventSeverity.CRITICAL,
        "panic": EventSeverity.CRITICAL,
        "alert": EventSeverity.CRITICAL,
        "emerg": EventSeverity.CRITICAL,
        "emergency": EventSeverity.CRITICAL,
    }

    # Default event type mapping from common job/app names
    EVENT_TYPE_MAPPING = {
        "nginx": EventType.HTTP,
        "apache": EventType.HTTP,
        "httpd": EventType.HTTP,
        "traefik": EventType.HTTP,
        "caddy": EventType.HTTP,
        "haproxy": EventType.HTTP,
        "envoy": EventType.HTTP,
        "varnish": EventType.HTTP,
        "dns": EventType.DNS,
        "bind": EventType.DNS,
        "unbound": EventType.DNS,
        "coredns": EventType.DNS,
        "pihole": EventType.DNS,
        "adguard": EventType.DNS,
        "auth": EventType.AUTH,
        "sshd": EventType.AUTH,
        "sudo": EventType.AUTH,
        "pam": EventType.AUTH,
        "login": EventType.AUTH,
        "firewall": EventType.FIREWALL,
        "iptables": EventType.FIREWALL,
        "nftables": EventType.FIREWALL,
        "ufw": EventType.FIREWALL,
        "pf": EventType.FIREWALL,
        "syslog": EventType.SYSTEM,
        "kernel": EventType.SYSTEM,
        "systemd": EventType.SYSTEM,
        "cron": EventType.SYSTEM,
        "ollama": EventType.LLM,
        "openai": EventType.LLM,
        "llm": EventType.LLM,
        "netflow": EventType.FLOW,
        "sflow": EventType.FLOW,
    }

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the Loki parser with configuration.

        Args:
            config: Optional configuration dictionary with:
                - severity_label: Label name for severity (default: "level")
                - event_type_label: Label name for event type (default: "job")
                - client_ip_label: Label name for client IP
                - target_ip_label: Label name for target IP
                - event_type_mapping: Custom event type mappings
                - extract_ips_from_message: Extract IPs from log line (default: True)
        """
        super().__init__(config)
        self.severity_label = self.config.get("severity_label", "level")
        self.event_type_label = self.config.get("event_type_label", "job")
        self.client_ip_label = self.config.get("client_ip_label")
        self.target_ip_label = self.config.get("target_ip_label")
        self.extract_ips = self.config.get("extract_ips_from_message", True)

        # Merge custom event type mappings
        self.event_type_map = {**self.EVENT_TYPE_MAPPING}
        if "event_type_mapping" in self.config:
            for key, value in self.config["event_type_mapping"].items():
                if isinstance(value, EventType):
                    self.event_type_map[key.lower()] = value
                elif isinstance(value, str):
                    try:
                        self.event_type_map[key.lower()] = EventType(value)
                    except ValueError:
                        pass

    def _parse_timestamp(self, timestamp_ns: str | int) -> datetime:
        """Parse Loki nanosecond timestamp to datetime.

        Args:
            timestamp_ns: Unix timestamp in nanoseconds (string or int).

        Returns:
            UTC datetime object.
        """
        try:
            ns = int(timestamp_ns)
            seconds = ns / 1_000_000_000
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (ValueError, TypeError, OSError):
            return datetime.now(UTC)

    def _determine_severity(self, labels: dict[str, str], log_line: str) -> EventSeverity:
        """Determine event severity from labels or log content.

        Args:
            labels: Stream labels dictionary.
            log_line: The log message content.

        Returns:
            EventSeverity enum value.
        """
        # Check configured severity label
        severity_value = labels.get(self.severity_label, "").lower()
        if severity_value in self.SEVERITY_MAPPING:
            return self.SEVERITY_MAPPING[severity_value]

        # Check common alternative label names
        for alt_label in ["severity", "log_level", "loglevel", "lvl"]:
            severity_value = labels.get(alt_label, "").lower()
            if severity_value in self.SEVERITY_MAPPING:
                return self.SEVERITY_MAPPING[severity_value]

        # Try to extract from log line (common patterns)
        log_lower = log_line.lower()
        for level, severity in self.SEVERITY_MAPPING.items():
            # Look for level indicators like [ERROR], level=error, "level":"error"
            if f"[{level}]" in log_lower or f"level={level}" in log_lower:
                return severity
            if f'"level":"{level}"' in log_lower or f"'level':'{level}'" in log_lower:
                return severity

        return EventSeverity.INFO

    def _determine_event_type(self, labels: dict[str, str]) -> EventType:
        """Determine event type from labels.

        Args:
            labels: Stream labels dictionary.

        Returns:
            EventType enum value.
        """
        # Check configured event type label
        type_value = labels.get(self.event_type_label, "").lower()
        if type_value in self.event_type_map:
            return self.event_type_map[type_value]

        # Check common alternative labels
        for alt_label in ["app", "application", "service", "component", "source"]:
            type_value = labels.get(alt_label, "").lower()
            if type_value in self.event_type_map:
                return self.event_type_map[type_value]

        # Check if any label value matches known types
        for value in labels.values():
            if value.lower() in self.event_type_map:
                return self.event_type_map[value.lower()]

        return EventType.SYSTEM

    def _extract_ips_from_line(self, log_line: str) -> tuple[str | None, str | None]:
        """Extract IP addresses from log line.

        Args:
            log_line: The log message content.

        Returns:
            Tuple of (client_ip, target_ip) - may be None.
        """
        if not self.extract_ips:
            return None, None

        ips = IP_PATTERN.findall(log_line)
        if not ips:
            return None, None

        # Filter out common non-client IPs
        filtered_ips = [ip for ip in ips if not ip.startswith("127.") and ip != "0.0.0.0"]  # nosec B104 - IP filtering, not binding

        if len(filtered_ips) >= 2:
            return filtered_ips[0], filtered_ips[1]
        elif len(filtered_ips) == 1:
            return filtered_ips[0], None

        return None, None

    def _parse_stream(self, stream_data: dict[str, Any]) -> list[ParseResult]:
        """Parse a single Loki stream with its values.

        Args:
            stream_data: Dict with "stream" labels and "values" entries.

        Returns:
            List of ParseResult objects.
        """
        results = []

        labels = stream_data.get("stream", {})
        values = stream_data.get("values", [])

        if not isinstance(labels, dict):
            labels = {}
        if not isinstance(values, list):
            return []

        # Determine event type and extract label-based IPs once per stream
        event_type = self._determine_event_type(labels)
        label_client_ip = labels.get(self.client_ip_label) if self.client_ip_label else None
        label_target_ip = labels.get(self.target_ip_label) if self.target_ip_label else None

        for entry in values:
            try:
                if not isinstance(entry, (list, tuple)) or len(entry) < 2:
                    continue

                timestamp_ns, log_line = entry[0], entry[1]

                if not isinstance(log_line, str):
                    log_line = str(log_line)

                timestamp = self._parse_timestamp(timestamp_ns)
                severity = self._determine_severity(labels, log_line)

                # Get IPs from labels or extract from message
                client_ip = label_client_ip
                target_ip = label_target_ip

                if not client_ip or not target_ip:
                    extracted_client, extracted_target = self._extract_ips_from_line(log_line)
                    client_ip = client_ip or extracted_client
                    target_ip = target_ip or extracted_target

                # Build parsed fields with all labels
                parsed_fields = {
                    "labels": labels,
                    "original_timestamp_ns": str(timestamp_ns),
                }

                # Include commonly useful labels at top level
                for key in ["namespace", "pod", "container", "host", "filename", "instance"]:
                    if key in labels:
                        parsed_fields[key] = labels[key]

                result = ParseResult(
                    timestamp=timestamp,
                    event_type=event_type,
                    severity=severity,
                    raw_message=log_line,
                    client_ip=client_ip,
                    target_ip=target_ip,
                    parsed_fields=parsed_fields,
                )
                results.append(result)

            except Exception as e:
                logger.warning(
                    "loki_entry_parse_error",
                    error=str(e),
                    entry=str(entry)[:200],
                )

        return results

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse Loki log data into normalized events.

        Args:
            raw_data: Loki API response (query or push format) or list of streams.

        Returns:
            List of ParseResult objects.
        """
        results = []

        if not raw_data:
            return []

        streams = []

        try:
            if isinstance(raw_data, dict):
                # Query API response format
                if "data" in raw_data and isinstance(raw_data["data"], dict):
                    data = raw_data["data"]
                    if data.get("resultType") == "streams":
                        streams = data.get("result", [])
                    elif "result" in data:
                        # Handle other result types that might have streams
                        streams = data.get("result", [])

                # Push API format
                elif "streams" in raw_data:
                    streams = raw_data["streams"]

                # Single stream object
                elif "stream" in raw_data and "values" in raw_data:
                    streams = [raw_data]

            elif isinstance(raw_data, list):
                # List of streams directly
                streams = raw_data

            else:
                logger.warning("loki_invalid_data", data_type=type(raw_data).__name__)
                return []

            # Parse each stream
            for stream_data in streams:
                if isinstance(stream_data, dict):
                    results.extend(self._parse_stream(stream_data))

        except Exception as e:
            logger.warning(
                "loki_parse_error",
                error=str(e),
                data_preview=str(raw_data)[:200] if raw_data else "None",
            )

        return results
