"""Docker/Podman container log parser."""

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("docker")
class DockerParser(BaseParser):
    """Parser for Docker/Podman container logs.

    Handles the JSON log format from Docker/Podman container logs:
    {"log": "...", "stream": "stdout|stderr", "time": "..."}

    Also handles container lifecycle events with metadata.

    Configuration options:
        detect_errors: Enable error pattern detection (default: True)
        error_keywords: Additional keywords to treat as errors
        container_name: Override container name extraction
    """

    # Common error patterns in container logs
    ERROR_PATTERNS = [
        "error",
        "exception",
        "failed",
        "fatal",
        "panic",
        "critical",
        "crash",
        "killed",
        "oom",
        "segfault",
        "timeout",
        "refused",
        "denied",
        "unauthorized",
    ]

    WARNING_PATTERNS = [
        "warning",
        "warn",
        "deprecated",
        "retry",
        "slow",
        "timeout",
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.detect_errors = self.config.get("detect_errors", True)
        self.error_keywords = set(
            self.config.get("error_keywords", []) + self.ERROR_PATTERNS
        )
        self.warning_keywords = set(
            self.config.get("warning_keywords", []) + self.WARNING_PATTERNS
        )

    def _parse_timestamp(self, time_str: str) -> datetime:
        """Parse Docker timestamp format (RFC 3339 nano)."""
        try:
            # Docker uses RFC 3339 format with nanoseconds
            # Example: 2024-01-15T10:30:45.123456789Z
            if "." in time_str:
                # Handle nanosecond precision by truncating to microseconds
                parts = time_str.split(".")
                if len(parts) == 2:
                    # Get microseconds (first 6 digits after decimal)
                    frac = parts[1].rstrip("Z").rstrip("+").split("+")[0].split("-")[0]
                    frac = frac[:6].ljust(6, "0")
                    time_str = f"{parts[0]}.{frac}+00:00"

            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as e:
            logger.debug("docker_timestamp_parse_error", error=str(e), time_str=time_str)
            return datetime.now(UTC)

    def _determine_severity(self, log_content: str, stream: str) -> EventSeverity:
        """Determine event severity based on log content and stream."""
        if not self.detect_errors:
            return EventSeverity.INFO

        lower_content = log_content.lower()

        # Check for error patterns
        for pattern in self.error_keywords:
            if pattern in lower_content:
                return EventSeverity.ERROR

        # Check for warning patterns
        for pattern in self.warning_keywords:
            if pattern in lower_content:
                return EventSeverity.WARNING

        # stderr is typically warnings or errors
        if stream == "stderr":
            return EventSeverity.WARNING

        return EventSeverity.INFO

    def _detect_container_event(self, entry: dict[str, Any]) -> str | None:
        """Detect container lifecycle events."""
        log_content = entry.get("log", "").lower()

        events = {
            "container started": "start",
            "container stopped": "stop",
            "container killed": "kill",
            "container restarted": "restart",
            "oomkilled": "oom_killed",
            "out of memory": "oom_killed",
            "exited with code": "exit",
            "health check": "health_check",
        }

        for pattern, event_type in events.items():
            if pattern in log_content:
                return event_type

        return None

    def _extract_exit_code(self, log_content: str) -> int | None:
        """Extract exit code from log message."""
        import re

        # Match patterns like "exited with code 1" or "exit code: 137"
        patterns = [
            r"exited?\s+(?:with\s+)?code[:\s]+(\d+)",
            r"exit[:\s]+(\d+)",
            r"status[:\s]+(\d+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, log_content, re.IGNORECASE)
            if match:
                return int(match.group(1))

        return None

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse Docker container log data.

        Args:
            raw_data: Either:
                - A dict with Docker JSON log format
                - A list of Docker log entries
                - A string containing JSON log lines
        """
        results = []
        entries = []

        # Handle different input formats
        if isinstance(raw_data, dict):
            entries = [raw_data]
        elif isinstance(raw_data, list):
            entries = raw_data
        elif isinstance(raw_data, str):
            # JSON lines format
            for line in raw_data.strip().split("\n"):
                if line.strip():
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Treat as plain text log
                        entries.append({
                            "log": line,
                            "stream": "stdout",
                            "time": datetime.now(UTC).isoformat(),
                        })
        else:
            logger.warning("docker_invalid_data", data_type=type(raw_data).__name__)
            return []

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            try:
                result = self._parse_entry(entry)
                if result:
                    results.append(result)
            except Exception as e:
                logger.warning(
                    "docker_entry_parse_error",
                    error=str(e),
                    entry=str(entry)[:200],
                )

        return results

    def _parse_entry(self, entry: dict[str, Any]) -> ParseResult | None:
        """Parse a single Docker log entry."""
        # Extract core fields
        log_content = entry.get("log", "").rstrip("\n")
        stream = entry.get("stream", "stdout")
        timestamp = self._parse_timestamp(entry.get("time", ""))

        if not log_content:
            return None

        # Extract container metadata
        container_id = entry.get("container_id", entry.get("containerId", ""))
        container_name = self.config.get(
            "container_name",
            entry.get("container_name", entry.get("containerName", "")),
        )
        image = entry.get("image", entry.get("attrs", {}).get("image", ""))

        # Detect container events
        container_event = self._detect_container_event(entry)

        # Build parsed fields
        parsed_fields: dict[str, Any] = {
            "container_id": container_id[:12] if container_id else None,
            "container_name": container_name,
            "image": image,
            "stream": stream,
        }

        # Add container event info if detected
        if container_event:
            parsed_fields["container_event"] = container_event
            if container_event == "oom_killed":
                parsed_fields["oom_killed"] = True

            exit_code = self._extract_exit_code(log_content)
            if exit_code is not None:
                parsed_fields["exit_code"] = exit_code

        # Check for restart information
        restart_count = entry.get("restart_count", entry.get("restartCount"))
        if restart_count is not None:
            parsed_fields["restart_count"] = restart_count

        # Determine severity
        severity = self._determine_severity(log_content, stream)

        # Elevate severity for critical container events
        if container_event in ("oom_killed", "kill"):
            severity = EventSeverity.CRITICAL
        elif container_event in ("exit",) and parsed_fields.get("exit_code", 0) != 0:
            severity = EventSeverity.ERROR
        elif container_event == "restart":
            severity = EventSeverity.WARNING

        # Build raw message
        prefix = f"[{container_name or container_id[:12] or 'unknown'}]"
        raw_message = f"{prefix} {log_content}"

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.CONTAINER,
            severity=severity,
            raw_message=raw_message,
            client_ip=None,
            target_ip=None,
            domain=None,
            port=None,
            protocol="docker",
            action=container_event,
            response_status=stream,
            parsed_fields=parsed_fields,
        )
