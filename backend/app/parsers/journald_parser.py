"""Systemd journal (journald) log parser."""

from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("journald")
class JournaldParser(BaseParser):
    """Parser for systemd journal (journald) logs.

    Handles the JSON output from `journalctl --output=json` or journal-remote.

    Priority levels (RFC 5424 / syslog):
        0: emerg   - System is unusable
        1: alert   - Action must be taken immediately
        2: crit    - Critical conditions
        3: err     - Error conditions
        4: warning - Warning conditions
        5: notice  - Normal but significant condition
        6: info    - Informational messages
        7: debug   - Debug-level messages

    Configuration options:
        units: List of systemd units to filter for
        priority_min: Minimum priority level to include (0-7, lower is more severe)
        include_kernel: Include kernel messages (_TRANSPORT=kernel)
    """

    # Map syslog priority to EventSeverity
    PRIORITY_MAP = {
        "0": EventSeverity.CRITICAL,  # emerg
        "1": EventSeverity.CRITICAL,  # alert
        "2": EventSeverity.CRITICAL,  # crit
        "3": EventSeverity.ERROR,  # err
        "4": EventSeverity.WARNING,  # warning
        "5": EventSeverity.INFO,  # notice
        "6": EventSeverity.INFO,  # info
        "7": EventSeverity.DEBUG,  # debug
    }

    # Common service failure patterns
    SERVICE_FAILURE_PATTERNS = [
        "failed",
        "failure",
        "error",
        "crashed",
        "killed",
        "timeout",
        "refused",
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.units = set(self.config.get("units", []))
        self.priority_min = self.config.get("priority_min", 7)  # Include all by default
        self.include_kernel = self.config.get("include_kernel", False)

    def _parse_timestamp(self, entry: dict[str, Any]) -> datetime:
        """Parse journal timestamp.

        Journal entries can have timestamps in different formats:
        - __REALTIME_TIMESTAMP: Microseconds since epoch (preferred)
        - _SOURCE_REALTIME_TIMESTAMP: Original source timestamp
        """
        try:
            # Try __REALTIME_TIMESTAMP first (microseconds since epoch)
            ts_str = entry.get("__REALTIME_TIMESTAMP")
            if ts_str:
                ts_us = int(ts_str)
                return datetime.fromtimestamp(ts_us / 1_000_000, tz=UTC)

            # Try _SOURCE_REALTIME_TIMESTAMP
            src_ts = entry.get("_SOURCE_REALTIME_TIMESTAMP")
            if src_ts:
                ts_us = int(src_ts)
                return datetime.fromtimestamp(ts_us / 1_000_000, tz=UTC)

            # Fallback to current time
            return datetime.now(UTC)

        except (ValueError, TypeError, OSError) as e:
            logger.debug("journald_timestamp_parse_error", error=str(e))
            return datetime.now(UTC)

    def _get_severity(self, entry: dict[str, Any]) -> EventSeverity:
        """Get severity from journal priority."""
        priority = entry.get("PRIORITY", "6")
        return self.PRIORITY_MAP.get(str(priority), EventSeverity.INFO)

    def _detect_service_state(self, entry: dict[str, Any]) -> str | None:
        """Detect service state changes from journal message."""
        message = entry.get("MESSAGE", "").lower()

        state_patterns = {
            "started": "started",
            "starting": "starting",
            "stopped": "stopped",
            "stopping": "stopping",
            "failed": "failed",
            "reloading": "reloading",
            "reloaded": "reloaded",
            "activated": "activated",
            "deactivated": "deactivated",
        }

        for pattern, state in state_patterns.items():
            if pattern in message:
                return state

        return None

    def _should_include(self, entry: dict[str, Any]) -> bool:
        """Check if entry should be included based on filters."""
        # Check priority
        priority = int(entry.get("PRIORITY", "6"))
        if priority > self.priority_min:
            return False

        # Check kernel messages
        transport = entry.get("_TRANSPORT", "")
        if transport == "kernel" and not self.include_kernel:
            return False

        # Check unit filter
        if self.units:
            unit = entry.get("_SYSTEMD_UNIT", entry.get("UNIT", ""))
            if unit and not any(u in unit for u in self.units):
                return False

        return True

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse journald log data.

        Args:
            raw_data: Either:
                - A dict with journal entry fields
                - A list of journal entries
                - A string containing JSON lines
        """
        import json

        results = []
        entries = []

        # Handle different input formats
        if isinstance(raw_data, dict):
            entries = [raw_data]
        elif isinstance(raw_data, list):
            entries = raw_data
        elif isinstance(raw_data, str):
            # JSON lines format (journalctl --output=json)
            for line in raw_data.strip().split("\n"):
                if line.strip():
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        else:
            logger.warning("journald_invalid_data", data_type=type(raw_data).__name__)
            return []

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            if not self._should_include(entry):
                continue

            try:
                result = self._parse_entry(entry)
                if result:
                    results.append(result)
            except Exception as e:
                logger.warning(
                    "journald_entry_parse_error",
                    error=str(e),
                    entry=str(entry)[:200],
                )

        return results

    def _parse_entry(self, entry: dict[str, Any]) -> ParseResult | None:
        """Parse a single journal entry."""
        message = entry.get("MESSAGE", "")
        if not message:
            return None

        # Handle binary messages
        if isinstance(message, list):
            # MESSAGE can be a list of bytes
            try:
                message = bytes(message).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                message = str(message)

        timestamp = self._parse_timestamp(entry)
        severity = self._get_severity(entry)

        # Extract key fields
        unit = entry.get("_SYSTEMD_UNIT", entry.get("UNIT", ""))
        syslog_identifier = entry.get("SYSLOG_IDENTIFIER", "")
        pid = entry.get("_PID", entry.get("SYSLOG_PID"))
        boot_id = entry.get("_BOOT_ID", "")
        machine_id = entry.get("_MACHINE_ID", "")
        hostname = entry.get("_HOSTNAME", "")
        transport = entry.get("_TRANSPORT", "")
        cursor = entry.get("__CURSOR", "")

        # Detect service state
        service_state = self._detect_service_state(entry)

        # Build parsed fields
        parsed_fields: dict[str, Any] = {
            "priority": int(entry.get("PRIORITY", 6)),
            "unit": unit,
            "syslog_identifier": syslog_identifier,
            "pid": int(pid) if pid else None,
            "boot_id": boot_id,
            "machine_id": machine_id,
            "hostname": hostname,
            "transport": transport,
            "cursor": cursor,
        }

        # Add service state if detected
        if service_state:
            parsed_fields["service_state"] = service_state

        # Add kernel-specific fields
        if transport == "kernel":
            parsed_fields["kernel"] = True
            parsed_fields["kernel_device"] = entry.get("_KERNEL_DEVICE", "")
            parsed_fields["kernel_subsystem"] = entry.get("_KERNEL_SUBSYSTEM", "")

        # Add systemd-specific fields
        if unit:
            parsed_fields["invocation_id"] = entry.get("_SYSTEMD_INVOCATION_ID", "")
            parsed_fields["cgroup"] = entry.get("_SYSTEMD_CGROUP", "")
            parsed_fields["slice"] = entry.get("_SYSTEMD_SLICE", "")

        # Add code location if available (useful for debugging)
        code_file = entry.get("CODE_FILE")
        code_line = entry.get("CODE_LINE")
        code_func = entry.get("CODE_FUNC")
        if code_file:
            parsed_fields["code_location"] = {
                "file": code_file,
                "line": code_line,
                "function": code_func,
            }

        # Determine event type
        event_type = EventType.JOURNAL
        if transport == "kernel":
            event_type = EventType.SYSTEM

        # Build raw message with context
        identifier = syslog_identifier or unit or "unknown"
        if pid:
            raw_message = f"{identifier}[{pid}]: {message}"
        else:
            raw_message = f"{identifier}: {message}"

        return ParseResult(
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            raw_message=raw_message,
            client_ip=None,
            target_ip=None,
            domain=hostname if hostname else None,
            port=None,
            protocol="journal",
            action=service_state,
            response_status=str(entry.get("PRIORITY", "6")),
            parsed_fields=parsed_fields,
        )
