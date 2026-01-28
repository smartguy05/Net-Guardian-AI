"""Endpoint agent data parser.

Parses events sent from endpoint agents that monitor local system activity
including processes, network connections, file changes, and system events.
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("endpoint")
class EndpointParser(BaseParser):
    """Parser for endpoint agent data.

    Expected JSON format:
    {
        "timestamp": "2024-01-15T10:30:00Z",
        "hostname": "workstation-01",
        "agent_id": "uuid",
        "event_type": "process|network|file|auth|system",
        "data": {
            # For process events:
            "pid": 1234,
            "name": "chrome.exe",
            "path": "/usr/bin/chrome",
            "cmdline": "chrome --flag",
            "user": "admin",
            "parent_pid": 1,
            "parent_name": "init",

            # For network events:
            "local_ip": "192.168.1.100",
            "local_port": 54321,
            "remote_ip": "8.8.8.8",
            "remote_port": 443,
            "protocol": "tcp",
            "state": "established",
            "process_name": "chrome",
            "process_pid": 1234,

            # For file events:
            "path": "/etc/passwd",
            "action": "read|write|delete|create|modify",
            "process_name": "vim",
            "process_pid": 1234,

            # For auth events:
            "action": "login|logout|failed",
            "user": "admin",
            "source": "console|ssh|rdp",
            "source_ip": "192.168.1.50",

            # For system events:
            "action": "startup|shutdown|service_start|service_stop",
            "service_name": "sshd",
        }
    }
    """

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse endpoint agent data.

        Args:
            raw_data: JSON data from endpoint agent (dict or list).

        Returns:
            List of ParseResult objects.
        """
        if isinstance(raw_data, list):
            results = []
            for entry in raw_data:
                result = self._parse_entry(entry)
                if result:
                    results.append(result)
            return results
        elif isinstance(raw_data, dict):
            result = self._parse_entry(raw_data)
            return [result] if result else []
        else:
            logger.warning("endpoint_parser_invalid_data", data_type=type(raw_data).__name__)
            return []

    def _parse_entry(self, entry: dict[str, Any]) -> ParseResult | None:
        """Parse a single endpoint agent entry."""
        try:
            # Parse timestamp
            ts_str = entry.get("timestamp")
            if ts_str:
                if isinstance(ts_str, str):
                    timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                else:
                    timestamp = datetime.fromtimestamp(ts_str, tz=UTC)
            else:
                timestamp = datetime.now(UTC)

            # Determine event type and severity
            endpoint_event_type = entry.get("event_type", "system")
            data = entry.get("data", {})

            event_type = EventType.ENDPOINT
            severity = EventSeverity.INFO
            action = None
            client_ip = None
            target_ip = None
            port = None
            protocol = None
            domain = None

            # Process event-specific fields
            if endpoint_event_type == "process":
                action = "process_start"
                severity = self._get_process_severity(data)
            elif endpoint_event_type == "network":
                client_ip = data.get("local_ip")
                target_ip = data.get("remote_ip")
                port = data.get("remote_port")
                protocol = data.get("protocol")
                action = data.get("state", "connection")
                severity = self._get_network_severity(data)
            elif endpoint_event_type == "file":
                action = data.get("action", "access")
                severity = self._get_file_severity(data)
            elif endpoint_event_type == "auth":
                event_type = EventType.AUTH
                action = data.get("action", "login")
                client_ip = data.get("source_ip")
                if action == "failed":
                    severity = EventSeverity.WARNING
            elif endpoint_event_type == "system":
                event_type = EventType.SYSTEM
                action = data.get("action", "event")

            # Build parsed fields
            parsed_fields = {
                "hostname": entry.get("hostname"),
                "agent_id": entry.get("agent_id"),
                "endpoint_event_type": endpoint_event_type,
                **data,
            }

            # Build raw message for display
            raw_message = self._build_raw_message(entry, endpoint_event_type, data)

            return ParseResult(
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                raw_message=raw_message,
                client_ip=client_ip,
                target_ip=target_ip,
                port=port,
                protocol=protocol,
                domain=domain,
                action=action,
                parsed_fields=parsed_fields,
            )

        except Exception as e:
            logger.warning("endpoint_parser_error", error=str(e), entry=entry)
            return None

    def _get_process_severity(self, data: dict[str, Any]) -> EventSeverity:
        """Determine severity based on process characteristics."""
        # Check for suspicious process patterns
        name = data.get("name", "").lower()
        path = data.get("path", "").lower()
        cmdline = data.get("cmdline", "").lower()

        # Suspicious process names
        suspicious_names = [
            "mimikatz", "pwdump", "procdump", "nc.exe", "netcat",
            "powershell_ise", "psexec", "wmic", "certutil",
        ]
        if any(s in name for s in suspicious_names):
            return EventSeverity.WARNING

        # Suspicious command line patterns
        suspicious_cmdline = [
            "-encodedcommand", "downloadstring", "invoke-expression",
            "bypass", "hidden", "-nop", "-noni", "-enc",
        ]
        if any(s in cmdline for s in suspicious_cmdline):
            return EventSeverity.WARNING

        # Running from temp/suspicious paths
        suspicious_paths = ["/tmp/", "\\temp\\", "\\appdata\\local\\temp\\"]
        if any(s in path for s in suspicious_paths):
            return EventSeverity.INFO

        return EventSeverity.DEBUG

    def _get_network_severity(self, data: dict[str, Any]) -> EventSeverity:
        """Determine severity based on network connection characteristics."""
        remote_port = data.get("remote_port", 0)
        state = data.get("state", "").lower()

        # Suspicious ports
        suspicious_ports = [4444, 5555, 6666, 31337, 1337, 8080, 9001]
        if remote_port in suspicious_ports:
            return EventSeverity.WARNING

        # Listening on all interfaces
        local_ip = data.get("local_ip", "")
        if state == "listen" and local_ip in ["0.0.0.0", "::"]:
            return EventSeverity.INFO

        return EventSeverity.DEBUG

    def _get_file_severity(self, data: dict[str, Any]) -> EventSeverity:
        """Determine severity based on file access patterns."""
        path = data.get("path", "").lower()
        action = data.get("action", "").lower()

        # Sensitive file paths
        sensitive_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "\\sam", "\\system", "\\security",
            ".ssh/", "credentials", "secrets",
        ]
        if any(s in path for s in sensitive_paths):
            if action in ["write", "delete", "modify"]:
                return EventSeverity.WARNING
            return EventSeverity.INFO

        return EventSeverity.DEBUG

    def _build_raw_message(
        self,
        entry: dict[str, Any],
        event_type: str,
        data: dict[str, Any],
    ) -> str:
        """Build a human-readable raw message."""
        hostname = entry.get("hostname", "unknown")

        if event_type == "process":
            name = data.get("name", "unknown")
            user = data.get("user", "unknown")
            return f"[{hostname}] Process started: {name} by {user}"
        elif event_type == "network":
            local = f"{data.get('local_ip', '?')}:{data.get('local_port', '?')}"
            remote = f"{data.get('remote_ip', '?')}:{data.get('remote_port', '?')}"
            state = data.get("state", "connection")
            process = data.get("process_name", "unknown")
            return f"[{hostname}] Network {state}: {local} -> {remote} ({process})"
        elif event_type == "file":
            action = data.get("action", "access")
            path = data.get("path", "unknown")
            process = data.get("process_name", "unknown")
            return f"[{hostname}] File {action}: {path} by {process}"
        elif event_type == "auth":
            action = data.get("action", "event")
            user = data.get("user", "unknown")
            source = data.get("source", "unknown")
            return f"[{hostname}] Auth {action}: {user} via {source}"
        elif event_type == "system":
            action = data.get("action", "event")
            service = data.get("service_name", "")
            if service:
                return f"[{hostname}] System {action}: {service}"
            return f"[{hostname}] System {action}"
        else:
            return f"[{hostname}] Endpoint event: {event_type}"
