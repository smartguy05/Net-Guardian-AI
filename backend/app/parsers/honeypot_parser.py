"""Parser for honeypot container logs."""

import json
import re
from datetime import datetime, timezone
from typing import Any

import structlog

from app.models.honeypot import HoneypotType
from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("honeypot")
class HoneypotParser(BaseParser):
    """Parser for honeypot container logs.

    Supports parsing logs from various honeypot types:
    - Cowrie (SSH/Telnet)
    - Dionaea (FTP, MySQL, SMB)
    - HTTP honeypots
    - Redis honeypots
    """

    # Cowrie SSH/Telnet log patterns
    COWRIE_LOGIN_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*Z?)\s+"
        r"\[(?P<session_id>[^\]]+)\]\s+"
        r"(?P<event_type>login attempt|New connection|SSH client version|"
        r"CMD|TTY log|Download|Session closed).*?"
        r"(?:from\s+)?(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?",
        re.IGNORECASE,
    )

    COWRIE_AUTH_PATTERN = re.compile(
        r"login attempt \[(?P<username>[^\]]*)/(?P<password>[^\]]*)\].*?"
        r"(?P<result>succeeded|failed)",
        re.IGNORECASE,
    )

    COWRIE_CMD_PATTERN = re.compile(
        r"CMD:\s*(?P<command>.*)",
        re.IGNORECASE,
    )

    # HTTP honeypot log patterns
    HTTP_REQUEST_PATTERN = re.compile(
        r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+-\s+"
        r"\[(?P<timestamp>[^\]]+)\]\s+"
        r"\"(?P<method>GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+"
        r"(?P<path>[^\s]+)\s+HTTP/\d\.\d\"\s+"
        r"(?P<status>\d+)\s+(?P<size>\d+)",
    )

    # SQL patterns for injection detection
    SQL_INJECTION_PATTERNS = [
        re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
        re.compile(r"OR\s+1\s*=\s*1", re.IGNORECASE),
        re.compile(r"'\s*OR\s*'", re.IGNORECASE),
        re.compile(r";\s*DROP\s+TABLE", re.IGNORECASE),
        re.compile(r"SLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),
        re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
        re.compile(r"LOAD_FILE\s*\(", re.IGNORECASE),
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        re.compile(r";\s*cat\s+/etc/passwd", re.IGNORECASE),
        re.compile(r"\|\s*(nc|netcat)\s+", re.IGNORECASE),
        re.compile(r"&&\s*(wget|curl)\s+", re.IGNORECASE),
        re.compile(r"\$\((curl|wget)", re.IGNORECASE),
        re.compile(r"`(curl|wget)", re.IGNORECASE),
    ]

    # Malware indicators
    MALWARE_PATTERNS = [
        re.compile(r"(xmrig|minerd|cpuminer)", re.IGNORECASE),  # Cryptominers
        re.compile(r"stratum\+tcp://", re.IGNORECASE),  # Mining pool
        re.compile(r"busybox", re.IGNORECASE),  # IoT malware
        re.compile(r"/tmp/\w+;\s*chmod\s+\+?[0-7]+", re.IGNORECASE),  # Download & execute
        re.compile(r"(tftp|wget|curl).*\|\s*sh", re.IGNORECASE),  # Pipe to shell
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the honeypot parser.

        Args:
            config: Parser configuration including:
                - honeypot_type: Type of honeypot (ssh, http, etc.)
                - container_name: Name of the honeypot container
        """
        super().__init__(config)
        self.honeypot_type = config.get("honeypot_type") if config else None
        self.container_name = config.get("container_name", "honeypot") if config else "honeypot"

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse honeypot log data into normalized events.

        Args:
            raw_data: Raw log data (string or dict).

        Returns:
            List of ParseResult objects.
        """
        if not raw_data:
            return []

        # Handle JSON data
        if isinstance(raw_data, dict):
            return self._parse_json_log(raw_data)

        # Handle string data
        if isinstance(raw_data, str):
            lines = raw_data.strip().split("\n")
            results = []
            for line in lines:
                if not line.strip():
                    continue
                # Try JSON first
                try:
                    data = json.loads(line)
                    results.extend(self._parse_json_log(data))
                except json.JSONDecodeError:
                    # Fall back to text parsing
                    result = self._parse_text_log(line)
                    if result:
                        results.append(result)
            return results

        return []

    def _parse_json_log(self, data: dict) -> list[ParseResult]:
        """Parse JSON-formatted honeypot log.

        Args:
            data: JSON log data.

        Returns:
            List of ParseResult objects.
        """
        results = []

        # Cowrie JSON format
        if "eventid" in data:
            result = self._parse_cowrie_json(data)
            if result:
                results.append(result)

        # Dionaea JSON format
        elif "connection" in data or "download" in data:
            result = self._parse_dionaea_json(data)
            if result:
                results.append(result)

        # Generic JSON with timestamp and message
        elif "timestamp" in data or "time" in data:
            result = self._parse_generic_json(data)
            if result:
                results.append(result)

        return results

    def _parse_cowrie_json(self, data: dict) -> ParseResult | None:
        """Parse Cowrie JSON log format.

        Args:
            data: Cowrie JSON log entry.

        Returns:
            ParseResult or None.
        """
        try:
            event_id = data.get("eventid", "")
            timestamp_str = data.get("timestamp", "")

            # Parse timestamp
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.now(timezone.utc)

            source_ip = data.get("src_ip", data.get("peer_ip", ""))
            session_id = data.get("session", "")

            # Determine event type and severity
            event_type = EventType.NETWORK
            severity = EventSeverity.LOW
            action = event_id

            parsed_fields = {
                "session_id": session_id,
                "honeypot_type": "ssh" if "ssh" in event_id.lower() else "telnet",
                "event_id": event_id,
            }

            # Login attempts
            if "login" in event_id.lower():
                event_type = EventType.AUTHENTICATION
                username = data.get("username", "")
                password = data.get("password", "")
                success = data.get("success", False)

                parsed_fields["username"] = username
                parsed_fields["password"] = password
                parsed_fields["success"] = success

                if success:
                    severity = EventSeverity.HIGH
                    action = "login_success"
                else:
                    severity = EventSeverity.MEDIUM
                    action = "login_failed"

            # Commands
            elif "command" in event_id.lower():
                event_type = EventType.APPLICATION
                command = data.get("input", data.get("command", ""))
                parsed_fields["command"] = command
                action = "command"

                # Check for malware indicators
                for pattern in self.MALWARE_PATTERNS:
                    if pattern.search(command):
                        severity = EventSeverity.CRITICAL
                        parsed_fields["malware_indicator"] = True
                        break
                else:
                    severity = EventSeverity.MEDIUM

            # Downloads
            elif "download" in event_id.lower():
                event_type = EventType.APPLICATION
                severity = EventSeverity.HIGH
                url = data.get("url", "")
                parsed_fields["download_url"] = url
                action = "download"

            # Session events
            elif "session" in event_id.lower():
                severity = EventSeverity.LOW
                action = "session_start" if "open" in event_id.lower() else "session_end"

            # Build message
            message = f"Cowrie {event_id}: {data.get('message', json.dumps(data))}"

            return ParseResult(
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                raw_message=message,
                client_ip=source_ip,
                action=action,
                parsed_fields=parsed_fields,
            )

        except Exception as e:
            logger.warning("cowrie_parse_error", error=str(e), data=data)
            return None

    def _parse_dionaea_json(self, data: dict) -> ParseResult | None:
        """Parse Dionaea JSON log format.

        Args:
            data: Dionaea JSON log entry.

        Returns:
            ParseResult or None.
        """
        try:
            timestamp = datetime.now(timezone.utc)
            if "timestamp" in data:
                try:
                    timestamp = datetime.fromisoformat(data["timestamp"])
                except (ValueError, AttributeError):
                    pass

            connection = data.get("connection", {})
            source_ip = connection.get("remote_host", "")
            source_port = connection.get("remote_port")
            protocol = connection.get("protocol", "")

            event_type = EventType.NETWORK
            severity = EventSeverity.MEDIUM
            action = "connection"

            parsed_fields = {
                "honeypot_type": protocol.lower() if protocol else "unknown",
                "protocol": protocol,
            }

            # Downloads/malware
            if "download" in data:
                download = data["download"]
                severity = EventSeverity.CRITICAL
                action = "malware_download"
                parsed_fields["download_url"] = download.get("url", "")
                parsed_fields["md5"] = download.get("md5", "")
                parsed_fields["sha256"] = download.get("sha256", "")

            # SMB specific
            if protocol and protocol.upper() == "SMB":
                severity = EventSeverity.HIGH
                if "exploit" in str(data).lower():
                    severity = EventSeverity.CRITICAL
                    action = "exploit_attempt"

            message = f"Dionaea {protocol}: {json.dumps(data)}"

            return ParseResult(
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                raw_message=message,
                client_ip=source_ip,
                port=source_port,
                protocol=protocol,
                action=action,
                parsed_fields=parsed_fields,
            )

        except Exception as e:
            logger.warning("dionaea_parse_error", error=str(e), data=data)
            return None

    def _parse_generic_json(self, data: dict) -> ParseResult | None:
        """Parse generic JSON log format.

        Args:
            data: Generic JSON log entry.

        Returns:
            ParseResult or None.
        """
        try:
            # Try various timestamp field names
            timestamp_str = data.get("timestamp") or data.get("time") or data.get("@timestamp")
            try:
                if isinstance(timestamp_str, str):
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                elif isinstance(timestamp_str, (int, float)):
                    timestamp = datetime.fromtimestamp(timestamp_str, timezone.utc)
                else:
                    timestamp = datetime.now(timezone.utc)
            except (ValueError, TypeError):
                timestamp = datetime.now(timezone.utc)

            source_ip = (
                data.get("src_ip")
                or data.get("source_ip")
                or data.get("client_ip")
                or data.get("ip")
                or ""
            )

            message = data.get("message") or data.get("msg") or json.dumps(data)

            return ParseResult(
                timestamp=timestamp,
                event_type=EventType.NETWORK,
                severity=EventSeverity.MEDIUM,
                raw_message=message,
                client_ip=source_ip,
                action="interaction",
                parsed_fields={"raw_data": data},
            )

        except Exception as e:
            logger.warning("generic_json_parse_error", error=str(e), data=data)
            return None

    def _parse_text_log(self, line: str) -> ParseResult | None:
        """Parse text-formatted log line.

        Args:
            line: Log line.

        Returns:
            ParseResult or None.
        """
        # Try Cowrie format
        cowrie_match = self.COWRIE_LOGIN_PATTERN.search(line)
        if cowrie_match:
            return self._parse_cowrie_text(line, cowrie_match)

        # Try HTTP format
        http_match = self.HTTP_REQUEST_PATTERN.search(line)
        if http_match:
            return self._parse_http_text(line, http_match)

        # Generic text line
        return self._parse_generic_text(line)

    def _parse_cowrie_text(self, line: str, match: re.Match) -> ParseResult | None:
        """Parse Cowrie text log format.

        Args:
            line: Full log line.
            match: Regex match object.

        Returns:
            ParseResult or None.
        """
        try:
            groups = match.groupdict()
            timestamp_str = groups.get("timestamp", "")
            session_id = groups.get("session_id", "")
            event_type_str = groups.get("event_type", "")
            source_ip = groups.get("ip", "")

            # Parse timestamp
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                timestamp = datetime.now(timezone.utc)

            event_type = EventType.NETWORK
            severity = EventSeverity.MEDIUM
            action = event_type_str.lower().replace(" ", "_")

            parsed_fields = {
                "session_id": session_id,
                "honeypot_type": "ssh",
            }

            # Check for login attempt details
            auth_match = self.COWRIE_AUTH_PATTERN.search(line)
            if auth_match:
                event_type = EventType.AUTHENTICATION
                parsed_fields["username"] = auth_match.group("username")
                parsed_fields["password"] = auth_match.group("password")
                success = auth_match.group("result").lower() == "succeeded"
                parsed_fields["success"] = success
                severity = EventSeverity.HIGH if success else EventSeverity.MEDIUM
                action = "login_success" if success else "login_failed"

            # Check for command
            cmd_match = self.COWRIE_CMD_PATTERN.search(line)
            if cmd_match:
                command = cmd_match.group("command")
                parsed_fields["command"] = command
                action = "command"
                event_type = EventType.APPLICATION

                # Check for malware
                for pattern in self.MALWARE_PATTERNS:
                    if pattern.search(command):
                        severity = EventSeverity.CRITICAL
                        parsed_fields["malware_indicator"] = True
                        break

            return ParseResult(
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                raw_message=line,
                client_ip=source_ip,
                action=action,
                parsed_fields=parsed_fields,
            )

        except Exception as e:
            logger.warning("cowrie_text_parse_error", error=str(e), line=line)
            return None

    def _parse_http_text(self, line: str, match: re.Match) -> ParseResult | None:
        """Parse HTTP honeypot log format.

        Args:
            line: Full log line.
            match: Regex match object.

        Returns:
            ParseResult or None.
        """
        try:
            groups = match.groupdict()
            source_ip = groups.get("ip", "")
            timestamp_str = groups.get("timestamp", "")
            method = groups.get("method", "")
            path = groups.get("path", "")
            status = groups.get("status", "")

            # Parse timestamp (common log format)
            try:
                # Format: 10/Oct/2000:13:55:36 -0700
                timestamp = datetime.strptime(
                    timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S"
                ).replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                timestamp = datetime.now(timezone.utc)

            event_type = EventType.APPLICATION
            severity = EventSeverity.LOW
            action = "http_request"

            parsed_fields = {
                "honeypot_type": "http",
                "method": method,
                "path": path,
                "status_code": status,
            }

            # Check for SQL injection
            for pattern in self.SQL_INJECTION_PATTERNS:
                if pattern.search(path):
                    severity = EventSeverity.HIGH
                    action = "sql_injection"
                    parsed_fields["attack_type"] = "sql_injection"
                    break

            # Check for command injection
            for pattern in self.COMMAND_INJECTION_PATTERNS:
                if pattern.search(path):
                    severity = EventSeverity.CRITICAL
                    action = "command_injection"
                    parsed_fields["attack_type"] = "command_injection"
                    break

            # Path traversal
            if "../" in path or "..%2f" in path.lower():
                severity = EventSeverity.HIGH
                action = "path_traversal"
                parsed_fields["attack_type"] = "path_traversal"

            return ParseResult(
                timestamp=timestamp,
                event_type=event_type,
                severity=severity,
                raw_message=line,
                client_ip=source_ip,
                action=action,
                response_status=status,
                parsed_fields=parsed_fields,
            )

        except Exception as e:
            logger.warning("http_parse_error", error=str(e), line=line)
            return None

    def _parse_generic_text(self, line: str) -> ParseResult | None:
        """Parse generic text log line.

        Args:
            line: Log line.

        Returns:
            ParseResult or None.
        """
        # Extract IP address if present
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        source_ip = ip_match.group(1) if ip_match else ""

        # Check for attack indicators
        severity = EventSeverity.LOW
        action = "interaction"

        for pattern in self.MALWARE_PATTERNS:
            if pattern.search(line):
                severity = EventSeverity.CRITICAL
                action = "malware_indicator"
                break

        for pattern in self.SQL_INJECTION_PATTERNS:
            if pattern.search(line):
                severity = EventSeverity.HIGH
                action = "sql_injection"
                break

        for pattern in self.COMMAND_INJECTION_PATTERNS:
            if pattern.search(line):
                severity = EventSeverity.CRITICAL
                action = "command_injection"
                break

        return ParseResult(
            timestamp=datetime.now(timezone.utc),
            event_type=EventType.NETWORK,
            severity=severity,
            raw_message=line,
            client_ip=source_ip,
            action=action,
            parsed_fields={},
        )

    def extract_threat_indicators(self, parsed_fields: dict) -> dict:
        """Extract threat indicators (IOCs) from parsed fields.

        Args:
            parsed_fields: Parsed data from honeypot interaction.

        Returns:
            Dict of threat indicators.
        """
        indicators = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "commands": [],
            "usernames": [],
            "passwords": [],
        }

        # Extract IPs
        if "download_url" in parsed_fields:
            url = parsed_fields["download_url"]
            indicators["urls"].append(url)
            # Extract domain from URL
            domain_match = re.search(r"https?://([^/]+)", url)
            if domain_match:
                indicators["domains"].append(domain_match.group(1))

        # Extract hashes
        for hash_type in ["md5", "sha256", "sha1"]:
            if hash_type in parsed_fields:
                indicators["hashes"].append({
                    "type": hash_type,
                    "value": parsed_fields[hash_type],
                })

        # Extract credentials
        if "username" in parsed_fields:
            indicators["usernames"].append(parsed_fields["username"])
        if "password" in parsed_fields:
            indicators["passwords"].append(parsed_fields["password"])

        # Extract commands
        if "command" in parsed_fields:
            indicators["commands"].append(parsed_fields["command"])

        # Remove empty lists
        return {k: v for k, v in indicators.items() if v}
