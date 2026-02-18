"""Python logging module log parser."""

import json
import re
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("python_log")
class PythonLogParser(BaseParser):
    """Parser for Python logging module output.

    Handles common Python logging formats:
    - Default logging module format
    - structlog JSON format
    - Custom formats with timestamp/level/message

    Features:
    - Python traceback parsing
    - Multi-line exception handling
    - structlog JSON support
    - Security exception detection

    Configuration options:
        format: Log format pattern (auto-detect if not specified)
        timestamp_format: strptime format for timestamps
        json_mode: Force JSON parsing mode (default: auto-detect)
    """

    # Common Python timestamp patterns
    TIMESTAMP_PATTERNS = [
        # ISO format: 2024-01-15 10:30:45,123
        (r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})", "%Y-%m-%d %H:%M:%S,%f"),
        # ISO format with dot: 2024-01-15 10:30:45.123
        (r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})", "%Y-%m-%d %H:%M:%S.%f"),
        # ISO 8601
        (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", "%Y-%m-%dT%H:%M:%S"),
        # Basic: 2024-01-15 10:30:45
        (r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})", "%Y-%m-%d %H:%M:%S"),
    ]

    # Log level pattern
    LOG_LEVEL_PATTERN = re.compile(
        r"\b(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)\b",
        re.IGNORECASE,
    )

    # Python traceback patterns
    TRACEBACK_START = re.compile(r"Traceback \(most recent call last\):")
    FRAME_PATTERN = re.compile(
        r'^\s+File "([^"]+)", line (\d+), in (\S+)',
        re.MULTILINE,
    )
    EXCEPTION_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)(?:Exception|Error):\s*(.*)$")

    # Security-related exceptions
    SECURITY_EXCEPTIONS = {
        "sqlite3.OperationalError": "sql_injection",
        "psycopg2.ProgrammingError": "sql_injection",
        "MySQLdb.ProgrammingError": "sql_injection",
        "sqlalchemy.exc.ProgrammingError": "sql_injection",
        "subprocess.CalledProcessError": "command_injection",
        "PermissionError": "auth_bypass",
        "FileNotFoundError": "path_traversal",
        "IsADirectoryError": "path_traversal",
        "pickle.UnpicklingError": "deserialization",
        "yaml.scanner.ScannerError": "deserialization",
        "xml.etree.ElementTree.ParseError": "xxe",
        "lxml.etree.XMLSyntaxError": "xxe",
        "jwt.exceptions.DecodeError": "auth_bypass",
        "jwt.exceptions.InvalidTokenError": "auth_bypass",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.timestamp_format = self.config.get("timestamp_format")
        self.json_mode = self.config.get("json_mode")

    def _parse_timestamp(self, text: str) -> datetime | None:
        """Extract and parse timestamp from log line."""
        if self.timestamp_format:
            # Try custom format
            for pattern, _ in self.TIMESTAMP_PATTERNS:
                match = re.search(pattern, text)
                if match:
                    try:
                        return datetime.strptime(match.group(1), self.timestamp_format).replace(
                            tzinfo=UTC
                        )
                    except ValueError:
                        continue

        # Try standard patterns
        for pattern, fmt in self.TIMESTAMP_PATTERNS:
            match = re.search(pattern, text)
            if match:
                try:
                    return datetime.strptime(match.group(1), fmt).replace(tzinfo=UTC)
                except ValueError:
                    continue

        return None

    def _get_log_level(self, text: str) -> EventSeverity:
        """Extract log level and map to severity."""
        match = self.LOG_LEVEL_PATTERN.search(text)
        if match:
            level = match.group(1).upper()
            level_map = {
                "DEBUG": EventSeverity.DEBUG,
                "INFO": EventSeverity.INFO,
                "WARNING": EventSeverity.WARNING,
                "WARN": EventSeverity.WARNING,
                "ERROR": EventSeverity.ERROR,
                "CRITICAL": EventSeverity.CRITICAL,
                "FATAL": EventSeverity.CRITICAL,
            }
            return level_map.get(level, EventSeverity.INFO)

        return EventSeverity.INFO

    def _parse_traceback(self, content: str) -> dict[str, Any] | None:
        """Parse a Python traceback."""
        if not self.TRACEBACK_START.search(content):
            return None

        result: dict[str, Any] = {
            "frames": [],
            "exception_type": None,
            "exception_message": None,
        }

        # Extract frames
        for match in self.FRAME_PATTERN.finditer(content):
            frame = {
                "file": match.group(1),
                "line": int(match.group(2)),
                "function": match.group(3),
            }
            result["frames"].append(frame)

        # Extract exception line (last line after traceback)
        lines = content.split("\n")
        for line in reversed(lines):
            line = line.strip()
            if line and not line.startswith("File ") and not line.startswith("Traceback"):
                # Check if it's an exception line
                if "Error" in line or "Exception" in line:
                    parts = line.split(":", 1)
                    result["exception_type"] = parts[0].strip()
                    if len(parts) > 1:
                        result["exception_message"] = parts[1].strip()
                    break

        return result if result["frames"] or result["exception_type"] else None

    def _detect_security_issues(
        self,
        traceback: dict[str, Any] | None,
        content: str,
    ) -> list[dict[str, Any]]:
        """Detect security-related issues."""
        issues: list[dict[str, Any]] = []

        if traceback and traceback.get("exception_type"):
            exc_type = traceback["exception_type"]
            for exc_class, issue_type in self.SECURITY_EXCEPTIONS.items():
                if exc_class in exc_type:
                    issues.append(
                        {
                            "type": issue_type,
                            "indicator": f"Security exception: {exc_type}",
                            "severity": "high",
                        }
                    )

        # Check for SQL patterns in error messages
        sql_indicators = [
            r"(?i)syntax error.*near",
            r"(?i)you have an error in your sql syntax",
            r"(?i)unclosed quotation mark",
            r"(?i)unterminated string literal",
        ]
        for pattern in sql_indicators:
            if re.search(pattern, content):
                issues.append(
                    {
                        "type": "sql_injection",
                        "indicator": "SQL syntax error in logs",
                        "severity": "high",
                    }
                )
                break

        # Check for command injection indicators
        cmd_indicators = [
            r"(?i)command not found",
            r"(?i)sh: .+: not found",
            r"(?i)returned non-zero exit status",
        ]
        for pattern in cmd_indicators:
            if re.search(pattern, content):
                issues.append(
                    {
                        "type": "command_injection",
                        "indicator": "Command execution error",
                        "severity": "medium",
                    }
                )
                break

        return issues

    def _is_json_line(self, line: str) -> bool:
        """Check if a line appears to be JSON."""
        stripped = line.strip()
        return stripped.startswith("{") and stripped.endswith("}")

    def _parse_json_entry(self, line: str) -> ParseResult | None:
        """Parse a JSON-formatted log entry (structlog style)."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        # Extract fields - handle various structlog/JSON logging conventions
        message = data.get("event") or data.get("message") or data.get("msg") or ""
        timestamp_raw = data.get("timestamp") or data.get("time") or data.get("ts")
        level = data.get("level") or data.get("severity") or data.get("levelname") or "INFO"

        # Parse timestamp
        if isinstance(timestamp_raw, str):
            timestamp = self._parse_timestamp(timestamp_raw)
            if not timestamp:
                try:
                    timestamp = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.now(UTC)
        elif isinstance(timestamp_raw, (int, float)):
            # Unix timestamp (possibly in milliseconds)
            if timestamp_raw > 1e12:
                timestamp_raw /= 1000
            timestamp = datetime.fromtimestamp(timestamp_raw, tz=UTC)
        else:
            timestamp = datetime.now(UTC)

        # Map level to severity
        level_str = str(level).upper()
        level_map = {
            "DEBUG": EventSeverity.DEBUG,
            "INFO": EventSeverity.INFO,
            "WARNING": EventSeverity.WARNING,
            "WARN": EventSeverity.WARNING,
            "ERROR": EventSeverity.ERROR,
            "CRITICAL": EventSeverity.CRITICAL,
            "FATAL": EventSeverity.CRITICAL,
        }
        severity = level_map.get(level_str, EventSeverity.INFO)

        # Build parsed fields from JSON data
        parsed_fields: dict[str, Any] = {
            "log_level": level_str,
        }

        # Extract common structlog fields
        for key in ["logger", "logger_name", "module", "func_name", "lineno"]:
            if key in data:
                parsed_fields[key] = data[key]

        # Handle exception info
        exc_info = data.get("exc_info") or data.get("exception")
        if exc_info:
            if isinstance(exc_info, str):
                traceback = self._parse_traceback(exc_info)
                if traceback:
                    parsed_fields["traceback"] = traceback
            elif isinstance(exc_info, dict):
                parsed_fields["exception_type"] = exc_info.get("type")
                parsed_fields["exception_message"] = exc_info.get("message")

        # Copy additional context fields
        skip_keys = {
            "event",
            "message",
            "msg",
            "timestamp",
            "time",
            "ts",
            "level",
            "severity",
            "levelname",
            "logger",
            "logger_name",
            "exc_info",
            "exception",
            "module",
            "func_name",
            "lineno",
        }
        for key, value in data.items():
            if key not in skip_keys and not key.startswith("_"):
                parsed_fields[key] = value

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.APPLICATION,
            severity=severity,
            raw_message=str(message)[:500],
            client_ip=None,
            target_ip=None,
            domain=None,
            port=None,
            protocol="python",
            action="exception" if exc_info else None,
            response_status=None,
            parsed_fields=parsed_fields,
        )

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse Python log data.

        Args:
            raw_data: Log content as string, list of lines, or JSON entries.
        """
        results = []

        if isinstance(raw_data, str):
            # Check if it's JSON lines
            if self.json_mode or (
                self.json_mode is None and self._is_json_line(raw_data.split("\n")[0])
            ):
                for line in raw_data.split("\n"):
                    if line.strip():
                        result = self._parse_json_entry(line)
                        if result:
                            results.append(result)
            else:
                results = self._parse_multiline(raw_data)

        elif isinstance(raw_data, list):
            for entry in raw_data:
                if isinstance(entry, str):
                    if self._is_json_line(entry):
                        result = self._parse_json_entry(entry)
                    else:
                        # Treat as single log line
                        partial = self._parse_multiline(entry)
                        result = partial[0] if partial else None
                    if result:
                        results.append(result)
                elif isinstance(entry, dict):
                    result = self._parse_json_entry(json.dumps(entry))
                    if result:
                        results.append(result)

        else:
            logger.warning("python_log_invalid_data", data_type=type(raw_data).__name__)

        return results

    def _parse_multiline(self, content: str) -> list[ParseResult]:
        """Parse multi-line log content with traceback aggregation."""
        results = []
        lines = content.split("\n")
        current_entry: list[str] = []
        current_timestamp: datetime | None = None
        in_traceback = False

        for line in lines:
            # Check for new log entry (has timestamp)
            timestamp = self._parse_timestamp(line)
            is_new_entry = timestamp is not None and not in_traceback

            # Check for traceback start
            if self.TRACEBACK_START.search(line):
                in_traceback = True

            # Check for traceback continuation
            is_traceback_line = (
                line.strip().startswith("File ")
                or line.strip().startswith("Traceback")
                or (in_traceback and line.startswith("    "))
            )

            if is_new_entry and current_entry and not is_traceback_line:
                # Process previous entry
                result = self._process_entry(current_entry, current_timestamp)
                if result:
                    results.append(result)
                current_entry = []
                in_traceback = False

            if timestamp:
                current_timestamp = timestamp

            # Check if traceback ends (non-indented line after frames)
            if in_traceback and line and not line.startswith(" ") and not line.startswith("\t"):
                if "Error" in line or "Exception" in line:
                    current_entry.append(line)
                    in_traceback = False
                    # Process immediately
                    result = self._process_entry(current_entry, current_timestamp)
                    if result:
                        results.append(result)
                    current_entry = []
                    continue

            current_entry.append(line)

        # Process final entry
        if current_entry:
            result = self._process_entry(current_entry, current_timestamp)
            if result:
                results.append(result)

        return results

    def _process_entry(
        self,
        lines: list[str],
        timestamp: datetime | None,
    ) -> ParseResult | None:
        """Process a collected log entry."""
        if not lines:
            return None

        content = "\n".join(lines)
        first_line = lines[0]

        if not first_line.strip():
            return None

        # Get basic info
        severity = self._get_log_level(first_line)
        timestamp = timestamp or datetime.now(UTC)

        # Parse traceback if present
        traceback = self._parse_traceback(content)

        # Build parsed fields
        parsed_fields: dict[str, Any] = {
            "log_level": severity.value.upper(),
        }

        if traceback:
            parsed_fields["traceback"] = traceback
            parsed_fields["exception_type"] = traceback.get("exception_type")
            parsed_fields["exception_message"] = traceback.get("exception_message")
            parsed_fields["frame_count"] = len(traceback.get("frames", []))

            # Detect security issues
            security_issues = self._detect_security_issues(traceback, content)
            if security_issues:
                parsed_fields["security_issues"] = security_issues
                if any(i["severity"] == "high" for i in security_issues):
                    severity = EventSeverity.ERROR

        # Extract logger name if present (common format: logger - level - message)
        logger_match = re.search(r"^([a-zA-Z0-9_.]+)\s*[-:]\s*\w+\s*[-:]\s*", first_line)
        if logger_match:
            parsed_fields["logger"] = logger_match.group(1)

        # Build raw message
        if traceback and traceback.get("exception_type"):
            raw_message = f"{traceback['exception_type']}: {traceback.get('exception_message', '')}"
        else:
            raw_message = first_line

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.APPLICATION,
            severity=severity,
            raw_message=raw_message[:500],
            client_ip=None,
            target_ip=None,
            domain=None,
            port=None,
            protocol="python",
            action="exception" if traceback else None,
            response_status=None,
            parsed_fields=parsed_fields,
        )
