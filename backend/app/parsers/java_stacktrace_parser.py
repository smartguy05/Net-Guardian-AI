"""Java stack trace and exception log parser."""

import re
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


@register_parser("java_stacktrace")
class JavaStacktraceParser(BaseParser):
    """Parser for Java application logs with stack trace support.

    Handles common Java logging formats:
    - Log4j/Logback pattern layouts
    - java.util.logging formats
    - Spring Boot default format

    Features:
    - Multi-line stack trace aggregation
    - Exception chain parsing (Caused by)
    - Root cause extraction
    - Security exception detection

    Configuration options:
        timestamp_format: strptime format for timestamps
        timestamp_pattern: Regex to extract timestamp from log line
        detect_security_exceptions: Enable security pattern detection (default: True)
    """

    # Common Java timestamp patterns
    TIMESTAMP_PATTERNS = [
        # ISO 8601
        r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:?\d{2})?)",
        # Common Log4j format
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})",
        # Date with milliseconds
        r"(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d{3})",
    ]

    # Log level patterns
    LOG_LEVEL_PATTERN = re.compile(
        r"\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|SEVERE)\b",
        re.IGNORECASE,
    )

    # Stack frame pattern: at com.example.Class.method(File.java:123)
    STACK_FRAME_PATTERN = re.compile(
        r"^\s*at\s+([a-zA-Z0-9_.$]+)\.([a-zA-Z0-9_$<>]+)"
        r"\(([^:)]+):?(\d+)?\)",
        re.MULTILINE,
    )

    # Exception pattern: java.lang.NullPointerException: message
    EXCEPTION_PATTERN = re.compile(
        r"^([a-zA-Z0-9_.$]+(?:Exception|Error|Throwable)):\s*(.*)$",
        re.MULTILINE,
    )

    # Caused by pattern
    CAUSED_BY_PATTERN = re.compile(
        r"^Caused by:\s*([a-zA-Z0-9_.$]+(?:Exception|Error|Throwable)):\s*(.*)$",
        re.MULTILINE,
    )

    # Security-related exceptions
    SECURITY_EXCEPTIONS = {
        "java.sql.SQLException": "sql_injection",
        "org.hibernate.exception.SQLGrammarException": "sql_injection",
        "java.security.AccessControlException": "auth_bypass",
        "javax.security.auth.login.LoginException": "auth_failure",
        "java.lang.SecurityException": "security",
        "javax.naming.NamingException": "jndi_injection",
        "javax.naming.directory.InvalidSearchFilterException": "ldap_injection",
        "org.xml.sax.SAXParseException": "xxe",
        "javax.xml.stream.XMLStreamException": "xxe",
        "java.io.FileNotFoundException": "path_traversal",
        "java.nio.file.AccessDeniedException": "path_traversal",
        "com.fasterxml.jackson.databind.exc.InvalidTypeIdException": "deserialization",
        "java.io.InvalidClassException": "deserialization",
        "java.lang.ClassNotFoundException": "deserialization",
    }

    # Deserialization gadget indicators
    GADGET_PATTERNS = [
        "org.apache.commons.collections.functors.InvokerTransformer",
        "org.apache.commons.collections4.functors.InvokerTransformer",
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "org.springframework.beans.factory.config.PropertyPathFactoryBean",
        "java.lang.Runtime.getRuntime",
        "org.apache.commons.beanutils.BeanComparator",
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.timestamp_format = self.config.get("timestamp_format")
        self.timestamp_pattern = self.config.get("timestamp_pattern")
        self.detect_security = self.config.get("detect_security_exceptions", True)
        self._multiline_buffer: list[str] = []
        self._current_timestamp: datetime | None = None

    def _parse_timestamp(self, line: str) -> datetime | None:
        """Extract and parse timestamp from log line."""
        if self.timestamp_pattern:
            match = re.search(self.timestamp_pattern, line)
            if match:
                ts_str = match.group(1)
                if self.timestamp_format:
                    try:
                        return datetime.strptime(ts_str, self.timestamp_format).replace(
                            tzinfo=UTC
                        )
                    except ValueError:
                        pass

        for pattern in self.TIMESTAMP_PATTERNS:
            match = re.search(pattern, line)
            if match:
                ts_str = match.group(1)
                return self._parse_timestamp_string(ts_str)

        return None

    def _parse_timestamp_string(self, ts_str: str) -> datetime:
        """Parse various timestamp string formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S,%f",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%d-%b-%Y %H:%M:%S.%f",
        ]

        # Normalize timezone format
        ts_str = ts_str.replace("Z", "+00:00")
        if len(ts_str) > 5 and ts_str[-3] != ":" and ts_str[-5] in "+-":
            ts_str = ts_str[:-2] + ":" + ts_str[-2:]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            except ValueError:
                continue

        return datetime.now(UTC)

    def _get_log_level(self, line: str) -> EventSeverity:
        """Extract log level from line and map to severity."""
        match = self.LOG_LEVEL_PATTERN.search(line)
        if match:
            level = match.group(1).upper()
            level_map = {
                "TRACE": EventSeverity.DEBUG,
                "DEBUG": EventSeverity.DEBUG,
                "INFO": EventSeverity.INFO,
                "WARN": EventSeverity.WARNING,
                "WARNING": EventSeverity.WARNING,
                "ERROR": EventSeverity.ERROR,
                "FATAL": EventSeverity.CRITICAL,
                "SEVERE": EventSeverity.ERROR,
            }
            return level_map.get(level, EventSeverity.INFO)

        return EventSeverity.INFO

    def _is_stack_frame(self, line: str) -> bool:
        """Check if line is a stack trace frame."""
        stripped = line.strip()
        return stripped.startswith("at ") or stripped.startswith("...")

    def _is_exception_line(self, line: str) -> bool:
        """Check if line starts an exception."""
        return bool(self.EXCEPTION_PATTERN.match(line.strip()))

    def _is_caused_by(self, line: str) -> bool:
        """Check if line is a 'Caused by' line."""
        return line.strip().startswith("Caused by:")

    def _parse_stack_trace(self, content: str) -> dict[str, Any]:
        """Parse a complete stack trace."""
        result: dict[str, Any] = {
            "exception_type": None,
            "exception_message": None,
            "stack_frames": [],
            "caused_by": [],
            "root_cause": None,
        }

        # Extract main exception
        exc_match = self.EXCEPTION_PATTERN.search(content)
        if exc_match:
            result["exception_type"] = exc_match.group(1)
            result["exception_message"] = exc_match.group(2).strip()

        # Extract stack frames
        for match in self.STACK_FRAME_PATTERN.finditer(content):
            frame = {
                "class": match.group(1),
                "method": match.group(2),
                "file": match.group(3),
                "line": int(match.group(4)) if match.group(4) else None,
            }
            result["stack_frames"].append(frame)

        # Extract caused by chain
        for match in self.CAUSED_BY_PATTERN.finditer(content):
            caused_by = {
                "exception_type": match.group(1),
                "exception_message": match.group(2).strip(),
            }
            result["caused_by"].append(caused_by)
            # Last caused by is the root cause
            result["root_cause"] = caused_by

        return result

    def _detect_security_issues(
        self, stack_trace: dict[str, Any], content: str
    ) -> list[dict[str, Any]]:
        """Detect security-related patterns in the stack trace."""
        issues: list[dict[str, Any]] = []

        if not self.detect_security:
            return issues

        # Check exception type
        exc_type = stack_trace.get("exception_type", "")
        for exc_class, issue_type in self.SECURITY_EXCEPTIONS.items():
            if exc_class in exc_type:
                issues.append({
                    "type": issue_type,
                    "indicator": f"Security exception: {exc_type}",
                    "severity": "high",
                })

        # Check caused by exceptions
        for caused_by in stack_trace.get("caused_by", []):
            exc_type = caused_by.get("exception_type", "")
            for exc_class, issue_type in self.SECURITY_EXCEPTIONS.items():
                if exc_class in exc_type:
                    issues.append({
                        "type": issue_type,
                        "indicator": f"Root cause exception: {exc_type}",
                        "severity": "high",
                    })

        # Check for deserialization gadgets
        for gadget in self.GADGET_PATTERNS:
            if gadget in content:
                issues.append({
                    "type": "deserialization_attack",
                    "indicator": f"Gadget chain detected: {gadget}",
                    "severity": "critical",
                })

        # Check for SQL injection patterns in message
        exc_message = stack_trace.get("exception_message", "")
        sql_patterns = [
            r"(?i)syntax error",
            r"(?i)sql syntax",
            r"(?i)unexpected token",
            r"(?i)unterminated string",
        ]
        for pattern in sql_patterns:
            if re.search(pattern, exc_message):
                issues.append({
                    "type": "sql_injection",
                    "indicator": f"SQL error in message: {exc_message[:100]}",
                    "severity": "high",
                })
                break

        return issues

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse Java log data with stack traces.

        Args:
            raw_data: Log content as string or list of log entries.
        """
        results = []

        if isinstance(raw_data, str):
            results = self._parse_multiline(raw_data)
        elif isinstance(raw_data, list):
            for entry in raw_data:
                if isinstance(entry, str):
                    results.extend(self._parse_multiline(entry))
                elif isinstance(entry, dict):
                    # Handle structured log entry
                    message = entry.get("message", entry.get("msg", ""))
                    timestamp = entry.get("timestamp", entry.get("time"))
                    level = entry.get("level", entry.get("severity", "INFO"))
                    result = self._parse_structured_entry(entry, message, timestamp, level)
                    if result:
                        results.append(result)
        else:
            logger.warning("java_invalid_data", data_type=type(raw_data).__name__)

        return results

    def _parse_multiline(self, content: str) -> list[ParseResult]:
        """Parse multi-line log content with stack trace aggregation."""
        results = []
        lines = content.split("\n")
        current_entry: list[str] = []
        current_timestamp: datetime | None = None
        in_stack_trace = False

        for line in lines:
            # Check if this is a new log entry
            timestamp = self._parse_timestamp(line)
            is_new_entry = timestamp is not None and not in_stack_trace

            if is_new_entry and current_entry:
                # Process previous entry
                result = self._process_entry(current_entry, current_timestamp)
                if result:
                    results.append(result)
                current_entry = []
                in_stack_trace = False

            if timestamp:
                current_timestamp = timestamp

            # Track if we're in a stack trace
            if self._is_exception_line(line) or self._is_caused_by(line):
                in_stack_trace = True
            elif self._is_stack_frame(line):
                in_stack_trace = True
            elif line.strip() and not line.startswith("\t") and timestamp:
                in_stack_trace = False

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

        # Get basic info
        severity = self._get_log_level(first_line)
        timestamp = timestamp or datetime.now(UTC)

        # Parse stack trace if present
        stack_trace = self._parse_stack_trace(content)
        has_exception = stack_trace["exception_type"] is not None

        # Build parsed fields
        parsed_fields: dict[str, Any] = {
            "log_level": severity.value,
        }

        if has_exception:
            parsed_fields["exception_type"] = stack_trace["exception_type"]
            parsed_fields["exception_message"] = stack_trace["exception_message"]
            parsed_fields["stack_frames"] = stack_trace["stack_frames"][:20]  # Limit
            if stack_trace["root_cause"]:
                parsed_fields["root_cause"] = stack_trace["root_cause"]
            parsed_fields["stack_depth"] = len(stack_trace["stack_frames"])

            # Detect security issues
            security_issues = self._detect_security_issues(stack_trace, content)
            if security_issues:
                parsed_fields["security_issues"] = security_issues
                # Elevate severity for security issues
                if any(i["severity"] == "critical" for i in security_issues):
                    severity = EventSeverity.CRITICAL
                elif any(i["severity"] == "high" for i in security_issues):
                    severity = EventSeverity.ERROR

        # Extract thread name if present
        thread_match = re.search(r"\[([^\]]+)\]", first_line)
        if thread_match:
            parsed_fields["thread_name"] = thread_match.group(1)

        # Extract logger name if present
        logger_match = re.search(r"([a-zA-Z0-9_.]+)\s*[-:]\s", first_line)
        if logger_match:
            parsed_fields["logger"] = logger_match.group(1)

        # Build raw message (truncate stack trace for readability)
        if has_exception:
            raw_message = f"{stack_trace['exception_type']}: {stack_trace['exception_message']}"
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
            protocol="java",
            action="exception" if has_exception else None,
            response_status=None,
            parsed_fields=parsed_fields,
        )

    def _parse_structured_entry(
        self,
        entry: dict[str, Any],
        message: str,
        timestamp: Any,
        level: str,
    ) -> ParseResult | None:
        """Parse a structured log entry (e.g., from logstash-logback-encoder)."""
        if not message:
            return None

        # Parse timestamp
        if isinstance(timestamp, str):
            ts = self._parse_timestamp_string(timestamp)
        elif isinstance(timestamp, (int, float)):
            ts = datetime.fromtimestamp(timestamp / 1000, tz=UTC)
        else:
            ts = datetime.now(UTC)

        # Map level
        level_str = str(level).upper()
        level_map = {
            "TRACE": EventSeverity.DEBUG,
            "DEBUG": EventSeverity.DEBUG,
            "INFO": EventSeverity.INFO,
            "WARN": EventSeverity.WARNING,
            "WARNING": EventSeverity.WARNING,
            "ERROR": EventSeverity.ERROR,
            "FATAL": EventSeverity.CRITICAL,
        }
        severity = level_map.get(level_str, EventSeverity.INFO)

        # Build parsed fields from structured data
        parsed_fields: dict[str, Any] = {
            "log_level": level_str,
            "logger": entry.get("logger_name", entry.get("logger")),
            "thread_name": entry.get("thread_name", entry.get("thread")),
        }

        # Handle stack trace in structured format
        stack_trace = entry.get("stack_trace", entry.get("exception"))
        if stack_trace:
            if isinstance(stack_trace, str):
                parsed_trace = self._parse_stack_trace(stack_trace)
                if parsed_trace["exception_type"]:
                    parsed_fields["exception_type"] = parsed_trace["exception_type"]
                    parsed_fields["exception_message"] = parsed_trace["exception_message"]
                    parsed_fields["stack_frames"] = parsed_trace["stack_frames"][:20]
                    if parsed_trace["root_cause"]:
                        parsed_fields["root_cause"] = parsed_trace["root_cause"]

        # Copy additional context
        for key in ["mdc", "context", "markers"]:
            if key in entry:
                parsed_fields[key] = entry[key]

        return ParseResult(
            timestamp=ts,
            event_type=EventType.APPLICATION,
            severity=severity,
            raw_message=message[:500],
            client_ip=None,
            target_ip=None,
            domain=None,
            port=None,
            protocol="java",
            action="exception" if stack_trace else None,
            response_status=None,
            parsed_fields=parsed_fields,
        )
