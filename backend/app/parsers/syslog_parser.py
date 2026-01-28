"""Syslog format parser (RFC 3164 and RFC 5424)."""

import re
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


# Syslog severity levels (RFC 5424)
SYSLOG_SEVERITY = {
    0: EventSeverity.CRITICAL,   # Emergency
    1: EventSeverity.CRITICAL,   # Alert
    2: EventSeverity.CRITICAL,   # Critical
    3: EventSeverity.ERROR,      # Error
    4: EventSeverity.WARNING,    # Warning
    5: EventSeverity.INFO,       # Notice
    6: EventSeverity.INFO,       # Informational
    7: EventSeverity.DEBUG,      # Debug
}

# Syslog facility names
SYSLOG_FACILITIES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "security", 14: "console", 15: "solaris-cron",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

# RFC 3164 pattern: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
RFC3164_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# RFC 5424 pattern: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
RFC5424_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>(?:\[.+?\])+|-)\s*"
    r"(?P<message>.*)$"
)

# Simple pattern for messages without PRI
SIMPLE_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<tag>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


@register_parser("syslog")
class SyslogParser(BaseParser):
    """Parser for syslog-formatted log messages.

    Supports RFC 3164 (BSD syslog) and RFC 5424 (modern syslog).

    Configuration options:
        default_facility: Default facility if not in message
        default_severity: Default severity if not in message
        year: Year to use for RFC 3164 timestamps (default: current year)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.default_facility = self.config.get("default_facility", 1)  # user
        self.default_severity = self.config.get("default_severity", 6)   # info
        self.year = self.config.get("year", datetime.now().year)

    def _parse_pri(self, pri: int) -> tuple[int, int]:
        """Parse PRI value into facility and severity."""
        facility = pri >> 3
        severity = pri & 0x07
        return facility, severity

    def _parse_rfc3164_timestamp(self, timestamp_str: str) -> datetime:
        """Parse RFC 3164 timestamp (e.g., 'Jan  5 12:34:56')."""
        # Handle double-space for single-digit days
        timestamp_str = re.sub(r"\s+", " ", timestamp_str)

        try:
            # Add year since RFC 3164 doesn't include it
            timestamp_with_year = f"{self.year} {timestamp_str}"
            dt = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)

    def _parse_rfc5424_timestamp(self, timestamp_str: str) -> datetime:
        """Parse RFC 5424 timestamp (ISO 8601)."""
        if timestamp_str == "-":
            return datetime.now(UTC)

        try:
            # Handle various ISO 8601 formats
            timestamp_str = timestamp_str.replace("Z", "+00:00")
            return datetime.fromisoformat(timestamp_str)
        except ValueError:
            return datetime.now(UTC)

    def _parse_rfc3164(self, line: str, match: re.Match) -> ParseResult | None:
        """Parse RFC 3164 format message."""
        pri = int(match.group("pri"))
        facility, severity = self._parse_pri(pri)

        timestamp = self._parse_rfc3164_timestamp(match.group("timestamp"))
        hostname = match.group("hostname")
        tag = match.group("tag")
        pid = match.group("pid")
        message = match.group("message")

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.SYSTEM,
            severity=SYSLOG_SEVERITY.get(severity, EventSeverity.INFO),
            raw_message=line,
            parsed_fields={
                "facility": SYSLOG_FACILITIES.get(facility, str(facility)),
                "facility_num": facility,
                "severity_num": severity,
                "hostname": hostname,
                "tag": tag,
                "pid": pid,
                "message": message,
            },
        )

    def _parse_rfc5424(self, line: str, match: re.Match) -> ParseResult | None:
        """Parse RFC 5424 format message."""
        pri = int(match.group("pri"))
        facility, severity = self._parse_pri(pri)

        timestamp = self._parse_rfc5424_timestamp(match.group("timestamp"))
        hostname = match.group("hostname") if match.group("hostname") != "-" else None
        appname = match.group("appname") if match.group("appname") != "-" else None
        procid = match.group("procid") if match.group("procid") != "-" else None
        msgid = match.group("msgid") if match.group("msgid") != "-" else None
        structured_data = match.group("structured_data")
        message = match.group("message")

        parsed_fields = {
            "facility": SYSLOG_FACILITIES.get(facility, str(facility)),
            "facility_num": facility,
            "severity_num": severity,
            "version": match.group("version"),
            "hostname": hostname,
            "appname": appname,
            "procid": procid,
            "msgid": msgid,
            "message": message,
        }

        # Parse structured data if present
        if structured_data and structured_data != "-":
            sd_pattern = re.compile(r'\[(\S+?)(?:\s+([^\]]+))?\]')
            for sd_match in sd_pattern.finditer(structured_data):
                sd_id = sd_match.group(1)
                sd_params = sd_match.group(2)
                if sd_params:
                    param_pattern = re.compile(r'(\S+)="([^"]*)"')
                    params = dict(param_pattern.findall(sd_params))
                    parsed_fields[f"sd_{sd_id}"] = params

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.SYSTEM,
            severity=SYSLOG_SEVERITY.get(severity, EventSeverity.INFO),
            raw_message=line,
            parsed_fields=parsed_fields,
        )

    def _parse_simple(self, line: str, match: re.Match) -> ParseResult | None:
        """Parse simple syslog format without PRI."""
        timestamp = self._parse_rfc3164_timestamp(match.group("timestamp"))
        hostname = match.group("hostname")
        tag = match.group("tag")
        pid = match.group("pid")
        message = match.group("message")

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.SYSTEM,
            severity=SYSLOG_SEVERITY.get(self.default_severity, EventSeverity.INFO),
            raw_message=line,
            parsed_fields={
                "facility": SYSLOG_FACILITIES.get(self.default_facility, "user"),
                "facility_num": self.default_facility,
                "severity_num": self.default_severity,
                "hostname": hostname,
                "tag": tag,
                "pid": pid,
                "message": message,
            },
        )

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse syslog messages."""
        results = []

        # Handle single string or list of strings
        if isinstance(raw_data, str):
            lines = raw_data.strip().split("\n")
        elif isinstance(raw_data, list):
            lines = raw_data
        else:
            lines = [str(raw_data)]

        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                result = None

                # Try RFC 5424 first
                match = RFC5424_PATTERN.match(line)
                if match:
                    result = self._parse_rfc5424(line, match)
                else:
                    # Try RFC 3164
                    match = RFC3164_PATTERN.match(line)
                    if match:
                        result = self._parse_rfc3164(line, match)
                    else:
                        # Try simple format
                        match = SIMPLE_PATTERN.match(line)
                        if match:
                            result = self._parse_simple(line, match)
                        else:
                            # Fallback: treat entire line as message
                            result = ParseResult(
                                timestamp=datetime.now(UTC),
                                event_type=EventType.SYSTEM,
                                severity=EventSeverity.INFO,
                                raw_message=line,
                                parsed_fields={"message": line},
                            )

                if result:
                    results.append(result)

            except Exception as e:
                logger.warning(
                    "syslog_parse_error",
                    error=str(e),
                    line=line[:200],
                )

        return results
