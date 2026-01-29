"""Nginx access and error log parser."""

import re
from datetime import UTC, datetime
from typing import Any

import structlog

from app.models.raw_event import EventSeverity, EventType
from app.parsers.base import BaseParser, ParseResult
from app.parsers.registry import register_parser

logger = structlog.get_logger()


# Nginx combined log format pattern:
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
# Example: 192.168.1.1 - - [28/Jan/2026:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
NGINX_COMBINED_PATTERN = re.compile(
    r"^(?P<remote_addr>\S+)\s+"  # Client IP
    r"-\s+"  # Always a dash
    r"(?P<remote_user>\S+)\s+"  # Remote user (or -)
    r"\[(?P<time_local>[^\]]+)\]\s+"  # Timestamp in brackets
    r'"(?P<request>[^"]*)"\s+'  # Request line
    r"(?P<status>\d+)\s+"  # Status code
    r"(?P<body_bytes_sent>\d+)\s+"  # Response size
    r'"(?P<http_referer>[^"]*)"\s+'  # Referer
    r'"(?P<http_user_agent>[^"]*)"'  # User agent
)

# Nginx error log pattern:
# YYYY/MM/DD HH:MM:SS [level] PID#TID: *CID message
# Example: 2026/01/28 12:34:56 [error] 1234#5678: *999 message here
NGINX_ERROR_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>\w+)\]\s+"
    r"(?P<pid>\d+)#(?P<tid>\d+):\s+"
    r"(?:\*(?P<cid>\d+)\s+)?"
    r"(?P<message>.*)$"
)

# Nginx error levels to severity mapping
NGINX_ERROR_LEVELS = {
    "debug": EventSeverity.DEBUG,
    "info": EventSeverity.INFO,
    "notice": EventSeverity.INFO,
    "warn": EventSeverity.WARNING,
    "error": EventSeverity.ERROR,
    "crit": EventSeverity.CRITICAL,
    "alert": EventSeverity.CRITICAL,
    "emerg": EventSeverity.CRITICAL,
}


def _status_to_severity(status: int) -> EventSeverity:
    """Convert HTTP status code to severity."""
    if status < 400:
        return EventSeverity.INFO
    elif status < 500:
        return EventSeverity.WARNING
    else:
        return EventSeverity.ERROR


@register_parser("nginx")
class NginxParser(BaseParser):
    """Parser for Nginx access and error logs.

    Supports:
    - Combined log format (default access log format)
    - Common log format
    - Error log format

    Configuration options:
        log_type: "access" or "error" (default: auto-detect)
    """

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.log_type = self.config.get("log_type", "auto")

    def _parse_access_timestamp(self, time_str: str) -> datetime:
        """Parse nginx access log timestamp format: 28/Jan/2026:12:34:56 +0000"""
        try:
            return datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                # Try without timezone
                dt = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S")
                return dt.replace(tzinfo=UTC)
            except ValueError:
                return datetime.now(UTC)

    def _parse_error_timestamp(self, time_str: str) -> datetime:
        """Parse nginx error log timestamp format: 2026/01/28 12:34:56"""
        try:
            dt = datetime.strptime(time_str, "%Y/%m/%d %H:%M:%S")
            return dt.replace(tzinfo=UTC)
        except ValueError:
            return datetime.now(UTC)

    def _parse_request(self, request: str) -> dict[str, str]:
        """Parse HTTP request line into method, path, protocol."""
        parts = request.split(" ", 2)
        result = {
            "method": parts[0] if len(parts) > 0 else "",
            "path": parts[1] if len(parts) > 1 else "",
            "protocol": parts[2] if len(parts) > 2 else "",
        }
        return result

    def _parse_access_line(self, line: str) -> ParseResult | None:
        """Parse nginx access log line."""
        match = NGINX_COMBINED_PATTERN.match(line)
        if not match:
            return None

        remote_addr = match.group("remote_addr")
        remote_user = match.group("remote_user")
        timestamp = self._parse_access_timestamp(match.group("time_local"))
        request = match.group("request")
        status = int(match.group("status"))
        body_bytes_sent = int(match.group("body_bytes_sent"))
        referer = match.group("http_referer")
        user_agent = match.group("http_user_agent")

        request_parts = self._parse_request(request)

        # Determine action based on status
        if status < 400:
            action = "allowed"
        elif status == 403:
            action = "forbidden"
        elif status == 404:
            action = "not_found"
        elif status < 500:
            action = "client_error"
        else:
            action = "server_error"

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.HTTP,
            severity=_status_to_severity(status),
            raw_message=line,
            client_ip=remote_addr if remote_addr != "-" else None,
            port=80,  # Default, could be parsed from Host header if available
            protocol="HTTP",
            action=action,
            response_status=str(status),
            parsed_fields={
                "remote_user": remote_user if remote_user != "-" else None,
                "method": request_parts["method"],
                "path": request_parts["path"],
                "http_version": request_parts["protocol"],
                "status_code": status,
                "body_bytes_sent": body_bytes_sent,
                "referer": referer if referer != "-" else None,
                "user_agent": user_agent,
                "request": request,
            },
        )

    def _parse_error_line(self, line: str) -> ParseResult | None:
        """Parse nginx error log line."""
        match = NGINX_ERROR_PATTERN.match(line)
        if not match:
            # Fallback for unmatched error lines
            return ParseResult(
                timestamp=datetime.now(UTC),
                event_type=EventType.SYSTEM,
                severity=EventSeverity.ERROR,
                raw_message=line,
                parsed_fields={"message": line},
            )

        timestamp = self._parse_error_timestamp(match.group("timestamp"))
        level = match.group("level").lower()
        pid = match.group("pid")
        tid = match.group("tid")
        cid = match.group("cid")
        message = match.group("message")

        # Try to extract client IP from error message
        client_ip = None
        ip_match = re.search(r"client:\s*(\d+\.\d+\.\d+\.\d+)", message)
        if ip_match:
            client_ip = ip_match.group(1)

        return ParseResult(
            timestamp=timestamp,
            event_type=EventType.SYSTEM,
            severity=NGINX_ERROR_LEVELS.get(level, EventSeverity.ERROR),
            raw_message=line,
            client_ip=client_ip,
            parsed_fields={
                "level": level,
                "pid": pid,
                "tid": tid,
                "connection_id": cid,
                "message": message,
            },
        )

    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse nginx log lines."""
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

                if self.log_type == "error":
                    result = self._parse_error_line(line)
                elif self.log_type == "access":
                    result = self._parse_access_line(line)
                else:
                    # Auto-detect: try access format first, then error
                    result = self._parse_access_line(line)
                    if not result:
                        result = self._parse_error_line(line)

                if result:
                    results.append(result)

            except Exception as e:
                logger.warning(
                    "nginx_parse_error",
                    error=str(e),
                    line=line[:200],
                )

        return results
