"""Tests for the Nginx parser.

Tests cover:
- Access log parsing (combined format)
- Error log parsing
- Auto-detection between access and error formats
- HTTP status to severity mapping
- Client IP extraction
- Edge cases and error handling
"""

from datetime import UTC, datetime

from app.models.raw_event import EventSeverity, EventType
from app.parsers.nginx_parser import (
    NGINX_COMBINED_PATTERN,
    NGINX_ERROR_PATTERN,
    NginxParser,
    _status_to_severity,
)


class TestStatusToSeverity:
    """Tests for HTTP status code to severity mapping."""

    def test_2xx_is_info(self):
        """2xx status codes should be INFO severity."""
        assert _status_to_severity(200) == EventSeverity.INFO
        assert _status_to_severity(201) == EventSeverity.INFO
        assert _status_to_severity(204) == EventSeverity.INFO
        assert _status_to_severity(299) == EventSeverity.INFO

    def test_3xx_is_info(self):
        """3xx status codes should be INFO severity."""
        assert _status_to_severity(301) == EventSeverity.INFO
        assert _status_to_severity(302) == EventSeverity.INFO
        assert _status_to_severity(304) == EventSeverity.INFO
        assert _status_to_severity(399) == EventSeverity.INFO

    def test_4xx_is_warning(self):
        """4xx status codes should be WARNING severity."""
        assert _status_to_severity(400) == EventSeverity.WARNING
        assert _status_to_severity(401) == EventSeverity.WARNING
        assert _status_to_severity(403) == EventSeverity.WARNING
        assert _status_to_severity(404) == EventSeverity.WARNING
        assert _status_to_severity(499) == EventSeverity.WARNING

    def test_5xx_is_error(self):
        """5xx status codes should be ERROR severity."""
        assert _status_to_severity(500) == EventSeverity.ERROR
        assert _status_to_severity(502) == EventSeverity.ERROR
        assert _status_to_severity(503) == EventSeverity.ERROR
        assert _status_to_severity(504) == EventSeverity.ERROR
        assert _status_to_severity(599) == EventSeverity.ERROR


class TestNginxCombinedPattern:
    """Tests for the combined access log regex pattern."""

    def test_matches_standard_combined_log(self):
        """Should match standard combined log format."""
        line = '192.168.1.100 - - [28/Jan/2026:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"'
        match = NGINX_COMBINED_PATTERN.match(line)

        assert match is not None
        assert match.group("remote_addr") == "192.168.1.100"
        assert match.group("remote_user") == "-"
        assert match.group("time_local") == "28/Jan/2026:12:34:56 +0000"
        assert match.group("request") == "GET /index.html HTTP/1.1"
        assert match.group("status") == "200"
        assert match.group("body_bytes_sent") == "1234"
        assert match.group("http_referer") == "https://example.com"
        assert match.group("http_user_agent") == "Mozilla/5.0"

    def test_matches_with_remote_user(self):
        """Should capture remote user when present."""
        line = (
            '10.0.0.1 - admin [01/Feb/2026:00:00:00 +0000] "POST /api HTTP/1.1" 201 100 "-" "curl"'
        )
        match = NGINX_COMBINED_PATTERN.match(line)

        assert match is not None
        assert match.group("remote_addr") == "10.0.0.1"
        assert match.group("remote_user") == "admin"

    def test_matches_ipv6_address(self):
        """Should match IPv6 client addresses."""
        line = '::1 - - [28/Jan/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "test"'
        match = NGINX_COMBINED_PATTERN.match(line)

        assert match is not None
        assert match.group("remote_addr") == "::1"


class TestNginxErrorPattern:
    """Tests for the error log regex pattern."""

    def test_matches_standard_error_log(self):
        """Should match standard error log format."""
        line = "2026/01/28 12:34:56 [error] 1234#5678: *999 test error message"
        match = NGINX_ERROR_PATTERN.match(line)

        assert match is not None
        assert match.group("timestamp") == "2026/01/28 12:34:56"
        assert match.group("level") == "error"
        assert match.group("pid") == "1234"
        assert match.group("tid") == "5678"
        assert match.group("cid") == "999"
        assert match.group("message") == "test error message"

    def test_matches_without_connection_id(self):
        """Should match error log without connection ID."""
        line = "2026/01/28 12:34:56 [warn] 1234#5678: some warning message"
        match = NGINX_ERROR_PATTERN.match(line)

        assert match is not None
        assert match.group("cid") is None
        assert match.group("message") == "some warning message"

    def test_matches_all_log_levels(self):
        """Should match all nginx error log levels."""
        levels = ["debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"]

        for level in levels:
            line = f"2026/01/28 12:00:00 [{level}] 1#1: test"
            match = NGINX_ERROR_PATTERN.match(line)
            assert match is not None, f"Failed to match level: {level}"
            assert match.group("level") == level


class TestNginxParserInit:
    """Tests for parser initialization."""

    def test_default_log_type_is_auto(self):
        """Should default to auto log type detection."""
        parser = NginxParser()
        assert parser.log_type == "auto"

    def test_explicit_access_log_type(self):
        """Should use explicit access log type."""
        parser = NginxParser({"log_type": "access"})
        assert parser.log_type == "access"

    def test_explicit_error_log_type(self):
        """Should use explicit error log type."""
        parser = NginxParser({"log_type": "error"})
        assert parser.log_type == "error"


class TestNginxParserAccessLogs:
    """Tests for parsing access logs."""

    def test_parse_basic_access_log(self):
        """Should parse a basic access log line."""
        parser = NginxParser()
        line = '192.168.1.1 - - [28/Jan/2026:12:34:56 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'

        results = parser.parse(line)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.HTTP
        assert result.client_ip == "192.168.1.1"
        assert result.response_status == "200"
        assert result.severity == EventSeverity.INFO
        assert result.action == "allowed"
        assert result.protocol == "HTTP"
        assert result.parsed_fields["method"] == "GET"
        assert result.parsed_fields["path"] == "/index.html"
        assert result.parsed_fields["status_code"] == 200
        assert result.parsed_fields["body_bytes_sent"] == 1234

    def test_parse_access_log_403_forbidden(self):
        """Should parse 403 forbidden response."""
        parser = NginxParser()
        line = '10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET /admin HTTP/1.1" 403 0 "-" "curl"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].action == "forbidden"
        assert results[0].severity == EventSeverity.WARNING
        assert results[0].response_status == "403"

    def test_parse_access_log_404_not_found(self):
        """Should parse 404 not found response."""
        parser = NginxParser()
        line = '10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET /missing HTTP/1.1" 404 0 "-" "curl"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].action == "not_found"
        assert results[0].severity == EventSeverity.WARNING

    def test_parse_access_log_500_server_error(self):
        """Should parse 500 server error response."""
        parser = NginxParser()
        line = '10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET /error HTTP/1.1" 500 0 "-" "curl"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].action == "server_error"
        assert results[0].severity == EventSeverity.ERROR

    def test_parse_access_log_4xx_client_error(self):
        """Should parse generic 4xx client error."""
        parser = NginxParser()
        line = '10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] "GET /bad HTTP/1.1" 400 0 "-" "curl"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].action == "client_error"

    def test_parse_access_log_timestamp(self):
        """Should correctly parse access log timestamp."""
        parser = NginxParser()
        line = '1.2.3.4 - - [15/Jun/2025:14:30:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].timestamp.year == 2025
        assert results[0].timestamp.month == 6
        assert results[0].timestamp.day == 15
        assert results[0].timestamp.hour == 14
        assert results[0].timestamp.minute == 30

    def test_parse_access_log_timestamp_with_timezone(self):
        """Should parse timestamp with timezone offset."""
        parser = NginxParser()
        line = '1.2.3.4 - - [15/Jun/2025:14:30:00 -0500] "GET / HTTP/1.1" 200 0 "-" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].timestamp.tzinfo is not None

    def test_parse_access_log_dash_client_ip(self):
        """Should handle dash client IP."""
        parser = NginxParser()
        line = '- - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].client_ip is None

    def test_parse_access_log_referer(self):
        """Should capture referer."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "https://google.com" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].parsed_fields["referer"] == "https://google.com"

    def test_parse_access_log_user_agent(self):
        """Should capture user agent."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "Mozilla/5.0 (Windows NT 10.0)"'

        results = parser.parse(line)

        assert len(results) == 1
        assert "Mozilla/5.0" in results[0].parsed_fields["user_agent"]

    def test_parse_explicit_access_type(self):
        """Should use explicit access type without auto-detection."""
        parser = NginxParser({"log_type": "access"})
        line = '192.168.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].event_type == EventType.HTTP


class TestNginxParserErrorLogs:
    """Tests for parsing error logs."""

    def test_parse_basic_error_log(self):
        """Should parse a basic error log line."""
        parser = NginxParser()
        line = "2026/01/28 12:34:56 [error] 1234#5678: *999 upstream timed out"

        results = parser.parse(line)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.SYSTEM
        assert result.severity == EventSeverity.ERROR
        assert result.parsed_fields["level"] == "error"
        assert result.parsed_fields["pid"] == "1234"
        assert result.parsed_fields["tid"] == "5678"
        assert result.parsed_fields["connection_id"] == "999"
        assert "upstream timed out" in result.parsed_fields["message"]

    def test_parse_error_log_severity_mapping(self):
        """Should map error log levels to severity."""
        parser = NginxParser({"log_type": "error"})

        test_cases = [
            ("debug", EventSeverity.DEBUG),
            ("info", EventSeverity.INFO),
            ("notice", EventSeverity.INFO),
            ("warn", EventSeverity.WARNING),
            ("error", EventSeverity.ERROR),
            ("crit", EventSeverity.CRITICAL),
            ("alert", EventSeverity.CRITICAL),
            ("emerg", EventSeverity.CRITICAL),
        ]

        for level, expected_severity in test_cases:
            line = f"2026/01/28 12:00:00 [{level}] 1#1: test message"
            results = parser.parse(line)
            assert len(results) == 1, f"Failed for level: {level}"
            assert results[0].severity == expected_severity, f"Wrong severity for {level}"

    def test_parse_error_log_timestamp(self):
        """Should correctly parse error log timestamp."""
        parser = NginxParser({"log_type": "error"})
        line = "2025/06/15 14:30:00 [error] 1#1: test"

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].timestamp.year == 2025
        assert results[0].timestamp.month == 6
        assert results[0].timestamp.day == 15
        assert results[0].timestamp.hour == 14
        assert results[0].timestamp.minute == 30

    def test_parse_error_log_extracts_client_ip(self):
        """Should extract client IP from error message."""
        parser = NginxParser({"log_type": "error"})
        line = "2026/01/28 12:00:00 [error] 1#1: *1 client: 192.168.1.100, server: example.com"

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].client_ip == "192.168.1.100"

    def test_parse_error_log_without_client_ip(self):
        """Should handle error log without client IP."""
        parser = NginxParser({"log_type": "error"})
        line = "2026/01/28 12:00:00 [error] 1#1: some error without client"

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].client_ip is None

    def test_parse_explicit_error_type(self):
        """Should use explicit error type without auto-detection."""
        parser = NginxParser({"log_type": "error"})
        line = "2026/01/28 12:00:00 [error] 1#1: test"

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].event_type == EventType.SYSTEM

    def test_parse_error_log_fallback(self):
        """Should create fallback result for unmatched error lines."""
        parser = NginxParser({"log_type": "error"})
        line = "This is not a standard error log format"

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.ERROR
        assert results[0].parsed_fields["message"] == line


class TestNginxParserAutoDetection:
    """Tests for auto-detection between access and error logs."""

    def test_auto_detect_access_log(self):
        """Should auto-detect access log format."""
        parser = NginxParser()  # Default is auto
        line = '192.168.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].event_type == EventType.HTTP

    def test_auto_detect_error_log(self):
        """Should auto-detect error log format."""
        parser = NginxParser()
        line = "2026/01/28 12:00:00 [error] 1#1: some error"

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].event_type == EventType.SYSTEM

    def test_auto_detect_mixed_logs(self):
        """Should handle mixed access and error logs."""
        parser = NginxParser()
        lines = [
            '192.168.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"',
            "2026/01/28 12:00:00 [error] 1#1: some error",
        ]

        results = parser.parse(lines)

        assert len(results) == 2
        assert results[0].event_type == EventType.HTTP
        assert results[1].event_type == EventType.SYSTEM


class TestNginxParserEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_input(self):
        """Should handle empty input."""
        parser = NginxParser()

        assert parser.parse("") == []
        assert parser.parse([]) == []
        assert parser.parse("   ") == []

    def test_multiple_lines(self):
        """Should parse multiple lines."""
        parser = NginxParser()
        lines = """192.168.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET /a HTTP/1.1" 200 0 "-" "-"
192.168.1.2 - - [01/Jan/2026:00:00:01 +0000] "GET /b HTTP/1.1" 200 0 "-" "-"
192.168.1.3 - - [01/Jan/2026:00:00:02 +0000] "GET /c HTTP/1.1" 200 0 "-" "-"
"""
        results = parser.parse(lines)

        assert len(results) == 3
        assert results[0].client_ip == "192.168.1.1"
        assert results[1].client_ip == "192.168.1.2"
        assert results[2].client_ip == "192.168.1.3"

    def test_list_input(self):
        """Should accept list of lines."""
        parser = NginxParser()
        lines = [
            '192.168.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"',
            '192.168.1.2 - - [01/Jan/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 0 "-" "-"',
        ]

        results = parser.parse(lines)

        assert len(results) == 2

    def test_non_string_input(self):
        """Should handle non-string input."""
        parser = NginxParser()
        results = parser.parse(12345)

        # Should create fallback for error type
        assert len(results) == 1

    def test_preserves_raw_message(self):
        """Should preserve raw message."""
        parser = NginxParser()
        line = '192.168.1.1 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'

        results = parser.parse(line)

        assert results[0].raw_message == line

    def test_post_request(self):
        """Should parse POST request."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "POST /api/data HTTP/1.1" 201 100 "-" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].parsed_fields["method"] == "POST"
        assert results[0].parsed_fields["path"] == "/api/data"

    def test_empty_request_line(self):
        """Should handle empty request line."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "" 400 0 "-" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].parsed_fields["method"] == ""
        assert results[0].parsed_fields["path"] == ""

    def test_malformed_timestamp_uses_current(self):
        """Should use current time for malformed timestamps."""
        parser = NginxParser()

        # Test error log with malformed timestamp
        before = datetime.now(UTC)
        # Create a line that matches the error pattern but has invalid timestamp
        line = "2026/99/99 99:99:99 [error] 1#1: test"
        results = parser.parse(line)
        after = datetime.now(UTC)

        assert len(results) == 1
        # Timestamp should be close to current time due to parse failure
        assert before <= results[0].timestamp <= after

    def test_special_characters_in_path(self):
        """Should handle special characters in request path."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /path?query=foo&bar=baz HTTP/1.1" 200 0 "-" "-"'

        results = parser.parse(line)

        assert len(results) == 1
        assert results[0].parsed_fields["path"] == "/path?query=foo&bar=baz"

    def test_unicode_in_user_agent(self):
        """Should handle unicode in user agent."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "Тест Unicode"'

        results = parser.parse(line)

        assert len(results) == 1
        assert "Unicode" in results[0].parsed_fields["user_agent"]


class TestNginxParserRequestParsing:
    """Tests for HTTP request line parsing."""

    def test_parse_full_request(self):
        """Should parse complete request line."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /api/v1/users HTTP/1.1" 200 0 "-" "-"'

        results = parser.parse(line)

        assert results[0].parsed_fields["method"] == "GET"
        assert results[0].parsed_fields["path"] == "/api/v1/users"
        assert results[0].parsed_fields["http_version"] == "HTTP/1.1"

    def test_parse_http2_request(self):
        """Should parse HTTP/2 request."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /test HTTP/2.0" 200 0 "-" "-"'

        results = parser.parse(line)

        assert results[0].parsed_fields["http_version"] == "HTTP/2.0"

    def test_parse_request_without_protocol(self):
        """Should handle request without protocol."""
        parser = NginxParser()
        line = '1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET /test" 200 0 "-" "-"'

        results = parser.parse(line)

        assert results[0].parsed_fields["method"] == "GET"
        assert results[0].parsed_fields["path"] == "/test"
        assert results[0].parsed_fields["http_version"] == ""
