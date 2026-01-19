"""Tests for the syslog parser."""

import pytest
from datetime import datetime, timezone

from app.models.raw_event import EventSeverity, EventType
from app.parsers.syslog_parser import SyslogParser


class TestSyslogParser:
    """Tests for SyslogParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = SyslogParser({"year": 2024})

    def test_parse_rfc3164_basic(self):
        """Test parsing RFC 3164 format syslog message."""
        log_line = "<34>Jan  5 12:34:56 myhost sshd[1234]: Failed password for invalid user admin"

        results = self.parser.parse(log_line)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.SYSTEM
        assert result.severity == EventSeverity.CRITICAL  # PRI 34 = facility 4, severity 2
        assert result.raw_message == log_line
        assert result.parsed_fields["hostname"] == "myhost"
        assert result.parsed_fields["tag"] == "sshd"
        assert result.parsed_fields["pid"] == "1234"
        assert "Failed password" in result.parsed_fields["message"]

    def test_parse_rfc3164_double_digit_day(self):
        """Test parsing RFC 3164 with double-digit day."""
        log_line = "<134>Oct 15 08:15:30 server01 cron[5678]: Job started"

        results = self.parser.parse(log_line)

        assert len(results) == 1
        result = results[0]
        assert result.parsed_fields["hostname"] == "server01"
        assert result.parsed_fields["tag"] == "cron"
        assert result.timestamp.month == 10
        assert result.timestamp.day == 15

    def test_parse_rfc5424_basic(self):
        """Test parsing RFC 5424 format syslog message."""
        log_line = '<165>1 2024-01-15T12:00:00.000Z myhost myapp 1234 ID47 - This is the message'

        results = self.parser.parse(log_line)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.SYSTEM
        assert result.parsed_fields["hostname"] == "myhost"
        assert result.parsed_fields["appname"] == "myapp"
        assert result.parsed_fields["procid"] == "1234"
        assert result.parsed_fields["msgid"] == "ID47"

    def test_parse_rfc5424_with_structured_data(self):
        """Test parsing RFC 5424 with structured data."""
        log_line = '<165>1 2024-01-15T12:00:00Z host app 123 msgid [exampleSDID@32473 iut="3" eventSource="Application"] Message'

        results = self.parser.parse(log_line)

        assert len(results) == 1
        result = results[0]
        assert "sd_exampleSDID@32473" in result.parsed_fields
        assert result.parsed_fields["sd_exampleSDID@32473"]["iut"] == "3"

    def test_parse_simple_format(self):
        """Test parsing simple syslog format without PRI."""
        log_line = "Jan  5 12:34:56 myhost sshd[1234]: Connection closed"

        results = self.parser.parse(log_line)

        assert len(results) == 1
        result = results[0]
        assert result.parsed_fields["hostname"] == "myhost"

    def test_parse_multiple_lines(self):
        """Test parsing multiple syslog lines."""
        logs = """<34>Jan  5 12:34:56 host1 app1: Message 1
<34>Jan  5 12:34:57 host2 app2: Message 2
<34>Jan  5 12:34:58 host3 app3: Message 3"""

        results = self.parser.parse(logs)

        assert len(results) == 3
        assert results[0].parsed_fields["hostname"] == "host1"
        assert results[1].parsed_fields["hostname"] == "host2"
        assert results[2].parsed_fields["hostname"] == "host3"

    def test_parse_list_input(self):
        """Test parsing a list of log lines."""
        logs = [
            "<34>Jan  5 12:34:56 host1 app1: Message 1",
            "<34>Jan  5 12:34:57 host2 app2: Message 2",
        ]

        results = self.parser.parse(logs)

        assert len(results) == 2

    def test_parse_empty_input(self):
        """Test parsing empty input."""
        results = self.parser.parse("")
        assert len(results) == 0

        results = self.parser.parse([])
        assert len(results) == 0

    def test_parse_invalid_line_fallback(self):
        """Test that invalid lines fall back to basic parsing."""
        log_line = "This is just a plain text message"

        results = self.parser.parse(log_line)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.SYSTEM
        assert result.severity == EventSeverity.INFO
        assert result.parsed_fields["message"] == log_line

    def test_severity_mapping(self):
        """Test severity mapping from PRI value."""
        # PRI = facility * 8 + severity
        # Emergency (0), Alert (1), Critical (2) -> CRITICAL
        # Error (3) -> ERROR
        # Warning (4) -> WARNING
        # Notice (5), Info (6) -> INFO
        # Debug (7) -> DEBUG

        test_cases = [
            ("<8>Jan  5 12:34:56 host app: Emergency", EventSeverity.CRITICAL),  # 1*8+0
            ("<11>Jan  5 12:34:56 host app: Error", EventSeverity.ERROR),  # 1*8+3
            ("<12>Jan  5 12:34:56 host app: Warning", EventSeverity.WARNING),  # 1*8+4
            ("<14>Jan  5 12:34:56 host app: Info", EventSeverity.INFO),  # 1*8+6
            ("<15>Jan  5 12:34:56 host app: Debug", EventSeverity.DEBUG),  # 1*8+7
        ]

        for log_line, expected_severity in test_cases:
            results = self.parser.parse(log_line)
            assert len(results) == 1
            assert results[0].severity == expected_severity, f"Failed for {log_line}"

    def test_facility_parsing(self):
        """Test facility extraction from PRI value."""
        # PRI 34 = facility 4 (auth), severity 2
        log_line = "<34>Jan  5 12:34:56 host app: Auth message"

        results = self.parser.parse(log_line)

        assert len(results) == 1
        assert results[0].parsed_fields["facility"] == "auth"
        assert results[0].parsed_fields["facility_num"] == 4

    def test_custom_year_config(self):
        """Test custom year configuration."""
        parser = SyslogParser({"year": 2023})
        log_line = "<34>Jan  5 12:34:56 host app: Message"

        results = parser.parse(log_line)

        assert len(results) == 1
        assert results[0].timestamp.year == 2023
