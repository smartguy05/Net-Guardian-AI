"""Tests for the JSON parser."""

import json
from datetime import UTC, datetime

from app.models.raw_event import EventSeverity, EventType
from app.parsers.json_parser import JsonParser


class TestJsonParser:
    """Tests for JsonParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = JsonParser()

    def test_parse_simple_object(self):
        """Test parsing a simple JSON object."""
        data = {
            "timestamp": "2024-01-15T12:00:00Z",
            "message": "Test event",
            "severity": "info",
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        result = results[0]
        assert result.severity == EventSeverity.INFO
        assert result.raw_message == "Test event"

    def test_parse_json_string(self):
        """Test parsing a JSON string."""
        data = json.dumps(
            {
                "timestamp": "2024-01-15T12:00:00Z",
                "message": "Test event",
            }
        )

        results = self.parser.parse(data)

        assert len(results) == 1

    def test_parse_list_of_events(self):
        """Test parsing a list of events."""
        data = [
            {"timestamp": "2024-01-15T12:00:00Z", "message": "Event 1"},
            {"timestamp": "2024-01-15T12:00:01Z", "message": "Event 2"},
            {"timestamp": "2024-01-15T12:00:02Z", "message": "Event 3"},
        ]

        results = self.parser.parse(data)

        assert len(results) == 3
        assert results[0].raw_message == "Event 1"
        assert results[1].raw_message == "Event 2"
        assert results[2].raw_message == "Event 3"

    def test_parse_with_events_path(self):
        """Test parsing with custom events path."""
        parser = JsonParser({"events_path": "$.data.events"})
        data = {
            "status": "ok",
            "data": {
                "events": [
                    {"timestamp": "2024-01-15T12:00:00Z", "message": "Event 1"},
                    {"timestamp": "2024-01-15T12:00:01Z", "message": "Event 2"},
                ]
            },
        }

        results = parser.parse(data)

        assert len(results) == 2

    def test_parse_with_field_mappings(self):
        """Test parsing with custom field mappings."""
        parser = JsonParser(
            {
                "field_mappings": {
                    "client_ip": "$.source.ip",
                    "domain": "$.request.host",
                }
            }
        )
        data = {
            "timestamp": "2024-01-15T12:00:00Z",
            "source": {"ip": "192.168.1.100"},
            "request": {"host": "example.com"},
            "message": "Test",
        }

        results = parser.parse(data)

        assert len(results) == 1
        assert results[0].client_ip == "192.168.1.100"
        assert results[0].domain == "example.com"

    def test_parse_severity_mapping(self):
        """Test severity mapping from string values."""
        test_cases = [
            ("debug", EventSeverity.DEBUG),
            ("info", EventSeverity.INFO),
            ("information", EventSeverity.INFO),
            ("warn", EventSeverity.WARNING),
            ("warning", EventSeverity.WARNING),
            ("error", EventSeverity.ERROR),
            ("err", EventSeverity.ERROR),
            ("critical", EventSeverity.CRITICAL),
            ("fatal", EventSeverity.CRITICAL),
        ]

        for severity_str, expected_severity in test_cases:
            data = {
                "timestamp": "2024-01-15T12:00:00Z",
                "severity": severity_str,
                "message": "Test",
            }
            results = self.parser.parse(data)
            assert results[0].severity == expected_severity, f"Failed for {severity_str}"

    def test_parse_custom_severity_map(self):
        """Test custom severity mapping."""
        parser = JsonParser(
            {
                "severity_map": {
                    "low": EventSeverity.DEBUG,
                    "medium": EventSeverity.WARNING,
                    "high": EventSeverity.CRITICAL,
                }
            }
        )

        data = {"timestamp": "2024-01-15T12:00:00Z", "severity": "high", "message": "Test"}
        results = parser.parse(data)

        assert results[0].severity == EventSeverity.CRITICAL

    def test_parse_unix_timestamp(self):
        """Test parsing Unix timestamp."""
        data = {
            "timestamp": 1705320000,  # 2024-01-15T12:00:00Z
            "message": "Test",
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024
        assert results[0].timestamp.month == 1
        assert results[0].timestamp.day == 15

    def test_parse_custom_timestamp_format(self):
        """Test parsing custom timestamp format."""
        parser = JsonParser({"timestamp_format": "%d/%m/%Y %H:%M:%S"})
        data = {
            "timestamp": "15/01/2024 12:00:00",
            "message": "Test",
        }

        results = parser.parse(data)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024
        assert results[0].timestamp.month == 1
        assert results[0].timestamp.day == 15

    def test_parse_with_all_fields(self):
        """Test parsing with all available fields."""
        data = {
            "timestamp": "2024-01-15T12:00:00Z",
            "message": "Full event",
            "client_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "domain": "example.com",
            "port": 443,
            "protocol": "HTTPS",
            "action": "blocked",
            "response_status": "403",
            "severity": "warning",
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        result = results[0]
        assert result.client_ip == "192.168.1.100"
        assert result.target_ip == "10.0.0.1"
        assert result.domain == "example.com"
        assert result.port == 443
        assert result.protocol == "HTTPS"
        assert result.action == "blocked"
        assert result.response_status == "403"

    def test_parse_default_event_type(self):
        """Test default event type configuration."""
        parser = JsonParser({"event_type": "dns"})
        data = {"timestamp": "2024-01-15T12:00:00Z", "message": "Test"}

        results = parser.parse(data)

        assert results[0].event_type == EventType.DNS

    def test_parse_invalid_json_string(self):
        """Test parsing invalid JSON string returns empty list."""
        results = self.parser.parse("not valid json")
        assert len(results) == 0

    def test_parse_empty_list(self):
        """Test parsing empty list."""
        results = self.parser.parse([])
        assert len(results) == 0

    def test_parse_missing_timestamp_uses_current(self):
        """Test that missing timestamp uses current time."""
        data = {"message": "No timestamp"}

        results = self.parser.parse(data)

        assert len(results) == 1
        # Should be recent (within last minute)
        now = datetime.now(UTC)
        assert (now - results[0].timestamp).total_seconds() < 60

    def test_parse_non_dict_items_skipped(self):
        """Test that non-dict items in list are skipped."""
        data = [
            {"timestamp": "2024-01-15T12:00:00Z", "message": "Valid"},
            "invalid string item",
            123,
            None,
            {"timestamp": "2024-01-15T12:00:01Z", "message": "Also valid"},
        ]

        results = self.parser.parse(data)

        assert len(results) == 2

    def test_parse_no_message_uses_json(self):
        """Test that missing message field uses JSON dump."""
        data = {"timestamp": "2024-01-15T12:00:00Z", "custom_field": "value"}

        results = self.parser.parse(data)

        assert len(results) == 1
        assert "custom_field" in results[0].raw_message
