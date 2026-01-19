"""Tests for the endpoint agent parser."""

import pytest
from datetime import datetime, timezone

from app.models.raw_event import EventSeverity, EventType
from app.parsers.endpoint_parser import EndpointParser


class TestEndpointParser:
    """Tests for EndpointParser."""

    @pytest.fixture
    def parser(self):
        """Create parser instance."""
        return EndpointParser()

    def test_parse_process_event(self, parser):
        """Test parsing a process event."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "process",
            "data": {
                "pid": 1234,
                "name": "chrome.exe",
                "path": "/usr/bin/chrome",
                "cmdline": "chrome --no-sandbox",
                "user": "testuser",
                "parent_pid": 1,
                "parent_name": "init",
            },
        }

        results = parser.parse(data)
        assert len(results) == 1

        result = results[0]
        assert result.event_type == EventType.ENDPOINT
        assert result.parsed_fields["hostname"] == "workstation-01"
        assert result.parsed_fields["agent_id"] == "abc123"
        assert result.parsed_fields["pid"] == 1234
        assert result.parsed_fields["name"] == "chrome.exe"
        assert result.action == "process_start"
        assert "Process started: chrome.exe" in result.raw_message

    def test_parse_network_event(self, parser):
        """Test parsing a network connection event."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "network",
            "data": {
                "local_ip": "192.168.1.100",
                "local_port": 54321,
                "remote_ip": "8.8.8.8",
                "remote_port": 443,
                "protocol": "tcp",
                "state": "established",
                "process_name": "chrome",
                "process_pid": 1234,
            },
        }

        results = parser.parse(data)
        assert len(results) == 1

        result = results[0]
        assert result.event_type == EventType.ENDPOINT
        assert result.client_ip == "192.168.1.100"
        assert result.target_ip == "8.8.8.8"
        assert result.port == 443
        assert result.protocol == "tcp"
        assert result.action == "established"
        assert "192.168.1.100:54321" in result.raw_message
        assert "8.8.8.8:443" in result.raw_message

    def test_parse_file_event(self, parser):
        """Test parsing a file access event."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "file",
            "data": {
                "path": "/etc/passwd",
                "action": "read",
                "process_name": "cat",
                "process_pid": 5678,
            },
        }

        results = parser.parse(data)
        assert len(results) == 1

        result = results[0]
        assert result.event_type == EventType.ENDPOINT
        assert result.action == "read"
        assert result.severity == EventSeverity.INFO  # Sensitive file
        assert "/etc/passwd" in result.raw_message

    def test_parse_auth_event(self, parser):
        """Test parsing an authentication event."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "auth",
            "data": {
                "action": "failed",
                "user": "admin",
                "source": "ssh",
                "source_ip": "192.168.1.50",
            },
        }

        results = parser.parse(data)
        assert len(results) == 1

        result = results[0]
        assert result.event_type == EventType.AUTH
        assert result.action == "failed"
        assert result.severity == EventSeverity.WARNING
        assert result.client_ip == "192.168.1.50"
        assert "Auth failed" in result.raw_message

    def test_parse_system_event(self, parser):
        """Test parsing a system event."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "system",
            "data": {
                "action": "service_start",
                "service_name": "sshd",
            },
        }

        results = parser.parse(data)
        assert len(results) == 1

        result = results[0]
        assert result.event_type == EventType.SYSTEM
        assert result.action == "service_start"
        assert "sshd" in result.raw_message

    def test_parse_batch(self, parser):
        """Test parsing a batch of events."""
        data = [
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "hostname": "workstation-01",
                "agent_id": "abc123",
                "event_type": "process",
                "data": {"pid": 1, "name": "proc1", "user": "user1"},
            },
            {
                "timestamp": "2024-01-15T10:30:01Z",
                "hostname": "workstation-01",
                "agent_id": "abc123",
                "event_type": "process",
                "data": {"pid": 2, "name": "proc2", "user": "user2"},
            },
        ]

        results = parser.parse(data)
        assert len(results) == 2

    def test_suspicious_process_detection(self, parser):
        """Test detection of suspicious processes."""
        # Suspicious process name
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "process",
            "data": {
                "pid": 1234,
                "name": "mimikatz.exe",
                "path": "C:\\Temp\\mimikatz.exe",
                "cmdline": "mimikatz.exe",
                "user": "admin",
            },
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_suspicious_cmdline_detection(self, parser):
        """Test detection of suspicious command lines."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "process",
            "data": {
                "pid": 1234,
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\powershell.exe",
                "cmdline": "powershell.exe -encodedcommand ZWNobyAiaGVsbG8i",
                "user": "admin",
            },
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_suspicious_port_network_event(self, parser):
        """Test detection of suspicious network ports."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "network",
            "data": {
                "local_ip": "192.168.1.100",
                "local_port": 54321,
                "remote_ip": "10.0.0.1",
                "remote_port": 4444,  # Common reverse shell port
                "protocol": "tcp",
                "state": "established",
                "process_name": "unknown",
                "process_pid": 1234,
            },
        }

        results = parser.parse(data)
        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_missing_timestamp_uses_current(self, parser):
        """Test that missing timestamp uses current time."""
        data = {
            "hostname": "workstation-01",
            "agent_id": "abc123",
            "event_type": "process",
            "data": {"pid": 1, "name": "test"},
        }

        results = parser.parse(data)
        assert len(results) == 1
        # Timestamp should be recent
        assert (datetime.now(timezone.utc) - results[0].timestamp).total_seconds() < 5

    def test_invalid_data_type(self, parser):
        """Test handling of invalid data types."""
        results = parser.parse("invalid string data")
        assert len(results) == 0

        results = parser.parse(12345)
        assert len(results) == 0
