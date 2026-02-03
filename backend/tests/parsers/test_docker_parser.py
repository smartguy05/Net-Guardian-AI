"""Tests for the Docker container log parser."""

import json
from datetime import UTC, datetime

import pytest

from app.models.raw_event import EventSeverity, EventType
from app.parsers.docker_parser import DockerParser


class TestDockerParser:
    """Tests for DockerParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = DockerParser({})

    # --- Basic Parsing Tests ---

    def test_parse_json_log_format(self):
        """Test parsing Docker JSON log format."""
        entry = {
            "log": "Application started successfully\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45.123456789Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.CONTAINER
        assert result.severity == EventSeverity.INFO
        assert "Application started successfully" in result.raw_message
        assert result.parsed_fields["stream"] == "stdout"

    def test_parse_json_lines_string(self):
        """Test parsing multiple JSON lines as string."""
        logs = """{"log": "Line 1\\n", "stream": "stdout", "time": "2024-01-15T10:30:45Z"}
{"log": "Line 2\\n", "stream": "stdout", "time": "2024-01-15T10:30:46Z"}
{"log": "Line 3\\n", "stream": "stderr", "time": "2024-01-15T10:30:47Z"}"""

        results = self.parser.parse(logs)

        assert len(results) == 3
        assert "Line 1" in results[0].raw_message
        assert "Line 2" in results[1].raw_message
        assert results[2].parsed_fields["stream"] == "stderr"

    def test_parse_list_of_entries(self):
        """Test parsing a list of log entries."""
        entries = [
            {"log": "Entry 1\n", "stream": "stdout", "time": "2024-01-15T10:30:45Z"},
            {"log": "Entry 2\n", "stream": "stdout", "time": "2024-01-15T10:30:46Z"},
        ]

        results = self.parser.parse(entries)

        assert len(results) == 2

    def test_parse_empty_input(self):
        """Test parsing empty input."""
        assert self.parser.parse("") == []
        assert self.parser.parse([]) == []
        assert self.parser.parse({}) == []

    def test_parse_plain_text_fallback(self):
        """Test parsing plain text that's not JSON."""
        logs = "This is just a plain text log message"

        results = self.parser.parse(logs)

        assert len(results) == 1
        assert "plain text log message" in results[0].raw_message

    # --- Timestamp Parsing Tests ---

    def test_parse_nanosecond_timestamp(self):
        """Test parsing Docker nanosecond timestamp."""
        entry = {
            "log": "Test\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45.123456789Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024
        assert results[0].timestamp.month == 1
        assert results[0].timestamp.day == 15
        assert results[0].timestamp.hour == 10
        assert results[0].timestamp.minute == 30
        assert results[0].timestamp.second == 45

    def test_parse_simple_timestamp(self):
        """Test parsing simple ISO timestamp."""
        entry = {
            "log": "Test\n",
            "stream": "stdout",
            "time": "2024-06-20T15:45:30Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].timestamp.month == 6
        assert results[0].timestamp.day == 20

    def test_parse_invalid_timestamp_fallback(self):
        """Test fallback to current time for invalid timestamp."""
        entry = {
            "log": "Test\n",
            "stream": "stdout",
            "time": "not-a-valid-timestamp",
        }

        before = datetime.now(UTC)
        results = self.parser.parse(entry)
        after = datetime.now(UTC)

        assert len(results) == 1
        assert before <= results[0].timestamp <= after

    # --- Severity Detection Tests ---

    def test_detect_error_in_content(self):
        """Test error detection from log content."""
        entry = {
            "log": "ERROR: Connection failed to database\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.ERROR

    def test_detect_warning_in_content(self):
        """Test warning detection from log content."""
        entry = {
            "log": "WARNING: Deprecated API usage detected\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_stderr_implies_warning(self):
        """Test that stderr stream implies warning severity."""
        entry = {
            "log": "Some message\n",
            "stream": "stderr",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_disable_error_detection(self):
        """Test disabling error detection."""
        parser = DockerParser({"detect_errors": False})
        entry = {
            "log": "ERROR: This should not be detected as error\n",
            "stream": "stderr",
            "time": "2024-01-15T10:30:45Z",
        }

        results = parser.parse(entry)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.INFO

    def test_custom_error_keywords(self):
        """Test custom error keywords."""
        parser = DockerParser({"error_keywords": ["myerror"]})
        entry = {
            "log": "MYERROR: Custom error occurred\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
        }

        results = parser.parse(entry)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.ERROR

    # --- Container Event Detection Tests ---

    def test_detect_oom_killed(self):
        """Test OOM killed event detection."""
        entry = {
            "log": "Container OOMKilled due to memory limits\n",
            "stream": "stderr",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.CRITICAL
        assert results[0].parsed_fields.get("container_event") == "oom_killed"
        assert results[0].parsed_fields.get("oom_killed") is True

    def test_detect_container_restart(self):
        """Test container restart event detection."""
        entry = {
            "log": "Container restarted due to policy\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING
        assert results[0].parsed_fields.get("container_event") == "restart"

    def test_detect_exit_with_code(self):
        """Test exit code detection."""
        entry = {
            "log": "Process exited with code 137\n",
            "stream": "stderr",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.ERROR
        assert results[0].parsed_fields.get("container_event") == "exit"
        assert results[0].parsed_fields.get("exit_code") == 137

    def test_detect_successful_exit(self):
        """Test successful exit (code 0) detection."""
        entry = {
            "log": "Process exited with code 0\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        # Code 0 shouldn't elevate to ERROR
        assert results[0].parsed_fields.get("exit_code") == 0

    # --- Container Metadata Tests ---

    def test_extract_container_metadata(self):
        """Test container metadata extraction."""
        entry = {
            "log": "Application running\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
            "container_id": "abc123def456789",
            "container_name": "my-app",
            "image": "nginx:latest",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].parsed_fields["container_id"] == "abc123def456"
        assert results[0].parsed_fields["container_name"] == "my-app"
        assert results[0].parsed_fields["image"] == "nginx:latest"

    def test_container_name_in_raw_message(self):
        """Test container name appears in raw message."""
        entry = {
            "log": "Test message\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
            "container_name": "web-server",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert "[web-server]" in results[0].raw_message

    def test_config_container_name_override(self):
        """Test container name override from config."""
        parser = DockerParser({"container_name": "overridden-name"})
        entry = {
            "log": "Test\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
            "container_name": "original-name",
        }

        results = parser.parse(entry)

        assert len(results) == 1
        assert results[0].parsed_fields["container_name"] == "overridden-name"

    def test_restart_count_extraction(self):
        """Test restart count extraction."""
        entry = {
            "log": "Container running\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
            "restart_count": 5,
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].parsed_fields.get("restart_count") == 5

    # --- Error Handling Tests ---

    def test_invalid_entry_skipped(self):
        """Test that invalid entries are skipped."""
        entries = [
            {"log": "Valid entry\n", "stream": "stdout", "time": "2024-01-15T10:30:45Z"},
            "not a dict",
            None,
            {"log": "Another valid\n", "stream": "stdout", "time": "2024-01-15T10:30:46Z"},
        ]

        results = self.parser.parse(entries)

        assert len(results) == 2

    def test_entry_without_log_skipped(self):
        """Test that entries without log content are skipped."""
        entry = {
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 0

    def test_entry_with_empty_log_skipped(self):
        """Test that entries with empty log are skipped."""
        entry = {
            "log": "\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 0

    # --- Protocol and Response Tests ---

    def test_protocol_is_docker(self):
        """Test that protocol is set to docker."""
        entry = {
            "log": "Test\n",
            "stream": "stdout",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].protocol == "docker"

    def test_response_status_is_stream(self):
        """Test that response_status contains the stream name."""
        entry = {
            "log": "Test\n",
            "stream": "stderr",
            "time": "2024-01-15T10:30:45Z",
        }

        results = self.parser.parse(entry)

        assert len(results) == 1
        assert results[0].response_status == "stderr"
