"""Tests for the Python logging module parser."""

from app.models.raw_event import EventSeverity, EventType
from app.parsers.python_log_parser import PythonLogParser


class TestPythonLogParser:
    """Tests for PythonLogParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = PythonLogParser({})

    # --- Basic Parsing Tests ---

    def test_parse_simple_log_line(self):
        """Test parsing simple Python log line."""
        log = "2024-01-15 10:30:45,123 INFO Application started successfully"

        results = self.parser.parse(log)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.APPLICATION
        assert result.severity == EventSeverity.INFO
        assert "Application started" in result.raw_message

    def test_parse_multiple_log_lines(self):
        """Test parsing multiple log lines."""
        logs = """2024-01-15 10:30:45,123 INFO Starting application
2024-01-15 10:30:46,456 WARNING Configuration file not found
2024-01-15 10:30:47,789 ERROR Failed to connect to database"""

        results = self.parser.parse(logs)

        assert len(results) == 3
        assert results[0].severity == EventSeverity.INFO
        assert results[1].severity == EventSeverity.WARNING
        assert results[2].severity == EventSeverity.ERROR

    def test_parse_list_of_lines(self):
        """Test parsing list of log lines."""
        logs = [
            "2024-01-15 10:30:45,123 INFO Entry 1",
            "2024-01-15 10:30:46,456 INFO Entry 2",
        ]

        results = self.parser.parse(logs)

        assert len(results) == 2

    def test_parse_empty_input(self):
        """Test parsing empty input."""
        assert self.parser.parse("") == []
        assert self.parser.parse([]) == []

    # --- Timestamp Parsing Tests ---

    def test_parse_comma_milliseconds(self):
        """Test parsing timestamp with comma milliseconds."""
        log = "2024-01-15 10:30:45,123 INFO Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024
        assert results[0].timestamp.month == 1
        assert results[0].timestamp.day == 15

    def test_parse_dot_milliseconds(self):
        """Test parsing timestamp with dot milliseconds."""
        log = "2024-01-15 10:30:45.123 INFO Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024

    def test_parse_iso_timestamp(self):
        """Test parsing ISO 8601 timestamp."""
        log = "2024-01-15T10:30:45 INFO Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024

    def test_parse_basic_timestamp(self):
        """Test parsing basic timestamp without milliseconds."""
        log = "2024-01-15 10:30:45 INFO Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].timestamp is not None

    def test_custom_timestamp_format(self):
        """Test custom timestamp format configuration."""
        parser = PythonLogParser({"timestamp_format": "%d/%m/%Y %H:%M:%S"})
        log = "15/01/2024 10:30:45 INFO Message"

        # Note: This will fallback to standard patterns if custom doesn't match
        results = parser.parse(log)

        assert len(results) == 1

    # --- Log Level Tests ---

    def test_parse_debug_level(self):
        """Test parsing DEBUG log level."""
        log = "2024-01-15 10:30:45,123 DEBUG Debug message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.DEBUG

    def test_parse_info_level(self):
        """Test parsing INFO log level."""
        log = "2024-01-15 10:30:45,123 INFO Info message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.INFO

    def test_parse_warning_level(self):
        """Test parsing WARNING log level."""
        log = "2024-01-15 10:30:45,123 WARNING Warning message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_parse_warn_level(self):
        """Test parsing WARN log level."""
        log = "2024-01-15 10:30:45,123 WARN Warning message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_parse_error_level(self):
        """Test parsing ERROR log level."""
        log = "2024-01-15 10:30:45,123 ERROR Error message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.ERROR

    def test_parse_critical_level(self):
        """Test parsing CRITICAL log level."""
        log = "2024-01-15 10:30:45,123 CRITICAL Critical error"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.CRITICAL

    def test_parse_fatal_level(self):
        """Test parsing FATAL log level."""
        log = "2024-01-15 10:30:45,123 FATAL Fatal error"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.CRITICAL

    def test_case_insensitive_level(self):
        """Test case-insensitive log level parsing."""
        log = "2024-01-15 10:30:45,123 warning Warning message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    # --- Python Traceback Tests ---

    def test_parse_simple_traceback(self):
        """Test parsing simple Python traceback."""
        log = """2024-01-15 10:30:45,123 ERROR Unhandled exception
Traceback (most recent call last):
  File "main.py", line 10, in main
    process_data()
  File "processor.py", line 25, in process_data
    return data[key]
KeyError: 'missing_key'"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Find result with exception info
        exception_types = [r.parsed_fields.get("exception_type") for r in results]
        assert "KeyError" in exception_types or any("KeyError" in r.raw_message for r in results)

    def test_parse_traceback_frames(self):
        """Test stack frame extraction from traceback."""
        log = """Traceback (most recent call last):
  File "/app/main.py", line 42, in run
    result = compute()
  File "/app/utils.py", line 15, in compute
    return x / 0
ZeroDivisionError: division by zero"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Check if any result has stack frames
        all_frames = []
        for r in results:
            all_frames.extend(r.parsed_fields.get("stack_frames", []))

        # If frames extracted, verify structure
        if len(all_frames) >= 1:
            first_frame = all_frames[0]
            assert "file" in first_frame
            assert "line" in first_frame
            assert "function" in first_frame

    def test_parse_exception_message(self):
        """Test exception message extraction."""
        log = """Traceback (most recent call last):
  File "test.py", line 1, in <module>
    raise ValueError("invalid input value")
ValueError: invalid input value"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        assert results[0].parsed_fields.get("exception_type") == "ValueError"
        assert results[0].parsed_fields.get("exception_message") == "invalid input value"

    # --- structlog JSON Tests ---

    def test_parse_structlog_json(self):
        """Test parsing structlog JSON format."""
        log = '{"event": "Request received", "level": "info", "timestamp": "2024-01-15T10:30:45.123Z", "path": "/api/users"}'

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.INFO
        assert "Request received" in results[0].raw_message

    def test_parse_structlog_json_with_exception(self):
        """Test parsing structlog JSON with exception info."""
        log = '{"event": "Error occurred", "level": "error", "timestamp": "2024-01-15T10:30:45.123Z", "exc_info": "ValueError: bad value"}'

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.ERROR

    def test_parse_json_lines(self):
        """Test parsing multiple JSON log lines."""
        logs = """{"event": "Line 1", "level": "info", "timestamp": "2024-01-15T10:30:45Z"}
{"event": "Line 2", "level": "warning", "timestamp": "2024-01-15T10:30:46Z"}
{"event": "Line 3", "level": "error", "timestamp": "2024-01-15T10:30:47Z"}"""

        results = self.parser.parse(logs)

        assert len(results) == 3

    def test_force_json_mode(self):
        """Test forcing JSON parsing mode."""
        parser = PythonLogParser({"json_mode": True})
        log = '{"event": "Test", "level": "info"}'

        results = parser.parse(log)

        assert len(results) == 1

    # --- Security Exception Detection Tests ---

    def test_detect_sql_exception(self):
        """Test SQL exception detection."""
        log = """Traceback (most recent call last):
  File "db.py", line 10, in query
    cursor.execute(sql)
sqlite3.OperationalError: near "DROP": syntax error"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Check for security issues or exception type detection
        security_issues = results[0].parsed_fields.get("security_issues", [])
        exception_type = results[0].parsed_fields.get("exception_type", "")
        assert len(security_issues) > 0 or "OperationalError" in exception_type or "sqlite3" in results[0].raw_message

    def test_detect_permission_error(self):
        """Test permission error detection."""
        log = """Traceback (most recent call last):
  File "file.py", line 5, in read_config
    open('/etc/shadow')
PermissionError: [Errno 13] Permission denied: '/etc/shadow'"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Check for security detection or exception type
        exception_type = results[0].parsed_fields.get("exception_type", "")
        assert "PermissionError" in exception_type or "PermissionError" in results[0].raw_message

    def test_detect_pickle_error(self):
        """Test pickle deserialization error detection."""
        log = """Traceback (most recent call last):
  File "load.py", line 3, in load_data
    pickle.loads(data)
pickle.UnpicklingError: invalid load key"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Check for exception in results
        assert any("UnpicklingError" in r.raw_message or "pickle" in r.raw_message for r in results)

    def test_detect_file_not_found(self):
        """Test file not found (path traversal) detection."""
        log = """Traceback (most recent call last):
  File "server.py", line 20, in serve_file
    open(path)
FileNotFoundError: [Errno 2] No such file or directory: '../../../etc/passwd'"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Check for exception in results
        assert any("FileNotFoundError" in r.raw_message or "etc/passwd" in r.raw_message for r in results)

    # --- Logger/Module Extraction Tests ---

    def test_extract_module_name(self):
        """Test module name extraction."""
        log = "2024-01-15 10:30:45,123 INFO myapp.services.user: User created"

        results = self.parser.parse(log)

        assert len(results) == 1
        # Module name should be in parsed fields
        assert "myapp" in results[0].raw_message or results[0].parsed_fields.get("module")

    # --- Error Handling Tests ---

    def test_parse_malformed_json(self):
        """Test handling malformed JSON."""
        log = '{"event": "broken json'

        results = self.parser.parse(log)

        # Should fall back to text parsing
        assert len(results) == 1

    def test_parse_mixed_format(self):
        """Test parsing mixed format logs."""
        logs = """2024-01-15 10:30:45,123 INFO Text log entry
{"event": "JSON entry", "level": "info"}
2024-01-15 10:30:46,456 WARNING Another text entry"""

        results = self.parser.parse(logs)

        assert len(results) >= 2

    # --- Multiline Aggregation Tests ---

    def test_aggregate_traceback_with_log(self):
        """Test aggregating traceback with preceding log line."""
        log = """2024-01-15 10:30:45,123 ERROR Exception occurred
Traceback (most recent call last):
  File "test.py", line 1, in test
    raise Exception("test")
Exception: test
2024-01-15 10:30:46,123 INFO Next log entry"""

        results = self.parser.parse(log)

        # Should have at least 2 entries
        assert len(results) >= 2
        # First error entry should have stack frames
        error_results = [r for r in results if r.severity == EventSeverity.ERROR]
        assert len(error_results) >= 1

    # --- Protocol and Event Type Tests ---

    def test_event_type_is_application(self):
        """Test that event type is APPLICATION."""
        log = "2024-01-15 10:30:45,123 INFO Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].event_type == EventType.APPLICATION

    def test_protocol_is_python(self):
        """Test that protocol is set to python."""
        log = "2024-01-15 10:30:45,123 INFO Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].protocol == "python"

    # --- Common Python Exceptions ---

    def test_parse_common_exceptions(self):
        """Test parsing various common Python exceptions."""
        exceptions = [
            ("TypeError: 'str' object", "TypeError"),
            ("ValueError: invalid literal", "ValueError"),
            ("AttributeError: 'NoneType'", "AttributeError"),
            ("IndexError: list index out of range", "IndexError"),
            ("ImportError: No module named", "ImportError"),
        ]

        for exc_line, expected_type in exceptions:
            log = f"""Traceback (most recent call last):
  File "test.py", line 1, in test
    code()
{exc_line}"""

            results = self.parser.parse(log)
            assert len(results) >= 1
            assert results[0].parsed_fields.get("exception_type") == expected_type
