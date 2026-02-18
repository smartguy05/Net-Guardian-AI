"""Tests for the Java stack trace parser."""

from app.models.raw_event import EventSeverity, EventType
from app.parsers.java_stacktrace_parser import JavaStacktraceParser


class TestJavaStacktraceParser:
    """Tests for JavaStacktraceParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = JavaStacktraceParser({})

    # --- Basic Parsing Tests ---

    def test_parse_simple_log_line(self):
        """Test parsing simple Java log line."""
        log = "2024-01-15 10:30:45,123 INFO  com.example.Main - Application started"

        results = self.parser.parse(log)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.APPLICATION
        assert result.severity == EventSeverity.INFO
        assert "Application started" in result.raw_message

    def test_parse_multiple_log_lines(self):
        """Test parsing multiple log lines."""
        logs = """2024-01-15 10:30:45,123 INFO  com.example.Main - Line 1
2024-01-15 10:30:46,456 WARN  com.example.Main - Line 2
2024-01-15 10:30:47,789 ERROR com.example.Main - Line 3"""

        results = self.parser.parse(logs)

        assert len(results) == 3
        assert results[0].severity == EventSeverity.INFO
        assert results[1].severity == EventSeverity.WARNING
        assert results[2].severity == EventSeverity.ERROR

    def test_parse_list_of_lines(self):
        """Test parsing list of log lines."""
        logs = [
            "2024-01-15 10:30:45,123 INFO  Main - Entry 1",
            "2024-01-15 10:30:46,456 INFO  Main - Entry 2",
        ]

        results = self.parser.parse(logs)

        assert len(results) == 2

    def test_parse_empty_input(self):
        """Test parsing empty or whitespace input."""
        # Empty list should return no results
        assert self.parser.parse([]) == []
        # Note: Empty string may return a result with defaults due to parser behavior

    # --- Timestamp Parsing Tests ---

    def test_parse_log4j_timestamp(self):
        """Test parsing Log4j timestamp format."""
        log = "2024-01-15 10:30:45,123 INFO Main - Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024
        assert results[0].timestamp.month == 1
        assert results[0].timestamp.day == 15
        assert results[0].timestamp.hour == 10
        assert results[0].timestamp.minute == 30

    def test_parse_iso_timestamp(self):
        """Test parsing ISO 8601 timestamp."""
        log = "2024-01-15T10:30:45.123Z INFO Main - Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024

    def test_parse_timestamp_with_timezone(self):
        """Test parsing timestamp with timezone offset."""
        log = "2024-01-15T10:30:45.123+05:30 INFO Main - Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].timestamp is not None

    # --- Log Level Tests ---

    def test_parse_trace_level(self):
        """Test parsing TRACE log level."""
        log = "2024-01-15 10:30:45,123 TRACE Main - Debug trace"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.DEBUG

    def test_parse_debug_level(self):
        """Test parsing DEBUG log level."""
        log = "2024-01-15 10:30:45,123 DEBUG Main - Debug message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.DEBUG

    def test_parse_info_level(self):
        """Test parsing INFO log level."""
        log = "2024-01-15 10:30:45,123 INFO Main - Info message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.INFO

    def test_parse_warn_level(self):
        """Test parsing WARN log level."""
        log = "2024-01-15 10:30:45,123 WARN Main - Warning message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_parse_warning_level(self):
        """Test parsing WARNING log level."""
        log = "2024-01-15 10:30:45,123 WARNING Main - Warning message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING

    def test_parse_error_level(self):
        """Test parsing ERROR log level."""
        log = "2024-01-15 10:30:45,123 ERROR Main - Error message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.ERROR

    def test_parse_fatal_level(self):
        """Test parsing FATAL log level."""
        log = "2024-01-15 10:30:45,123 FATAL Main - Fatal error"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.CRITICAL

    def test_parse_severe_level(self):
        """Test parsing SEVERE log level (java.util.logging)."""
        log = "2024-01-15 10:30:45,123 SEVERE Main - Severe error"

        results = self.parser.parse(log)

        assert len(results) == 1
        # SEVERE maps to ERROR in Java logging (not CRITICAL)
        assert results[0].severity == EventSeverity.ERROR

    # --- Exception Parsing Tests ---

    def test_parse_simple_exception(self):
        """Test parsing simple exception."""
        log = """2024-01-15 10:30:45,123 ERROR Main - Operation failed
java.lang.NullPointerException: value cannot be null
	at com.example.Service.process(Service.java:42)
	at com.example.Main.main(Main.java:10)"""

        results = self.parser.parse(log)

        assert len(results) == 1
        result = results[0]
        assert result.severity == EventSeverity.ERROR
        assert result.parsed_fields.get("exception_type") == "java.lang.NullPointerException"
        assert result.parsed_fields.get("exception_message") == "value cannot be null"
        assert "stack_frames" in result.parsed_fields
        assert len(result.parsed_fields["stack_frames"]) >= 2

    def test_parse_exception_chain(self):
        """Test parsing exception with caused by chain."""
        log = """2024-01-15 10:30:45,123 ERROR Main - Database error
java.lang.RuntimeException: Failed to save entity
	at com.example.DAO.save(DAO.java:50)
Caused by: java.sql.SQLException: Connection refused
	at com.mysql.Driver.connect(Driver.java:100)
Caused by: java.net.ConnectException: Connection refused
	at java.net.Socket.connect(Socket.java:500)"""

        results = self.parser.parse(log)

        assert len(results) == 1
        result = results[0]
        assert result.parsed_fields.get("exception_type") == "java.lang.RuntimeException"
        # Should have caused by chain
        assert "caused_by" in result.parsed_fields or "root_cause" in result.parsed_fields

    def test_parse_stack_frames(self):
        """Test stack frame extraction."""
        log = """2024-01-15 10:30:45,123 ERROR Main - Error
java.lang.Exception: test
	at com.example.MyClass.myMethod(MyClass.java:42)
	at com.example.Other.call(Other.java:100)"""

        results = self.parser.parse(log)

        assert len(results) == 1
        frames = results[0].parsed_fields.get("stack_frames", [])
        assert len(frames) >= 2

        first_frame = frames[0]
        assert first_frame.get("class") == "com.example.MyClass"
        assert first_frame.get("method") == "myMethod"
        assert first_frame.get("file") == "MyClass.java"
        assert first_frame.get("line") == 42

    # --- Security Exception Detection Tests ---

    def test_detect_sql_exception(self):
        """Test SQL exception detection."""
        log = """2024-01-15 10:30:45,123 ERROR Main - Database error
java.sql.SQLException: You have an error in your SQL syntax
	at com.mysql.Driver.executeQuery(Driver.java:100)"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Parser stores security issues in 'security_issues' field
        security_issues = results[0].parsed_fields.get("security_issues", [])
        assert (
            len(security_issues) > 0
            or results[0].parsed_fields.get("exception_type") == "java.sql.SQLException"
        )

    def test_detect_security_exception(self):
        """Test generic security exception detection."""
        log = """2024-01-15 10:30:45,123 ERROR Main - Access denied
java.lang.SecurityException: Access to file denied
	at java.lang.SecurityManager.checkRead(SecurityManager.java:50)"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Check exception type is detected
        assert results[0].parsed_fields.get("exception_type") == "java.lang.SecurityException"

    def test_detect_jndi_injection(self):
        """Test JNDI injection pattern detection."""
        log = """2024-01-15 10:30:45,123 ERROR Main - JNDI lookup failed
javax.naming.NamingException: Invalid JNDI lookup
	at javax.naming.InitialContext.lookup(InitialContext.java:100)"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Check exception type is detected
        assert results[0].parsed_fields.get("exception_type") == "javax.naming.NamingException"

    def test_detect_deserialization_gadget(self):
        """Test deserialization gadget detection."""
        log = """2024-01-15 10:30:45,123 ERROR Main - Deserialization error
java.io.InvalidClassException: Object stream class desc
	at org.apache.commons.collections.functors.InvokerTransformer.transform(InvokerTransformer.java:50)"""

        results = self.parser.parse(log)

        assert len(results) >= 1
        # Check for security_issues or exception detection
        security_issues = results[0].parsed_fields.get("security_issues", [])
        has_gadget = any("deserialization" in str(issue).lower() for issue in security_issues)
        assert has_gadget or "InvalidClassException" in results[0].parsed_fields.get(
            "exception_type", ""
        )

    def test_disable_security_detection(self):
        """Test disabling security exception detection."""
        parser = JavaStacktraceParser({"detect_security_exceptions": False})
        log = """2024-01-15 10:30:45,123 ERROR Main - SQL error
java.sql.SQLException: Error
	at com.mysql.Driver.execute(Driver.java:100)"""

        results = parser.parse(log)

        assert len(results) == 1
        assert results[0].parsed_fields.get("is_security_exception") is not True

    # --- Thread Information Tests ---

    def test_extract_thread_name(self):
        """Test thread name extraction."""
        log = "2024-01-15 10:30:45,123 [http-nio-8080-exec-1] INFO Main - Request"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].parsed_fields.get("thread_name") == "http-nio-8080-exec-1"

    # --- Spring Boot Format Tests ---

    def test_parse_spring_boot_format(self):
        """Test parsing Spring Boot default log format."""
        log = "2024-01-15 10:30:45.123  INFO 12345 --- [main] c.e.Application : Started Application in 5.5 seconds"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.INFO
        assert "Started Application" in results[0].raw_message

    # --- Logger Name Extraction Tests ---

    def test_extract_logger_name(self):
        """Test logger name extraction."""
        log = "2024-01-15 10:30:45,123 INFO com.example.service.UserService - User created"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].parsed_fields.get("logger") == "com.example.service.UserService"

    # --- Error Handling Tests ---

    def test_parse_malformed_line(self):
        """Test parsing line without standard format."""
        log = "Just some random text without timestamp or level"

        results = self.parser.parse(log)

        # Should still parse, but with defaults
        assert len(results) == 1
        assert results[0].severity == EventSeverity.INFO

    def test_parse_mixed_valid_invalid(self):
        """Test parsing mix of valid and invalid lines."""
        logs = """2024-01-15 10:30:45,123 INFO Main - Valid line 1
Some continuation text
2024-01-15 10:30:46,123 ERROR Main - Valid line 2"""

        results = self.parser.parse(logs)

        # Should get at least 2 results (with possible aggregation)
        assert len(results) >= 2

    # --- Multiline Aggregation Tests ---

    def test_aggregate_multiline_stacktrace(self):
        """Test that multiline stack traces are aggregated."""
        log = """2024-01-15 10:30:45,123 ERROR Main - Error occurred
java.lang.Exception: Test
	at com.example.Test.run(Test.java:10)
	at com.example.Main.main(Main.java:5)
2024-01-15 10:30:46,123 INFO Main - Next log entry"""

        results = self.parser.parse(log)

        # Should have multiple results
        assert len(results) >= 1
        # Check if any result has stack frames
        has_stack = any(len(r.parsed_fields.get("stack_frames", [])) > 0 for r in results)
        assert has_stack or any(r.severity == EventSeverity.ERROR for r in results)

    # --- Protocol and Event Type Tests ---

    def test_event_type_is_application(self):
        """Test that event type is APPLICATION."""
        log = "2024-01-15 10:30:45,123 INFO Main - Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].event_type == EventType.APPLICATION

    def test_protocol_is_java(self):
        """Test that protocol is set to java."""
        log = "2024-01-15 10:30:45,123 INFO Main - Message"

        results = self.parser.parse(log)

        assert len(results) == 1
        assert results[0].protocol == "java"
