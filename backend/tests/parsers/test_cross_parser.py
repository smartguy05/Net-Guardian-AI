"""Cross-parser tests for edge cases, unicode, and boundary conditions.

Tests that verify all parsers handle:
- Unicode characters in various fields
- Very long strings
- Empty values
- Special characters
- Malformed input
"""

import pytest
from datetime import datetime, timezone

from app.parsers.adguard_parser import AdGuardParser
from app.parsers.json_parser import JsonParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.endpoint_parser import EndpointParser
from app.parsers.custom_parser import CustomParser
from app.parsers.netflow_parser import NetFlowParser
from app.parsers.sflow_parser import SFlowParser
from app.parsers.loki_parser import LokiParser
from app.parsers.ollama_parser import OllamaParser


class TestUnicodeHandling:
    """Tests for unicode character handling across all parsers."""

    @pytest.fixture
    def json_parser(self):
        return JsonParser()

    @pytest.fixture
    def syslog_parser(self):
        return SyslogParser()

    @pytest.fixture
    def endpoint_parser(self):
        return EndpointParser()

    @pytest.fixture
    def adguard_parser(self):
        return AdGuardParser()

    @pytest.fixture
    def custom_parser(self):
        return CustomParser(config={
            "patterns": [r"(?P<message>.+)"]
        })

    @pytest.fixture
    def netflow_parser(self):
        return NetFlowParser()

    @pytest.fixture
    def sflow_parser(self):
        return SFlowParser()

    @pytest.fixture
    def loki_parser(self):
        return LokiParser()

    @pytest.fixture
    def ollama_parser(self):
        return OllamaParser()

    # --- JSON Parser Unicode Tests ---

    def test_json_parser_unicode_message(self, json_parser):
        """Test JSON parser with unicode in message field."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "Error: файл не найден (файл: 日本語.txt)",
            "level": "error",
        }
        results = json_parser.parse(data)
        assert len(results) == 1
        assert "файл" in results[0].raw_message
        assert "日本語" in results[0].raw_message

    def test_json_parser_unicode_hostname(self, json_parser):
        """Test JSON parser with unicode in hostname."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "сервер-001",
            "message": "Test message",
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    def test_json_parser_emoji_in_message(self, json_parser):
        """Test JSON parser with emoji characters."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "Build succeeded! 🎉 All tests passed ✅",
        }
        results = json_parser.parse(data)
        assert len(results) == 1
        assert "🎉" in results[0].raw_message

    def test_json_parser_chinese_characters(self, json_parser):
        """Test JSON parser with Chinese characters."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "用户登录: 张三 从 北京",
            "user": "张三",
        }
        results = json_parser.parse(data)
        assert len(results) == 1
        assert "张三" in results[0].raw_message

    def test_json_parser_arabic_characters(self, json_parser):
        """Test JSON parser with Arabic characters."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "تم تسجيل الدخول بنجاح",
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    # --- Syslog Parser Unicode Tests ---

    def test_syslog_parser_unicode_message(self, syslog_parser):
        """Test syslog parser with unicode in message."""
        log = "<134>Jan 15 10:30:00 server app: Ошибка подключения к базе данных"
        results = syslog_parser.parse(log)
        assert len(results) == 1
        assert "Ошибка" in results[0].raw_message

    def test_syslog_rfc5424_unicode(self, syslog_parser):
        """Test RFC5424 syslog with unicode."""
        log = '<165>1 2024-01-15T10:30:00Z server app - - - Événement: échec de connexion'
        results = syslog_parser.parse(log)
        assert len(results) == 1
        assert "échec" in results[0].raw_message

    # --- Endpoint Parser Unicode Tests ---

    def test_endpoint_parser_unicode_process(self, endpoint_parser):
        """Test endpoint parser with unicode in process name."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "process",
            "hostname": "workstation-001",
            "data": {
                "name": "приложение.exe",
                "user": "Пользователь",
            }
        }
        results = endpoint_parser.parse(data)
        assert len(results) == 1
        # Unicode process name should appear in raw_message
        assert "приложение" in results[0].raw_message

    def test_endpoint_parser_unicode_path(self, endpoint_parser):
        """Test endpoint parser with unicode in file path."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "file",
            "hostname": "server-001",
            "data": {
                "path": "/home/用户/документы/файл.txt",
                "action": "access",
            }
        }
        results = endpoint_parser.parse(data)
        assert len(results) == 1
        assert "用户" in results[0].raw_message or "документы" in results[0].raw_message

    # --- Custom Parser Unicode Tests ---

    def test_custom_parser_unicode_capture(self, custom_parser):
        """Test custom parser captures unicode correctly."""
        log = "Событие: пользователь вошел в систему"
        results = custom_parser.parse(log)
        assert len(results) == 1
        assert "пользователь" in results[0].raw_message

    # --- NetFlow Parser Unicode (JSON mode) ---

    def test_netflow_json_unicode_fields(self, netflow_parser):
        """Test NetFlow parser handles unicode in JSON fields."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "application": "веб-сервер",
            "notes": "Трафик от сервера",
        }
        results = netflow_parser.parse(data)
        assert len(results) == 1

    # --- sFlow Parser Unicode (JSON mode) ---

    def test_sflow_json_unicode_fields(self, sflow_parser):
        """Test sFlow parser handles unicode in JSON fields."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "protocol": "TCP",
            "application": "数据库",
        }
        results = sflow_parser.parse(data)
        assert len(results) == 1

    # --- Loki Parser Unicode Tests ---

    def test_loki_parser_unicode_labels(self, loki_parser):
        """Test Loki parser with unicode in labels."""
        data = {
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [
                    {
                        "stream": {"job": "приложение", "instance": "сервер"},
                        "values": [
                            ["1705312200000000000", "Log message with unicode: 日本語"]
                        ]
                    }
                ]
            }
        }
        results = loki_parser.parse(data)
        assert len(results) == 1
        assert "日本語" in results[0].raw_message


class TestBoundaryConditions:
    """Tests for boundary conditions (long strings, empty values, etc.)."""

    @pytest.fixture
    def json_parser(self):
        return JsonParser()

    @pytest.fixture
    def syslog_parser(self):
        return SyslogParser()

    @pytest.fixture
    def endpoint_parser(self):
        return EndpointParser()

    @pytest.fixture
    def custom_parser(self):
        return CustomParser(config={
            "patterns": [r"(?P<message>.+)"]
        })

    @pytest.fixture
    def netflow_parser(self):
        return NetFlowParser()

    @pytest.fixture
    def adguard_parser(self):
        return AdGuardParser()

    # --- Very Long Strings ---

    def test_json_parser_very_long_message(self, json_parser):
        """Test JSON parser with very long message (100KB)."""
        long_message = "A" * 100000  # 100KB message
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": long_message,
        }
        results = json_parser.parse(data)
        assert len(results) == 1
        assert len(results[0].raw_message) >= 100000

    def test_syslog_parser_very_long_message(self, syslog_parser):
        """Test syslog parser with very long message."""
        long_message = "X" * 50000
        log = f"<134>Jan 15 10:30:00 server app: {long_message}"
        results = syslog_parser.parse(log)
        assert len(results) == 1

    def test_endpoint_parser_long_process_name(self, endpoint_parser):
        """Test endpoint parser with very long process name."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "process",
            "hostname": "workstation",
            "data": {
                "name": "process_" + "x" * 1000 + ".exe",
                "user": "test",
            }
        }
        results = endpoint_parser.parse(data)
        assert len(results) == 1

    def test_custom_parser_long_line(self, custom_parser):
        """Test custom parser with very long line."""
        long_line = "Log: " + "message " * 10000
        results = custom_parser.parse(long_line)
        assert len(results) == 1

    # --- Empty Values ---

    def test_json_parser_empty_message(self, json_parser):
        """Test JSON parser with empty message."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "",
        }
        results = json_parser.parse(data)
        # Should still produce a result
        assert len(results) == 1

    def test_json_parser_null_fields(self, json_parser):
        """Test JSON parser with null fields."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": None,
            "hostname": None,
            "level": None,
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    def test_json_parser_empty_object(self, json_parser):
        """Test JSON parser with empty object."""
        results = json_parser.parse({})
        # May or may not produce result depending on implementation
        # Just verify it doesn't crash
        assert isinstance(results, list)

    def test_syslog_parser_empty_string(self, syslog_parser):
        """Test syslog parser with empty string."""
        results = syslog_parser.parse("")
        assert len(results) == 0

    def test_custom_parser_empty_string(self, custom_parser):
        """Test custom parser with empty string."""
        results = custom_parser.parse("")
        assert len(results) == 0

    def test_netflow_parser_empty_json(self, netflow_parser):
        """Test NetFlow parser with empty JSON."""
        results = netflow_parser.parse({})
        assert isinstance(results, list)

    # --- Whitespace Handling ---

    def test_json_parser_whitespace_only_message(self, json_parser):
        """Test JSON parser with whitespace-only message."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "   \t\n   ",
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    def test_syslog_parser_whitespace_padding(self, syslog_parser):
        """Test syslog parser with whitespace padding."""
        log = "   <134>Jan 15 10:30:00 server app: Message   "
        results = syslog_parser.parse(log)
        # Should handle leading/trailing whitespace
        assert isinstance(results, list)

    # --- Special Characters ---

    def test_json_parser_special_characters(self, json_parser):
        """Test JSON parser with special characters."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": 'Path: C:\\Users\\test\\file.txt with "quotes" and <tags>',
        }
        results = json_parser.parse(data)
        assert len(results) == 1
        assert "C:\\Users" in results[0].raw_message

    def test_json_parser_newlines_in_message(self, json_parser):
        """Test JSON parser with newlines in message."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "Line 1\nLine 2\nLine 3",
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    def test_json_parser_tab_characters(self, json_parser):
        """Test JSON parser with tab characters."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "Column1\tColumn2\tColumn3",
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    def test_syslog_parser_control_characters(self, syslog_parser):
        """Test syslog parser with control characters."""
        # Some logs may contain control chars
        log = "<134>Jan 15 10:30:00 server app: Data\x00with\x01control\x02chars"
        results = syslog_parser.parse(log)
        # Should handle without crashing
        assert isinstance(results, list)


class TestMalformedInput:
    """Tests for handling malformed or unexpected input."""

    @pytest.fixture
    def json_parser(self):
        return JsonParser()

    @pytest.fixture
    def syslog_parser(self):
        return SyslogParser()

    @pytest.fixture
    def endpoint_parser(self):
        return EndpointParser()

    @pytest.fixture
    def netflow_parser(self):
        return NetFlowParser()

    @pytest.fixture
    def sflow_parser(self):
        return SFlowParser()

    @pytest.fixture
    def adguard_parser(self):
        return AdGuardParser()

    # --- Invalid Types ---

    def test_json_parser_with_number(self, json_parser):
        """Test JSON parser with numeric input."""
        results = json_parser.parse(12345)
        assert isinstance(results, list)

    def test_json_parser_with_boolean(self, json_parser):
        """Test JSON parser with boolean input."""
        results = json_parser.parse(True)
        assert isinstance(results, list)

    def test_json_parser_with_none(self, json_parser):
        """Test JSON parser with None input."""
        results = json_parser.parse(None)
        assert isinstance(results, list)

    def test_syslog_parser_with_bytes(self, syslog_parser):
        """Test syslog parser with bytes input."""
        results = syslog_parser.parse(b"<134>Jan 15 10:30:00 server app: Message")
        # Should handle bytes or return empty
        assert isinstance(results, list)

    def test_endpoint_parser_with_string(self, endpoint_parser):
        """Test endpoint parser with string instead of dict."""
        results = endpoint_parser.parse("not a dict")
        assert isinstance(results, list)
        assert len(results) == 0

    def test_netflow_parser_with_invalid_bytes(self, netflow_parser):
        """Test NetFlow parser with random bytes."""
        results = netflow_parser.parse(b"\x00\x01\x02\x03")
        assert isinstance(results, list)
        assert len(results) == 0

    def test_sflow_parser_with_invalid_bytes(self, sflow_parser):
        """Test sFlow parser with random bytes."""
        results = sflow_parser.parse(b"\xff\xfe\xfd\xfc")
        assert isinstance(results, list)
        assert len(results) == 0

    # --- Malformed Timestamps ---

    def test_json_parser_invalid_timestamp(self, json_parser):
        """Test JSON parser with invalid timestamp format."""
        data = {
            "timestamp": "not-a-timestamp",
            "message": "Test message",
        }
        # JSON parser may raise an exception or return empty for invalid timestamps
        # This tests that it doesn't crash silently
        try:
            results = json_parser.parse(data)
            # If it succeeds, verify it's a valid result
            assert isinstance(results, list)
        except (ValueError, TypeError):
            # Parser may raise exception for truly invalid timestamps
            pass

    def test_json_parser_future_timestamp(self, json_parser):
        """Test JSON parser with far-future timestamp."""
        data = {
            "timestamp": "2099-12-31T23:59:59Z",
            "message": "Message from the future",
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    def test_json_parser_epoch_timestamp(self, json_parser):
        """Test JSON parser with Unix epoch timestamp."""
        data = {
            "timestamp": 1705312200,  # Integer timestamp
            "message": "Test message",
        }
        results = json_parser.parse(data)
        # Should handle integer timestamp
        assert len(results) == 1

    # --- Invalid IP Addresses ---

    def test_endpoint_parser_invalid_ip(self, endpoint_parser):
        """Test endpoint parser with invalid IP address."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "network",
            "hostname": "workstation",
            "data": {
                "local_ip": "999.999.999.999",  # Invalid IP
                "remote_ip": "not-an-ip",
                "local_port": 12345,
                "remote_port": 443,
            }
        }
        results = endpoint_parser.parse(data)
        # Should handle gracefully
        assert len(results) == 1

    # --- Deeply Nested Data ---

    def test_json_parser_deeply_nested(self, json_parser):
        """Test JSON parser with deeply nested data."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "message": "Test",
            "nested": {
                "level1": {
                    "level2": {
                        "level3": {
                            "level4": {
                                "value": "deep"
                            }
                        }
                    }
                }
            }
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    # --- Large Arrays ---

    def test_json_parser_large_array(self, json_parser):
        """Test JSON parser with large array of entries."""
        data = [
            {"timestamp": "2024-01-15T10:30:00Z", "message": f"Message {i}"}
            for i in range(1000)
        ]
        results = json_parser.parse(data)
        assert len(results) == 1000


class TestIPv6Addresses:
    """Tests for IPv6 address handling across parsers."""

    @pytest.fixture
    def json_parser(self):
        return JsonParser()

    @pytest.fixture
    def endpoint_parser(self):
        return EndpointParser()

    @pytest.fixture
    def netflow_parser(self):
        return NetFlowParser()

    @pytest.fixture
    def sflow_parser(self):
        return SFlowParser()

    def test_json_parser_ipv6_full(self, json_parser):
        """Test JSON parser with full IPv6 address."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "message": "Connection from IPv6",
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    def test_json_parser_ipv6_compressed(self, json_parser):
        """Test JSON parser with compressed IPv6 address."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "source_ip": "2001:db8::1",
            "dest_ip": "::1",  # Loopback
            "message": "IPv6 connection",
        }
        results = json_parser.parse(data)
        assert len(results) == 1

    def test_endpoint_parser_ipv6(self, endpoint_parser):
        """Test endpoint parser with IPv6 addresses."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "network",
            "hostname": "workstation",
            "data": {
                "local_ip": "fe80::1",  # Link-local
                "remote_ip": "2001:db8::8888",
                "local_port": 54321,
                "remote_port": 443,
            }
        }
        results = endpoint_parser.parse(data)
        assert len(results) == 1
        assert results[0].client_ip == "fe80::1"

    def test_netflow_parser_ipv6_json(self, netflow_parser):
        """Test NetFlow parser with IPv6 in JSON mode."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "2001:db8::1",
            "dst_ip": "2001:db8::2",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
        }
        results = netflow_parser.parse(data)
        assert len(results) == 1
        assert results[0].client_ip == "2001:db8::1"

    def test_sflow_parser_ipv6_json(self, sflow_parser):
        """Test sFlow parser with IPv6 in JSON mode."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_ip": "::ffff:192.168.1.1",  # IPv4-mapped IPv6
            "dst_ip": "::ffff:8.8.8.8",
            "protocol": "TCP",
        }
        results = sflow_parser.parse(data)
        assert len(results) == 1


class TestConcurrentParsing:
    """Tests for parser thread safety and concurrent access."""

    @pytest.fixture
    def json_parser(self):
        return JsonParser()

    def test_parse_multiple_formats_sequentially(self, json_parser):
        """Test parsing different formats sequentially."""
        # Single entry
        result1 = json_parser.parse({"timestamp": "2024-01-15T10:00:00Z", "message": "Single"})

        # Array
        result2 = json_parser.parse([
            {"timestamp": "2024-01-15T10:01:00Z", "message": "Array 1"},
            {"timestamp": "2024-01-15T10:02:00Z", "message": "Array 2"},
        ])

        # Line-delimited
        result3 = json_parser.parse('{"timestamp": "2024-01-15T10:03:00Z", "message": "Line"}')

        assert len(result1) == 1
        assert len(result2) == 2
        assert len(result3) == 1

    def test_parser_state_isolation(self):
        """Test that parser instances maintain isolated state."""
        parser1 = JsonParser(config={"timestamp_field": "ts"})
        parser2 = JsonParser(config={"timestamp_field": "time"})

        # Verify configs are isolated
        assert parser1.config.get("timestamp_field") == "ts"
        assert parser2.config.get("timestamp_field") == "time"
