"""Tests for the Grafana Loki parser."""

from datetime import UTC, datetime

from app.models.raw_event import EventSeverity, EventType
from app.parsers.loki_parser import LokiParser


class TestLokiParser:
    """Tests for LokiParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = LokiParser()

    def test_parse_query_api_response(self):
        """Test parsing standard Loki query API response."""
        data = {
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [
                    {
                        "stream": {
                            "job": "nginx",
                            "level": "info",
                        },
                        "values": [
                            ["1705320000000000000", "192.168.1.100 - - GET /api/users 200"],
                        ],
                    }
                ],
            },
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.HTTP
        assert result.severity == EventSeverity.INFO
        assert result.raw_message == "192.168.1.100 - - GET /api/users 200"
        assert result.client_ip == "192.168.1.100"
        assert result.parsed_fields["labels"]["job"] == "nginx"

    def test_parse_push_api_format(self):
        """Test parsing Loki push API format."""
        data = {
            "streams": [
                {
                    "stream": {
                        "job": "syslog",
                        "host": "server1",
                    },
                    "values": [
                        ["1705320000000000000", "System started successfully"],
                    ],
                }
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].event_type == EventType.SYSTEM
        assert results[0].parsed_fields["host"] == "server1"

    def test_parse_single_stream_format(self):
        """Test parsing single stream object."""
        data = {
            "stream": {
                "job": "app",
                "level": "error",
            },
            "values": [
                ["1705320000000000000", "Connection failed to database"],
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.ERROR

    def test_parse_list_of_streams(self):
        """Test parsing list of streams directly."""
        data = [
            {
                "stream": {"job": "nginx"},
                "values": [["1705320000000000000", "Request received"]],
            },
            {
                "stream": {"job": "auth"},
                "values": [["1705320001000000000", "User login"]],
            },
        ]

        results = self.parser.parse(data)

        assert len(results) == 2
        assert results[0].event_type == EventType.HTTP
        assert results[1].event_type == EventType.AUTH

    def test_parse_multiple_values_in_stream(self):
        """Test parsing stream with multiple log entries."""
        data = {
            "streams": [
                {
                    "stream": {"job": "app"},
                    "values": [
                        ["1705320000000000000", "First log entry"],
                        ["1705320001000000000", "Second log entry"],
                        ["1705320002000000000", "Third log entry"],
                    ],
                }
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 3
        assert results[0].raw_message == "First log entry"
        assert results[1].raw_message == "Second log entry"
        assert results[2].raw_message == "Third log entry"

    def test_timestamp_parsing(self):
        """Test nanosecond timestamp parsing."""
        # 2024-01-15 12:00:00 UTC in nanoseconds
        timestamp_ns = "1705320000000000000"
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [[timestamp_ns, "Test message"]],
                }
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        # Check timestamp is approximately correct (within a second)
        expected = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        assert abs((results[0].timestamp - expected).total_seconds()) < 1

    def test_timestamp_as_integer(self):
        """Test timestamp as integer instead of string."""
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [[1705320000000000000, "Test message"]],
                }
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].timestamp.year == 2024

    def test_severity_from_level_label(self):
        """Test severity extraction from level label."""
        severity_tests = [
            ("debug", EventSeverity.DEBUG),
            ("info", EventSeverity.INFO),
            ("warn", EventSeverity.WARNING),
            ("warning", EventSeverity.WARNING),
            ("error", EventSeverity.ERROR),
            ("critical", EventSeverity.CRITICAL),
            ("fatal", EventSeverity.CRITICAL),
        ]

        for level, expected_severity in severity_tests:
            data = {
                "streams": [
                    {
                        "stream": {"level": level},
                        "values": [["1705320000000000000", "Test"]],
                    }
                ],
            }

            results = self.parser.parse(data)
            assert results[0].severity == expected_severity, f"Failed for level={level}"

    def test_severity_from_alternative_labels(self):
        """Test severity from alternative label names."""
        for label_name in ["severity", "log_level", "loglevel", "lvl"]:
            data = {
                "streams": [
                    {
                        "stream": {label_name: "error"},
                        "values": [["1705320000000000000", "Test"]],
                    }
                ],
            }

            results = self.parser.parse(data)
            assert results[0].severity == EventSeverity.ERROR

    def test_severity_from_log_line_bracket_format(self):
        """Test severity extraction from log line [LEVEL] format."""
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [["1705320000000000000", "[ERROR] Database connection failed"]],
                }
            ],
        }

        results = self.parser.parse(data)

        assert results[0].severity == EventSeverity.ERROR

    def test_severity_from_log_line_equals_format(self):
        """Test severity extraction from log line level=X format."""
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [
                        ["1705320000000000000", 'time=2024-01-15 level=warning msg="High latency"']
                    ],
                }
            ],
        }

        results = self.parser.parse(data)

        assert results[0].severity == EventSeverity.WARNING

    def test_event_type_from_job_label(self):
        """Test event type mapping from job label."""
        job_mappings = [
            ("nginx", EventType.HTTP),
            ("apache", EventType.HTTP),
            ("traefik", EventType.HTTP),
            ("coredns", EventType.DNS),
            ("pihole", EventType.DNS),
            ("sshd", EventType.AUTH),
            ("iptables", EventType.FIREWALL),
            ("systemd", EventType.SYSTEM),
            ("ollama", EventType.LLM),
        ]

        for job, expected_type in job_mappings:
            data = {
                "streams": [
                    {
                        "stream": {"job": job},
                        "values": [["1705320000000000000", "Test"]],
                    }
                ],
            }

            results = self.parser.parse(data)
            assert results[0].event_type == expected_type, f"Failed for job={job}"

    def test_event_type_from_alternative_labels(self):
        """Test event type from alternative label names."""
        for label_name in ["app", "application", "service", "component"]:
            data = {
                "streams": [
                    {
                        "stream": {label_name: "nginx"},
                        "values": [["1705320000000000000", "Test"]],
                    }
                ],
            }

            results = self.parser.parse(data)
            assert results[0].event_type == EventType.HTTP

    def test_ip_extraction_from_log_line(self):
        """Test IP address extraction from log content."""
        data = {
            "streams": [
                {
                    "stream": {"job": "nginx"},
                    "values": [
                        ["1705320000000000000", "192.168.1.50 -> 10.0.0.1 connection established"]
                    ],
                }
            ],
        }

        results = self.parser.parse(data)

        assert results[0].client_ip == "192.168.1.50"
        assert results[0].target_ip == "10.0.0.1"

    def test_ip_extraction_filters_localhost(self):
        """Test that localhost IPs are filtered out."""
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [["1705320000000000000", "127.0.0.1 -> 192.168.1.100 forwarded"]],
                }
            ],
        }

        results = self.parser.parse(data)

        # 127.0.0.1 should be filtered, 192.168.1.100 should be client
        assert results[0].client_ip == "192.168.1.100"

    def test_ip_extraction_disabled_by_config(self):
        """Test IP extraction can be disabled."""
        parser = LokiParser({"extract_ips_from_message": False})
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [["1705320000000000000", "192.168.1.100 sent request"]],
                }
            ],
        }

        results = parser.parse(data)

        assert results[0].client_ip is None

    def test_ip_from_label_takes_precedence(self):
        """Test IP from label overrides extraction."""
        parser = LokiParser(
            {
                "client_ip_label": "source_ip",
                "target_ip_label": "dest_ip",
            }
        )
        data = {
            "streams": [
                {
                    "stream": {
                        "source_ip": "10.0.0.1",
                        "dest_ip": "10.0.0.2",
                    },
                    "values": [["1705320000000000000", "192.168.1.100 sent request"]],
                }
            ],
        }

        results = parser.parse(data)

        assert results[0].client_ip == "10.0.0.1"
        assert results[0].target_ip == "10.0.0.2"

    def test_custom_severity_label(self):
        """Test custom severity label configuration."""
        parser = LokiParser({"severity_label": "log_severity"})
        data = {
            "streams": [
                {
                    "stream": {"log_severity": "critical"},
                    "values": [["1705320000000000000", "Test"]],
                }
            ],
        }

        results = parser.parse(data)

        assert results[0].severity == EventSeverity.CRITICAL

    def test_custom_event_type_label(self):
        """Test custom event type label configuration."""
        parser = LokiParser({"event_type_label": "service_name"})
        data = {
            "streams": [
                {
                    "stream": {"service_name": "nginx"},
                    "values": [["1705320000000000000", "Test"]],
                }
            ],
        }

        results = parser.parse(data)

        assert results[0].event_type == EventType.HTTP

    def test_custom_event_type_mapping(self):
        """Test custom event type mapping."""
        parser = LokiParser(
            {
                "event_type_mapping": {
                    "my-custom-service": "http",
                    "my-dns-service": EventType.DNS,
                }
            }
        )
        data = {
            "streams": [
                {
                    "stream": {"job": "my-custom-service"},
                    "values": [["1705320000000000000", "Test"]],
                }
            ],
        }

        results = parser.parse(data)

        assert results[0].event_type == EventType.HTTP

    def test_parsed_fields_include_all_labels(self):
        """Test that all labels are preserved in parsed_fields."""
        data = {
            "streams": [
                {
                    "stream": {
                        "job": "app",
                        "namespace": "production",
                        "pod": "app-pod-123",
                        "container": "main",
                        "custom_label": "custom_value",
                    },
                    "values": [["1705320000000000000", "Test"]],
                }
            ],
        }

        results = self.parser.parse(data)

        assert results[0].parsed_fields["labels"]["job"] == "app"
        assert results[0].parsed_fields["labels"]["custom_label"] == "custom_value"
        # Common labels promoted to top level
        assert results[0].parsed_fields["namespace"] == "production"
        assert results[0].parsed_fields["pod"] == "app-pod-123"
        assert results[0].parsed_fields["container"] == "main"

    def test_original_timestamp_preserved(self):
        """Test that original nanosecond timestamp is preserved."""
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [["1705320000123456789", "Test"]],
                }
            ],
        }

        results = self.parser.parse(data)

        assert results[0].parsed_fields["original_timestamp_ns"] == "1705320000123456789"

    def test_parse_empty_data(self):
        """Test parsing empty data."""
        assert self.parser.parse(None) == []
        assert self.parser.parse({}) == []
        assert self.parser.parse([]) == []
        assert self.parser.parse({"streams": []}) == []
        assert self.parser.parse({"data": {"result": []}}) == []

    def test_parse_invalid_data_type(self):
        """Test parsing invalid data type returns empty list."""
        assert self.parser.parse("invalid string") == []
        assert self.parser.parse(12345) == []

    def test_parse_invalid_stream_format(self):
        """Test parsing invalid stream format."""
        data = {
            "streams": [
                "invalid",
                None,
                {"stream": {}, "values": "not a list"},
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 0

    def test_parse_invalid_value_entries(self):
        """Test that invalid value entries are skipped."""
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [
                        ["1705320000000000000", "Valid entry"],
                        "invalid",
                        None,
                        ["only_timestamp"],
                        [],
                    ],
                }
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].raw_message == "Valid entry"

    def test_parse_non_string_log_line(self):
        """Test handling non-string log line."""
        data = {
            "streams": [
                {
                    "stream": {},
                    "values": [
                        ["1705320000000000000", {"message": "structured log"}],
                    ],
                }
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 1
        assert "message" in results[0].raw_message

    def test_parse_mixed_valid_invalid_streams(self):
        """Test parsing mix of valid and invalid streams."""
        data = {
            "streams": [
                {
                    "stream": {"job": "valid"},
                    "values": [["1705320000000000000", "Valid stream"]],
                },
                "invalid_stream",
                {
                    "stream": {"job": "also_valid"},
                    "values": [["1705320001000000000", "Another valid"]],
                },
            ],
        }

        results = self.parser.parse(data)

        assert len(results) == 2

    def test_default_event_type_is_system(self):
        """Test that unknown jobs default to SYSTEM event type."""
        data = {
            "streams": [
                {
                    "stream": {"job": "unknown-service"},
                    "values": [["1705320000000000000", "Test"]],
                }
            ],
        }

        results = self.parser.parse(data)

        assert results[0].event_type == EventType.SYSTEM

    def test_default_severity_is_info(self):
        """Test that unknown severity defaults to INFO."""
        data = {
            "streams": [
                {
                    "stream": {"level": "unknown_level"},
                    "values": [["1705320000000000000", "Test"]],
                }
            ],
        }

        results = self.parser.parse(data)

        assert results[0].severity == EventSeverity.INFO

    def test_case_insensitive_severity(self):
        """Test severity matching is case insensitive."""
        for level in ["ERROR", "Error", "error", "ERROR"]:
            data = {
                "streams": [
                    {
                        "stream": {"level": level},
                        "values": [["1705320000000000000", "Test"]],
                    }
                ],
            }

            results = self.parser.parse(data)
            assert results[0].severity == EventSeverity.ERROR

    def test_case_insensitive_event_type(self):
        """Test event type matching is case insensitive."""
        for job in ["NGINX", "Nginx", "nginx", "NginX"]:
            data = {
                "streams": [
                    {
                        "stream": {"job": job},
                        "values": [["1705320000000000000", "Test"]],
                    }
                ],
            }

            results = self.parser.parse(data)
            assert results[0].event_type == EventType.HTTP

    def test_real_world_loki_response(self):
        """Test with realistic Loki query response."""
        data = {
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [
                    {
                        "stream": {
                            "app": "nginx",
                            "container": "nginx",
                            "filename": "/var/log/nginx/access.log",
                            "host": "web-server-1",
                            "job": "nginx",
                            "level": "info",
                            "namespace": "production",
                            "pod": "nginx-7b5c8d4f7-x2j9k",
                        },
                        "values": [
                            [
                                "1705320000000000000",
                                '10.244.1.15 - - [15/Jan/2024:12:00:00 +0000] "GET /api/health HTTP/1.1" 200 15 "-" "kube-probe/1.28"',
                            ],
                            [
                                "1705320001000000000",
                                '192.168.1.100 - user [15/Jan/2024:12:00:01 +0000] "POST /api/login HTTP/1.1" 200 256 "-" "Mozilla/5.0"',
                            ],
                        ],
                    }
                ],
            },
        }

        results = self.parser.parse(data)

        assert len(results) == 2

        # First entry
        assert results[0].event_type == EventType.HTTP
        assert results[0].severity == EventSeverity.INFO
        assert results[0].client_ip == "10.244.1.15"
        assert results[0].parsed_fields["namespace"] == "production"
        assert results[0].parsed_fields["pod"] == "nginx-7b5c8d4f7-x2j9k"
        assert "GET /api/health" in results[0].raw_message

        # Second entry
        assert results[1].client_ip == "192.168.1.100"
        assert "POST /api/login" in results[1].raw_message
