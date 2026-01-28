"""Tests for the AdGuard Home parser."""


from app.models.raw_event import EventSeverity, EventType
from app.parsers.adguard_parser import AdGuardParser


class TestAdGuardParser:
    """Tests for AdGuardParser."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = AdGuardParser()

    def test_parse_basic_query(self):
        """Test parsing a basic DNS query."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {
                "name": "example.com.",
                "type": "A",
            },
            "answer": [
                {"value": "93.184.216.34", "type": "A", "ttl": 300}
            ],
            "client": "192.168.1.100",
            "reason": "NotFilteredNotFound",
            "upstream": "https://dns.google/dns-query",
            "elapsedMs": 45,
            "cached": False,
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        result = results[0]
        assert result.event_type == EventType.DNS
        assert result.severity == EventSeverity.INFO
        assert result.client_ip == "192.168.1.100"
        assert result.domain == "example.com"
        assert result.target_ip == "93.184.216.34"
        assert result.port == 53
        assert result.protocol == "DNS"
        assert result.action == "allowed"

    def test_parse_blocked_query(self):
        """Test parsing a blocked DNS query."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "malware.com.", "type": "A"},
            "answer": [],
            "client": "192.168.1.100",
            "reason": "FilteredBlackList",
            "rules": [{"text": "||malware.com^", "filter_list_id": 1}],
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        result = results[0]
        assert result.severity == EventSeverity.WARNING
        assert result.action == "blocked"
        assert result.response_status == "blocked"

    def test_parse_safe_browsing_blocked(self):
        """Test parsing safe browsing blocked query."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "phishing.com.", "type": "A"},
            "answer": [],
            "client": "192.168.1.100",
            "reason": "FilteredSafeBrowsing",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING
        assert results[0].action == "blocked"

    def test_parse_parental_blocked(self):
        """Test parsing parental control blocked query."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "adult-site.com.", "type": "A"},
            "answer": [],
            "client": "192.168.1.100",
            "reason": "FilteredParental",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].action == "blocked"

    def test_parse_blocked_service(self):
        """Test parsing blocked service query."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "tiktok.com.", "type": "A"},
            "answer": [],
            "client": "192.168.1.100",
            "reason": "FilteredBlockedService",
            "serviceName": "tiktok",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].action == "blocked"
        assert results[0].parsed_fields["service_name"] == "tiktok"

    def test_parse_rewritten_query(self):
        """Test parsing rewritten DNS query."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "local-server.", "type": "A"},
            "answer": [{"value": "192.168.1.50", "type": "A"}],
            "client": "192.168.1.100",
            "reason": "Rewrite",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].action == "rewritten"
        assert results[0].response_status == "rewritten"

    def test_parse_safe_search_rewrite(self):
        """Test parsing safe search rewrite."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "www.google.com.", "type": "A"},
            "answer": [{"value": "216.239.38.120", "type": "A"}],
            "client": "192.168.1.100",
            "reason": "FilteredSafeSearch",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].action == "rewritten"
        assert results[0].severity == EventSeverity.INFO

    def test_parse_api_response_format(self):
        """Test parsing full API response format."""
        data = {
            "data": [
                {
                    "time": "2024-01-15T12:00:00Z",
                    "question": {"name": "example1.com.", "type": "A"},
                    "answer": [],
                    "client": "192.168.1.100",
                    "reason": "NotFilteredNotFound",
                },
                {
                    "time": "2024-01-15T12:00:01Z",
                    "question": {"name": "example2.com.", "type": "A"},
                    "answer": [],
                    "client": "192.168.1.101",
                    "reason": "NotFilteredNotFound",
                },
            ],
            "oldest": "2024-01-15T11:00:00Z",
        }

        results = self.parser.parse(data)

        assert len(results) == 2
        assert results[0].domain == "example1.com"
        assert results[1].domain == "example2.com"

    def test_parse_list_of_entries(self):
        """Test parsing list of entries directly."""
        data = [
            {
                "time": "2024-01-15T12:00:00Z",
                "question": {"name": "example.com.", "type": "A"},
                "answer": [],
                "client": "192.168.1.100",
                "reason": "NotFilteredNotFound",
            },
        ]

        results = self.parser.parse(data)

        assert len(results) == 1

    def test_parse_multiple_answers(self):
        """Test parsing query with multiple answer IPs."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "cdn.example.com.", "type": "A"},
            "answer": [
                {"value": "93.184.216.34", "type": "A"},
                {"value": "93.184.216.35", "type": "A"},
                {"value": "93.184.216.36", "type": "A"},
            ],
            "client": "192.168.1.100",
            "reason": "NotFilteredNotFound",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].target_ip == "93.184.216.34"  # First IP
        assert len(results[0].parsed_fields["answer_ips"]) == 3

    def test_parse_different_query_types(self):
        """Test parsing different DNS query types."""
        query_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]

        for qtype in query_types:
            data = [{
                "time": "2024-01-15T12:00:00Z",
                "question": {"name": "example.com.", "type": qtype},
                "answer": [],
                "client": "192.168.1.100",
                "reason": "NotFilteredNotFound",
            }]

            results = self.parser.parse(data)

            assert len(results) == 1
            assert results[0].parsed_fields["query_type"] == qtype

    def test_parse_cached_response(self):
        """Test parsing cached DNS response."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "example.com.", "type": "A"},
            "answer": [{"value": "93.184.216.34", "type": "A"}],
            "client": "192.168.1.100",
            "reason": "NotFilteredNotFound",
            "cached": True,
            "elapsedMs": 0,
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].parsed_fields["cached"] is True

    def test_parse_with_client_info(self):
        """Test parsing with client info."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "example.com.", "type": "A"},
            "answer": [],
            "client": "192.168.1.100",
            "reason": "NotFilteredNotFound",
            "client_info": {
                "name": "my-laptop",
                "ids": ["192.168.1.100"],
            },
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].parsed_fields["client_info"]["name"] == "my-laptop"

    def test_parse_empty_list(self):
        """Test parsing empty list."""
        results = self.parser.parse([])
        assert len(results) == 0

    def test_parse_empty_data_field(self):
        """Test parsing response with empty data field."""
        data = {"data": [], "oldest": "2024-01-15T12:00:00Z"}
        results = self.parser.parse(data)
        assert len(results) == 0

    def test_parse_invalid_data_type(self):
        """Test parsing invalid data type returns empty list."""
        results = self.parser.parse("invalid string")
        assert len(results) == 0

    def test_parse_non_dict_entries_skipped(self):
        """Test that non-dict entries are skipped."""
        data = [
            {
                "time": "2024-01-15T12:00:00Z",
                "question": {"name": "example.com.", "type": "A"},
                "answer": [],
                "client": "192.168.1.100",
                "reason": "NotFilteredNotFound",
            },
            "invalid entry",
            None,
        ]

        results = self.parser.parse(data)

        assert len(results) == 1

    def test_raw_message_format(self):
        """Test raw message format."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "example.com.", "type": "A"},
            "answer": [],
            "client": "192.168.1.100",
            "reason": "NotFilteredNotFound",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].raw_message == "192.168.1.100 -> example.com (A)"

    def test_domain_trailing_dot_removed(self):
        """Test that trailing dot is removed from domain."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "example.com.", "type": "A"},
            "answer": [],
            "client": "192.168.1.100",
            "reason": "NotFilteredNotFound",
        }]

        results = self.parser.parse(data)

        assert results[0].domain == "example.com"  # No trailing dot

    def test_parse_whitelisted_query(self):
        """Test parsing whitelisted query."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "allowed.com.", "type": "A"},
            "answer": [{"value": "1.2.3.4", "type": "A"}],
            "client": "192.168.1.100",
            "reason": "NotFilteredWhiteList",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].action == "allowed"

    def test_parse_error_response(self):
        """Test parsing error response."""
        data = [{
            "time": "2024-01-15T12:00:00Z",
            "question": {"name": "example.com.", "type": "A"},
            "answer": [],
            "client": "192.168.1.100",
            "reason": "NotFilteredError",
        }]

        results = self.parser.parse(data)

        assert len(results) == 1
        assert results[0].action == "error"
