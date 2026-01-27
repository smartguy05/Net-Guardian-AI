"""Tests for Authentik event log parser."""

import pytest
from datetime import datetime, timezone

from app.parsers.authentik_parser import AuthentikParser
from app.models.raw_event import EventSeverity, EventType


class TestAuthentikParser:
    """Tests for AuthentikParser class."""

    @pytest.fixture
    def parser(self):
        """Create AuthentikParser instance."""
        return AuthentikParser()

    def test_parse_login_event(self, parser):
        """Test parsing a successful login event."""
        event = {
            "pk": "event-123",
            "action": "login",
            "app": "authentik.events",
            "created": "2026-01-27T10:00:00Z",
            "user": {
                "pk": "user-456",
                "username": "testuser",
                "email": "test@example.com",
            },
            "context": {
                "http_request": {
                    "client_ip": "192.168.1.100",
                    "user_agent": "Mozilla/5.0",
                }
            },
        }

        results = parser.parse([event])

        assert len(results) == 1
        result = results[0]

        assert result.event_type == EventType.AUTH
        assert result.severity == EventSeverity.INFO
        assert result.client_ip == "192.168.1.100"
        assert "testuser logged in" in result.raw_message
        assert result.action == "success"
        assert result.parsed_fields["action"] == "login"
        assert result.parsed_fields["username"] == "testuser"

    def test_parse_login_failed_event(self, parser):
        """Test parsing a failed login event."""
        event = {
            "pk": "event-456",
            "action": "login_failed",
            "created": "2026-01-27T10:00:00Z",
            "user": {
                "username": "attacker",
            },
            "context": {
                "message": "invalid password",
                "http_request": {
                    "client_ip": "10.0.0.1",
                }
            },
        }

        results = parser.parse([event])

        assert len(results) == 1
        result = results[0]

        assert result.severity == EventSeverity.WARNING
        assert result.action == "blocked"
        assert "Login failed" in result.raw_message
        assert result.parsed_fields["is_security_event"] is True

    def test_parse_suspicious_request(self, parser):
        """Test parsing a suspicious request event."""
        event = {
            "action": "suspicious_request",
            "created": "2026-01-27T10:00:00Z",
            "user": {"username": "hacker"},
            "context": {
                "http_request": {"client_ip": "203.0.113.1"},
            },
        }

        results = parser.parse([event])

        assert len(results) == 1
        result = results[0]

        assert result.severity == EventSeverity.ERROR
        assert result.parsed_fields["is_security_event"] is True

    def test_parse_impersonation_event(self, parser):
        """Test parsing impersonation started event."""
        event = {
            "action": "impersonation_started",
            "created": "2026-01-27T10:00:00Z",
            "user": {"username": "admin"},
            "context": {
                "user": {"username": "targetuser"},
                "http_request": {"client_ip": "192.168.1.1"},
            },
        }

        results = parser.parse([event])

        assert len(results) == 1
        result = results[0]

        assert result.severity == EventSeverity.WARNING
        assert "impersonating" in result.raw_message.lower()
        assert result.parsed_fields["is_security_event"] is True

    def test_parse_authorize_application(self, parser):
        """Test parsing application authorization event."""
        event = {
            "action": "authorize_application",
            "created": "2026-01-27T10:00:00Z",
            "user": {"username": "user1"},
            "context": {
                "authorized_application": {
                    "name": "NetGuardian AI",
                },
                "http_request": {"client_ip": "192.168.1.50"},
            },
        }

        results = parser.parse([event])

        assert len(results) == 1
        result = results[0]

        assert result.severity == EventSeverity.INFO
        assert "NetGuardian AI" in result.raw_message

    def test_parse_paginated_response(self, parser):
        """Test parsing paginated API response format."""
        data = {
            "pagination": {
                "count": 2,
                "next": None,
                "previous": None,
            },
            "results": [
                {
                    "action": "login",
                    "created": "2026-01-27T10:00:00Z",
                    "user": {"username": "user1"},
                    "context": {},
                },
                {
                    "action": "logout",
                    "created": "2026-01-27T10:01:00Z",
                    "user": {"username": "user2"},
                    "context": {},
                },
            ],
        }

        results = parser.parse(data)

        assert len(results) == 2
        assert results[0].parsed_fields["action"] == "login"
        assert results[1].parsed_fields["action"] == "logout"

    def test_parse_direct_list(self, parser):
        """Test parsing direct list of events."""
        events = [
            {
                "action": "login",
                "created": "2026-01-27T10:00:00Z",
                "user": {"username": "user1"},
                "context": {},
            },
        ]

        results = parser.parse(events)

        assert len(results) == 1

    def test_parse_empty_list(self, parser):
        """Test parsing empty event list."""
        results = parser.parse([])
        assert len(results) == 0

    def test_parse_invalid_data(self, parser):
        """Test parsing invalid data returns empty list."""
        results = parser.parse("not a list or dict")
        assert len(results) == 0

    def test_parse_timestamp_formats(self, parser):
        """Test parsing different timestamp formats."""
        events = [
            {
                "action": "login",
                "created": "2026-01-27T10:00:00Z",
                "user": {"username": "user1"},
                "context": {},
            },
            {
                "action": "logout",
                "created": "2026-01-27T10:00:00+00:00",
                "user": {"username": "user2"},
                "context": {},
            },
        ]

        results = parser.parse(events)

        assert len(results) == 2
        assert results[0].timestamp.tzinfo is not None
        assert results[1].timestamp.tzinfo is not None

    def test_extract_client_ip_from_http_request(self, parser):
        """Test extracting client IP from http_request context."""
        event = {
            "action": "login",
            "created": "2026-01-27T10:00:00Z",
            "user": {"username": "user1"},
            "context": {
                "http_request": {"client_ip": "10.0.0.1"},
            },
        }

        results = parser.parse([event])

        assert results[0].client_ip == "10.0.0.1"

    def test_extract_client_ip_from_geo(self, parser):
        """Test extracting client IP from geo context."""
        event = {
            "action": "login",
            "created": "2026-01-27T10:00:00Z",
            "user": {"username": "user1"},
            "context": {
                "geo": {"ip": "203.0.113.1", "country": "US"},
            },
        }

        results = parser.parse([event])

        assert results[0].client_ip == "203.0.113.1"
        assert results[0].parsed_fields.get("geo") == {"ip": "203.0.113.1", "country": "US"}

    def test_skip_non_dict_entries(self, parser):
        """Test that non-dict entries are skipped."""
        events = [
            {"action": "login", "created": "2026-01-27T10:00:00Z", "user": {"username": "user1"}, "context": {}},
            "not a dict",
            None,
            123,
            {"action": "logout", "created": "2026-01-27T10:01:00Z", "user": {"username": "user2"}, "context": {}},
        ]

        results = parser.parse(events)

        assert len(results) == 2

    def test_handle_missing_user(self, parser):
        """Test handling events without user info."""
        event = {
            "action": "system_task_exception",
            "created": "2026-01-27T10:00:00Z",
            "context": {
                "message": "Task failed",
            },
        }

        results = parser.parse([event])

        assert len(results) == 1
        assert "system" in results[0].raw_message.lower()

    def test_model_events(self, parser):
        """Test parsing model CRUD events."""
        event = {
            "action": "model_created",
            "created": "2026-01-27T10:00:00Z",
            "user": {"username": "admin"},
            "context": {
                "model": {
                    "app": "authentik_core",
                    "model_name": "User",
                },
            },
        }

        results = parser.parse([event])

        assert len(results) == 1
        assert results[0].severity == EventSeverity.INFO
        assert "Model Created" in results[0].raw_message

    def test_policy_exception_event(self, parser):
        """Test parsing policy exception event."""
        event = {
            "action": "policy_exception",
            "created": "2026-01-27T10:00:00Z",
            "user": {"username": "user1"},
            "context": {
                "expression": "ak_is_sso_flow",
                "message": "Policy evaluation failed",
            },
        }

        results = parser.parse([event])

        assert len(results) == 1
        assert results[0].severity == EventSeverity.WARNING
        assert "policy exception" in results[0].raw_message.lower()
