"""Tests for the log query service."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.raw_event import EventSeverity, EventType, RawEvent
from app.services.log_query_service import (
    LogQueryParameters,
    LogQueryResult,
    LogQueryService,
)


# Sample device list for testing
SAMPLE_DEVICES = [
    {
        "id": "11111111-1111-1111-1111-111111111111",
        "hostname": "ring-doorbell",
        "device_type": "iot",
        "ip_addresses": ["192.168.1.50"],
        "mac_address": "AA:BB:CC:DD:EE:01",
        "manufacturer": "Ring",
        "profile_tags": ["camera", "outdoor"],
    },
    {
        "id": "22222222-2222-2222-2222-222222222222",
        "hostname": "desktop-pc",
        "device_type": "pc",
        "ip_addresses": ["192.168.1.100"],
        "mac_address": "AA:BB:CC:DD:EE:02",
        "manufacturer": "Dell",
        "profile_tags": ["workstation"],
    },
    {
        "id": "33333333-3333-3333-3333-333333333333",
        "hostname": "nas-server",
        "device_type": "server",
        "ip_addresses": ["192.168.1.10"],
        "mac_address": "AA:BB:CC:DD:EE:03",
        "manufacturer": "Synology",
        "profile_tags": ["storage", "backup"],
    },
]


class TestHeuristicExtract:
    """Tests for the _heuristic_extract method."""

    def setup_method(self) -> None:
        self.service = LogQueryService()

    def test_extract_dns_event_type(self):
        """Should detect DNS event type from message."""
        params = self.service._heuristic_extract("Show me DNS queries", SAMPLE_DEVICES)
        assert EventType.DNS in params.event_types

    def test_extract_firewall_event_type(self):
        """Should detect firewall event type from message."""
        params = self.service._heuristic_extract(
            "Show me firewall blocks", SAMPLE_DEVICES
        )
        assert EventType.FIREWALL in params.event_types

    def test_extract_auth_event_type(self):
        """Should detect auth event type from 'login' keyword."""
        params = self.service._heuristic_extract(
            "Show me login failures", SAMPLE_DEVICES
        )
        assert EventType.AUTH in params.event_types

    def test_extract_container_event_type(self):
        """Should detect container event type from 'docker' keyword."""
        params = self.service._heuristic_extract(
            "Show me docker container logs", SAMPLE_DEVICES
        )
        assert EventType.CONTAINER in params.event_types

    def test_extract_multiple_event_types(self):
        """Should detect multiple event types if mentioned."""
        params = self.service._heuristic_extract(
            "Show me DNS and firewall events", SAMPLE_DEVICES
        )
        assert EventType.DNS in params.event_types
        assert EventType.FIREWALL in params.event_types

    def test_extract_ip_address(self):
        """Should extract IP addresses from message."""
        params = self.service._heuristic_extract(
            "Show events from 192.168.1.50", SAMPLE_DEVICES
        )
        assert params.client_ip == "192.168.1.50"

    def test_extract_two_ip_addresses(self):
        """Should extract source and target IPs."""
        params = self.service._heuristic_extract(
            "Traffic from 192.168.1.50 to 10.0.0.1", SAMPLE_DEVICES
        )
        assert params.client_ip == "192.168.1.50"
        assert params.target_ip == "10.0.0.1"

    def test_extract_domain(self):
        """Should extract domain-like strings."""
        params = self.service._heuristic_extract(
            "DNS queries to ring.amazon.com", SAMPLE_DEVICES
        )
        assert params.domain_contains == "ring.amazon.com"

    def test_extract_time_range_last_hour(self):
        """Should detect 'last hour' time expression."""
        params = self.service._heuristic_extract(
            "Show events in the last hour", SAMPLE_DEVICES
        )
        assert params.time_range_hours == 1

    def test_extract_time_range_today(self):
        """Should detect 'today' time expression."""
        params = self.service._heuristic_extract(
            "Show DNS events today", SAMPLE_DEVICES
        )
        assert params.time_range_hours == 24

    def test_extract_time_range_this_week(self):
        """Should detect 'this week' time expression."""
        params = self.service._heuristic_extract(
            "Show events this week", SAMPLE_DEVICES
        )
        assert params.time_range_hours == 168

    def test_extract_time_range_yesterday(self):
        """Should detect 'yesterday' time expression."""
        params = self.service._heuristic_extract(
            "What happened yesterday", SAMPLE_DEVICES
        )
        assert params.time_range_hours == 48

    def test_default_time_range(self):
        """Should default to 24 hours if no time expression."""
        params = self.service._heuristic_extract(
            "Show me DNS events", SAMPLE_DEVICES
        )
        assert params.time_range_hours == 24

    def test_extract_blocked_action(self):
        """Should detect 'blocked' and set blocked_only flag."""
        params = self.service._heuristic_extract(
            "Show me blocked requests", SAMPLE_DEVICES
        )
        assert params.action == "block"
        assert params.blocked_only is True

    def test_extract_denied_action(self):
        """Should detect 'denied' and set blocked_only flag."""
        params = self.service._heuristic_extract(
            "Show me denied connections", SAMPLE_DEVICES
        )
        assert params.action == "block"
        assert params.blocked_only is True

    def test_extract_allowed_action(self):
        """Should detect 'allowed' action."""
        params = self.service._heuristic_extract(
            "Show me allowed traffic", SAMPLE_DEVICES
        )
        assert params.action == "allow"
        assert params.blocked_only is False

    def test_extract_severity_error(self):
        """Should detect error severity keyword."""
        params = self.service._heuristic_extract(
            "Show me error events", SAMPLE_DEVICES
        )
        assert params.severity_min == EventSeverity.ERROR

    def test_extract_severity_critical(self):
        """Should detect critical severity keyword."""
        params = self.service._heuristic_extract(
            "Are there any critical events?", SAMPLE_DEVICES
        )
        assert params.severity_min == EventSeverity.CRITICAL

    def test_extract_severity_warning(self):
        """Should detect warning severity keyword."""
        params = self.service._heuristic_extract(
            "Show me warnings", SAMPLE_DEVICES
        )
        assert params.severity_min == EventSeverity.WARNING

    def test_extract_device_by_hostname(self):
        """Should match device by hostname."""
        params = self.service._heuristic_extract(
            "What has ring-doorbell been doing?", SAMPLE_DEVICES
        )
        assert params.device_name == "ring-doorbell"
        assert params.device_id == UUID("11111111-1111-1111-1111-111111111111")

    def test_extract_device_by_type(self):
        """Should match device by device_type when hostname not found."""
        devices = [
            {
                "id": "44444444-4444-4444-4444-444444444444",
                "hostname": "my-nas",
                "device_type": "server",
                "ip_addresses": [],
                "mac_address": "AA:BB:CC:DD:EE:04",
            },
        ]
        params = self.service._heuristic_extract(
            "Show me events from the server", devices
        )
        assert params.device_name == "my-nas"

    def test_no_device_match(self):
        """Should leave device_name as None if no match."""
        params = self.service._heuristic_extract(
            "Show me all DNS queries", SAMPLE_DEVICES
        )
        assert params.device_name is None
        assert params.device_id is None

    def test_complex_message(self):
        """Should extract multiple parameters from a complex message."""
        params = self.service._heuristic_extract(
            "Show me blocked DNS queries from ring-doorbell in the last hour",
            SAMPLE_DEVICES,
        )
        assert EventType.DNS in params.event_types
        assert params.blocked_only is True
        assert params.device_name == "ring-doorbell"
        assert params.time_range_hours == 1


class TestResolveDevice:
    """Tests for the _resolve_device static method."""

    def test_resolve_by_exact_hostname(self):
        """Should resolve by exact hostname match."""
        result = LogQueryService._resolve_device("ring-doorbell", SAMPLE_DEVICES)
        assert result == UUID("11111111-1111-1111-1111-111111111111")

    def test_resolve_by_partial_hostname(self):
        """Should resolve by partial hostname match."""
        result = LogQueryService._resolve_device("ring", SAMPLE_DEVICES)
        assert result == UUID("11111111-1111-1111-1111-111111111111")

    def test_resolve_case_insensitive(self):
        """Should resolve case-insensitively."""
        result = LogQueryService._resolve_device("Ring-Doorbell", SAMPLE_DEVICES)
        assert result == UUID("11111111-1111-1111-1111-111111111111")

    def test_resolve_by_manufacturer(self):
        """Should resolve by manufacturer name."""
        result = LogQueryService._resolve_device("Dell", SAMPLE_DEVICES)
        assert result == UUID("22222222-2222-2222-2222-222222222222")

    def test_resolve_by_device_type(self):
        """Should resolve by device_type."""
        result = LogQueryService._resolve_device("iot", SAMPLE_DEVICES)
        assert result == UUID("11111111-1111-1111-1111-111111111111")

    def test_resolve_by_profile_tag(self):
        """Should resolve by profile tag."""
        result = LogQueryService._resolve_device("camera", SAMPLE_DEVICES)
        assert result == UUID("11111111-1111-1111-1111-111111111111")

    def test_resolve_no_match(self):
        """Should return None if no device matches."""
        result = LogQueryService._resolve_device("nonexistent", SAMPLE_DEVICES)
        assert result is None

    def test_resolve_empty_devices(self):
        """Should return None for empty device list."""
        result = LogQueryService._resolve_device("ring", [])
        assert result is None

    def test_resolve_by_storage_tag(self):
        """Should resolve by storage profile tag."""
        result = LogQueryService._resolve_device("storage", SAMPLE_DEVICES)
        assert result == UUID("33333333-3333-3333-3333-333333333333")


class TestQueryEvents:
    """Tests for the query_events method."""

    @pytest.fixture
    def service(self) -> LogQueryService:
        return LogQueryService()

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        return AsyncMock(spec=AsyncSession)

    @pytest.mark.asyncio
    async def test_query_with_device_filter(self, service, mock_session):
        """Should include device_id filter in query."""
        device_id = uuid4()
        params = LogQueryParameters(device_id=device_id)

        # Mock count result
        count_result = MagicMock()
        count_result.scalar.return_value = 0

        # Mock events result
        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params)

        assert result.total_matching == 0
        assert result.events == []
        assert mock_session.execute.call_count == 2

    @pytest.mark.asyncio
    async def test_query_with_event_type_filter(self, service, mock_session):
        """Should filter by event types."""
        params = LogQueryParameters(event_types=[EventType.DNS])

        count_result = MagicMock()
        count_result.scalar.return_value = 5

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params)

        assert result.total_matching == 5

    @pytest.mark.asyncio
    async def test_query_with_time_range(self, service, mock_session):
        """Should filter by time range."""
        params = LogQueryParameters(time_range_hours=1)

        count_result = MagicMock()
        count_result.scalar.return_value = 10

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params)

        assert result.total_matching == 10

    @pytest.mark.asyncio
    async def test_query_with_domain_filter(self, service, mock_session):
        """Should filter by domain contains."""
        params = LogQueryParameters(domain_contains="ring.com")

        count_result = MagicMock()
        count_result.scalar.return_value = 3

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params)

        assert result.total_matching == 3

    @pytest.mark.asyncio
    async def test_query_respects_limit(self, service, mock_session):
        """Should pass limit to query."""
        params = LogQueryParameters()

        count_result = MagicMock()
        count_result.scalar.return_value = 100

        # Create mock events
        mock_events = []
        for i in range(10):
            event = MagicMock(spec=RawEvent)
            event.timestamp = datetime.now(UTC) - timedelta(minutes=i)
            event.event_type = EventType.DNS
            event.severity = EventSeverity.INFO
            event.client_ip = "192.168.1.50"
            event.domain = f"test{i}.com"
            event.target_ip = None
            event.action = "allowed"
            event.query_type = "A"
            event.response_status = "success"
            event.blocked_reason = None
            event.port = None
            event.protocol = None
            event.parsed_fields = {}
            mock_events.append(event)

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = mock_events

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params, limit=10)

        assert result.total_matching == 100
        assert len(result.events) == 10

    @pytest.mark.asyncio
    async def test_query_empty_results(self, service, mock_session):
        """Should handle empty results gracefully."""
        params = LogQueryParameters(
            device_id=uuid4(),
            event_types=[EventType.FIREWALL],
        )

        count_result = MagicMock()
        count_result.scalar.return_value = 0

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params)

        assert result.total_matching == 0
        assert result.events == []

    @pytest.mark.asyncio
    async def test_query_event_formatting(self, service, mock_session):
        """Should format events as compact dicts."""
        params = LogQueryParameters()

        count_result = MagicMock()
        count_result.scalar.return_value = 1

        event = MagicMock(spec=RawEvent)
        event.timestamp = datetime(2026, 2, 18, 10, 30, tzinfo=UTC)
        event.event_type = EventType.DNS
        event.severity = EventSeverity.INFO
        event.client_ip = "192.168.1.50"
        event.domain = "ring.com"
        event.target_ip = None
        event.action = "allowed"
        event.query_type = "A"
        event.response_status = "success"
        event.blocked_reason = None
        event.port = None
        event.protocol = None
        event.parsed_fields = {}

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = [event]

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params)

        assert len(result.events) == 1
        e = result.events[0]
        assert e["timestamp"] == "02-18 10:30"
        assert e["type"] == "dns"
        assert e["severity"] == "info"
        assert e["source_ip"] == "192.168.1.50"
        assert e["domain"] == "ring.com"
        assert e["action"] == "allowed"
        assert "A" in e["details"]

    @pytest.mark.asyncio
    async def test_query_severity_filter(self, service, mock_session):
        """Should filter by minimum severity."""
        params = LogQueryParameters(severity_min=EventSeverity.WARNING)

        count_result = MagicMock()
        count_result.scalar.return_value = 2

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params)

        assert result.total_matching == 2

    @pytest.mark.asyncio
    async def test_query_blocked_only(self, service, mock_session):
        """Should filter for blocked-only events."""
        params = LogQueryParameters(blocked_only=True)

        count_result = MagicMock()
        count_result.scalar.return_value = 5

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[count_result, events_result])

        result = await service.query_events(mock_session, params)

        assert result.total_matching == 5


class TestFormatEventsForContext:
    """Tests for the format_events_for_context static method."""

    def test_format_with_events(self):
        """Should produce a markdown table with events."""
        result = LogQueryResult(
            events=[
                {
                    "timestamp": "02-18 10:30",
                    "type": "dns",
                    "severity": "info",
                    "source_ip": "192.168.1.50",
                    "domain": "ring.com",
                    "action": "allowed",
                    "details": "A, success",
                },
                {
                    "timestamp": "02-18 10:31",
                    "type": "dns",
                    "severity": "info",
                    "source_ip": "192.168.1.50",
                    "domain": "amazonaws.com",
                    "action": "allowed",
                    "details": "A",
                },
            ],
            total_matching=1234,
            query_params=LogQueryParameters(
                event_types=[EventType.DNS],
                device_name="ring-doorbell",
                time_range_hours=24,
            ),
            query_description='DNS events from "ring-doorbell" in the last 24 hours',
        )

        output = LogQueryService.format_events_for_context(result)

        assert "## Log Query Results" in output
        assert "Showing 2 of 1,234 matching events" in output
        assert "ring-doorbell" in output
        assert "| 02-18 10:30 |" in output
        assert "ring.com" in output
        assert "amazonaws.com" in output
        assert "| Time (UTC) |" in output

    def test_format_empty_results(self):
        """Should show helpful message for empty results."""
        result = LogQueryResult(
            events=[],
            total_matching=0,
            query_params=LogQueryParameters(
                event_types=[EventType.FIREWALL],
                time_range_hours=1,
            ),
            query_description="FIREWALL events in the last 1 hours",
        )

        output = LogQueryService.format_events_for_context(result)

        assert "## Log Query Results" in output
        assert "No events found" in output
        assert "broadening the search" in output

    def test_format_shows_count_info(self):
        """Should show total count when more events exist than shown."""
        result = LogQueryResult(
            events=[
                {
                    "timestamp": "02-18 10:30",
                    "type": "dns",
                    "severity": "info",
                }
            ],
            total_matching=500,
            query_params=LogQueryParameters(),
            query_description="All events in the last 24 hours",
        )

        output = LogQueryService.format_events_for_context(result)

        assert "Showing 1 of 500 matching events" in output


class TestExtractDetails:
    """Tests for the _extract_details static method."""

    def test_dns_details(self):
        """Should extract DNS-specific details."""
        event = MagicMock(spec=RawEvent)
        event.event_type = EventType.DNS
        event.query_type = "A"
        event.response_status = "blocked"
        event.blocked_reason = "ads"
        event.port = None
        event.protocol = None
        event.parsed_fields = {}

        details = LogQueryService._extract_details(event)

        assert "A" in details
        assert "blocked" in details
        assert "ads" in details

    def test_firewall_details(self):
        """Should extract firewall-specific details."""
        event = MagicMock(spec=RawEvent)
        event.event_type = EventType.FIREWALL
        event.port = 443
        event.protocol = "TCP"
        event.query_type = None
        event.response_status = None
        event.blocked_reason = None
        event.parsed_fields = {}

        details = LogQueryService._extract_details(event)

        assert "port 443" in details
        assert "TCP" in details

    def test_auth_details(self):
        """Should extract auth-specific details."""
        event = MagicMock(spec=RawEvent)
        event.event_type = EventType.AUTH
        event.parsed_fields = {"username": "admin"}
        event.query_type = None
        event.response_status = None
        event.blocked_reason = None
        event.port = None
        event.protocol = None

        details = LogQueryService._extract_details(event)

        assert "user: admin" in details

    def test_container_details(self):
        """Should extract container-specific details."""
        event = MagicMock(spec=RawEvent)
        event.event_type = EventType.CONTAINER
        event.parsed_fields = {
            "container_name": "nginx",
            "exception_type": "OOMKilled",
        }
        event.query_type = None
        event.response_status = None
        event.blocked_reason = None
        event.port = None
        event.protocol = None

        details = LogQueryService._extract_details(event)

        assert "nginx" in details
        assert "OOMKilled" in details

    def test_empty_details(self):
        """Should return empty string for events without details."""
        event = MagicMock(spec=RawEvent)
        event.event_type = EventType.SYSTEM
        event.query_type = None
        event.response_status = None
        event.blocked_reason = None
        event.port = None
        event.protocol = None
        event.parsed_fields = {}

        details = LogQueryService._extract_details(event)

        assert details == ""


class TestBuildQueryDescription:
    """Tests for the _build_query_description static method."""

    def test_description_with_event_types(self):
        """Should include event types in description."""
        params = LogQueryParameters(event_types=[EventType.DNS])
        desc = LogQueryService._build_query_description(params)
        assert "DNS events" in desc

    def test_description_with_device(self):
        """Should include device name in description."""
        params = LogQueryParameters(device_name="ring-doorbell")
        desc = LogQueryService._build_query_description(params)
        assert '"ring-doorbell"' in desc

    def test_description_with_time_range(self):
        """Should include time range in description."""
        params = LogQueryParameters(time_range_hours=1)
        desc = LogQueryService._build_query_description(params)
        assert "last 1 hours" in desc

    def test_description_with_severity(self):
        """Should include severity in description."""
        params = LogQueryParameters(severity_min=EventSeverity.ERROR)
        desc = LogQueryService._build_query_description(params)
        assert "severity >= error" in desc

    def test_description_with_domain(self):
        """Should include domain in description."""
        params = LogQueryParameters(domain_contains="ring.com")
        desc = LogQueryService._build_query_description(params)
        assert "ring.com" in desc

    def test_description_with_blocked_only(self):
        """Should indicate blocked only in description."""
        params = LogQueryParameters(blocked_only=True)
        desc = LogQueryService._build_query_description(params)
        assert "blocked only" in desc

    def test_description_no_event_types(self):
        """Should say 'All events' when no event types specified."""
        params = LogQueryParameters()
        desc = LogQueryService._build_query_description(params)
        assert "All events" in desc

    def test_description_with_client_ip(self):
        """Should include client IP in description."""
        params = LogQueryParameters(client_ip="192.168.1.50")
        desc = LogQueryService._build_query_description(params)
        assert "192.168.1.50" in desc

    def test_description_with_multiple_types(self):
        """Should include multiple event types."""
        params = LogQueryParameters(event_types=[EventType.DNS, EventType.FIREWALL])
        desc = LogQueryService._build_query_description(params)
        assert "DNS" in desc
        assert "FIREWALL" in desc


class TestExtractQueryParameters:
    """Tests for the LLM-based extract_query_parameters method."""

    @pytest.mark.asyncio
    async def test_falls_back_to_heuristic_without_api_key(self):
        """Should use heuristic when no API key."""
        service = LogQueryService()

        with patch("app.services.log_query_service.settings") as mock_settings:
            mock_settings.anthropic_api_key = ""
            params = await service.extract_query_parameters(
                "Show me DNS queries from ring-doorbell", SAMPLE_DEVICES
            )

        assert EventType.DNS in params.event_types
        assert params.device_name == "ring-doorbell"

    @pytest.mark.asyncio
    async def test_falls_back_on_llm_error(self):
        """Should fall back to heuristic when LLM call fails."""
        service = LogQueryService()
        service._client = MagicMock()
        service._client.messages.create = AsyncMock(
            side_effect=Exception("API error")
        )

        with patch("app.services.log_query_service.settings") as mock_settings:
            mock_settings.anthropic_api_key = "test-key"
            mock_settings.llm_model_fast = "claude-3-5-haiku-latest"
            params = await service.extract_query_parameters(
                "Show me DNS queries", SAMPLE_DEVICES
            )

        assert EventType.DNS in params.event_types

    @pytest.mark.asyncio
    async def test_llm_extraction_success(self):
        """Should parse LLM response into parameters."""
        service = LogQueryService()
        service._client = MagicMock()

        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(
                text='{"event_types": ["dns"], "device_name": "ring-doorbell", "time_range_hours": 1}'
            )
        ]
        service._client.messages.create = AsyncMock(return_value=mock_response)

        with patch("app.services.log_query_service.settings") as mock_settings:
            mock_settings.anthropic_api_key = "test-key"
            mock_settings.llm_model_fast = "claude-3-5-haiku-latest"
            params = await service.extract_query_parameters(
                "Show me DNS queries from ring-doorbell in the last hour",
                SAMPLE_DEVICES,
            )

        assert EventType.DNS in params.event_types
        assert params.device_name == "ring-doorbell"
        assert params.device_id == UUID("11111111-1111-1111-1111-111111111111")
        assert params.time_range_hours == 1

    @pytest.mark.asyncio
    async def test_llm_extraction_with_conversation_context(self):
        """Should pass conversation context to LLM."""
        service = LogQueryService()
        service._client = MagicMock()

        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(text='{"blocked_only": true, "event_types": ["dns"]}')
        ]
        service._client.messages.create = AsyncMock(return_value=mock_response)

        with patch("app.services.log_query_service.settings") as mock_settings:
            mock_settings.anthropic_api_key = "test-key"
            mock_settings.llm_model_fast = "claude-3-5-haiku-latest"

            conversation = [
                {"role": "user", "content": "Show me DNS queries from ring-doorbell"},
                {"role": "assistant", "content": "Here are the DNS queries..."},
                {"role": "user", "content": "Were any of those blocked?"},
            ]

            params = await service.extract_query_parameters(
                "Were any of those blocked?",
                SAMPLE_DEVICES,
                conversation_context=conversation,
            )

        assert params.blocked_only is True
        # Verify conversation context was included in prompt
        call_args = service._client.messages.create.call_args
        prompt_content = call_args.kwargs["messages"][0]["content"]
        assert "Recent conversation" in prompt_content

    @pytest.mark.asyncio
    async def test_llm_handles_markdown_code_block(self):
        """Should handle LLM responses wrapped in markdown code blocks."""
        service = LogQueryService()
        service._client = MagicMock()

        mock_response = MagicMock()
        mock_response.content = [
            MagicMock(
                text='```json\n{"event_types": ["firewall"], "blocked_only": true}\n```'
            )
        ]
        service._client.messages.create = AsyncMock(return_value=mock_response)

        with patch("app.services.log_query_service.settings") as mock_settings:
            mock_settings.anthropic_api_key = "test-key"
            mock_settings.llm_model_fast = "claude-3-5-haiku-latest"
            params = await service.extract_query_parameters(
                "Show me firewall blocks", SAMPLE_DEVICES
            )

        assert EventType.FIREWALL in params.event_types
        assert params.blocked_only is True


class TestLogQueryParametersDataclass:
    """Tests for the LogQueryParameters dataclass."""

    def test_defaults(self):
        """Should have sensible defaults."""
        params = LogQueryParameters()
        assert params.device_name is None
        assert params.device_id is None
        assert params.event_types == []
        assert params.severity_min is None
        assert params.domain_contains is None
        assert params.client_ip is None
        assert params.target_ip is None
        assert params.action is None
        assert params.time_range_hours == 24
        assert params.keywords == []
        assert params.blocked_only is False


class TestLogQueryResultDataclass:
    """Tests for the LogQueryResult dataclass."""

    def test_creation(self):
        """Should create with required fields."""
        result = LogQueryResult(
            events=[{"timestamp": "02-18 10:30", "type": "dns"}],
            total_matching=1,
            query_params=LogQueryParameters(),
            query_description="test query",
        )
        assert len(result.events) == 1
        assert result.total_matching == 1
        assert result.query_description == "test query"
