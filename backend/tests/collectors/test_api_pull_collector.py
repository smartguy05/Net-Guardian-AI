"""Tests for the API pull collector."""

import asyncio
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from app.collectors.api_pull_collector import ApiPullCollector
from app.models.log_source import LogSource, SourceType
from app.parsers.json_parser import JsonParser


def create_mock_source(config: dict = None, parser_config: dict = None) -> MagicMock:
    """Create a mock LogSource for testing."""
    source = MagicMock(spec=LogSource)
    source.id = "test-source"
    source.name = "Test Source"
    source.source_type = SourceType.API_PULL
    source.config = config or {
        "url": "https://api.example.com",
        "endpoint": "/events",
        "auth_type": "none",
        "poll_interval_seconds": 30,
    }
    source.parser_type = "json"
    source.parser_config = parser_config or {}
    return source


class TestApiPullCollectorInit:
    """Tests for ApiPullCollector initialization."""

    def test_init_basic(self):
        """Test basic collector initialization."""
        source = create_mock_source()
        parser = JsonParser()

        collector = ApiPullCollector(source, parser)

        assert collector.source_id == "test-source"
        assert collector.parser == parser
        assert not collector.is_running()

    def test_source_id_property(self):
        """Test source_id property."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        assert collector.source_id == source.id

    def test_config_property(self):
        """Test config property."""
        config = {"url": "https://test.com", "endpoint": "/api"}
        source = create_mock_source(config=config)
        collector = ApiPullCollector(source, JsonParser())

        assert collector.config == config


class TestApiPullCollectorUrlBuilding:
    """Tests for URL building logic."""

    def test_build_url_with_endpoint(self):
        """Test URL building with endpoint."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "endpoint": "/v1/events",
        })
        collector = ApiPullCollector(source, JsonParser())

        url = collector._build_url()

        assert url == "https://api.example.com/v1/events"

    def test_build_url_without_endpoint(self):
        """Test URL building without endpoint."""
        source = create_mock_source(config={
            "url": "https://api.example.com/events",
            "endpoint": "",
        })
        collector = ApiPullCollector(source, JsonParser())

        url = collector._build_url()

        assert url == "https://api.example.com/events"

    def test_build_url_strips_trailing_slash(self):
        """Test that trailing slashes are handled."""
        source = create_mock_source(config={
            "url": "https://api.example.com/",
            "endpoint": "/events",
        })
        collector = ApiPullCollector(source, JsonParser())

        url = collector._build_url()

        assert url == "https://api.example.com/events"


class TestApiPullCollectorHeaders:
    """Tests for header building logic."""

    def test_build_headers_no_auth(self):
        """Test header building with no auth."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "auth_type": "none",
        })
        collector = ApiPullCollector(source, JsonParser())

        headers = collector._build_headers()

        assert "Authorization" not in headers

    def test_build_headers_bearer_auth(self):
        """Test header building with bearer auth."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "auth_type": "bearer",
            "api_key": "my-secret-token",
        })
        collector = ApiPullCollector(source, JsonParser())

        headers = collector._build_headers()

        assert headers["Authorization"] == "Bearer my-secret-token"

    def test_build_headers_api_key(self):
        """Test header building with API key auth."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "auth_type": "api_key",
            "api_key": "my-api-key",
            "api_key_header": "X-Custom-Key",
        })
        collector = ApiPullCollector(source, JsonParser())

        headers = collector._build_headers()

        assert headers["X-Custom-Key"] == "my-api-key"

    def test_build_headers_custom_headers(self):
        """Test header building with custom headers."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "auth_type": "none",
            "headers": {
                "X-Custom-Header": "value",
                "Accept": "application/json",
            },
        })
        collector = ApiPullCollector(source, JsonParser())

        headers = collector._build_headers()

        assert headers["X-Custom-Header"] == "value"
        assert headers["Accept"] == "application/json"


class TestApiPullCollectorBasicAuth:
    """Tests for basic auth building."""

    def test_build_auth_basic(self):
        """Test basic auth tuple building."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "auth_type": "basic",
            "username": "user",
            "password": "pass",
        })
        collector = ApiPullCollector(source, JsonParser())

        auth = collector._build_auth()

        assert auth == ("user", "pass")

    def test_build_auth_no_basic(self):
        """Test that non-basic auth returns None."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "auth_type": "bearer",
        })
        collector = ApiPullCollector(source, JsonParser())

        auth = collector._build_auth()

        assert auth is None


class TestApiPullCollectorParams:
    """Tests for query parameter building."""

    def test_build_params_basic(self):
        """Test basic query params."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "query_params": {"limit": 100, "format": "json"},
        })
        collector = ApiPullCollector(source, JsonParser())

        params = collector._build_params()

        assert params["limit"] == 100
        assert params["format"] == "json"

    def test_build_params_with_cursor_pagination(self):
        """Test params with cursor pagination."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "pagination": {
                "type": "cursor",
                "cursor_param": "cursor",
            },
        })
        collector = ApiPullCollector(source, JsonParser())
        collector._last_cursor = "abc123"

        params = collector._build_params()

        assert params["cursor"] == "abc123"

    def test_build_params_without_cursor(self):
        """Test params with cursor pagination but no cursor yet."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "pagination": {
                "type": "cursor",
                "cursor_param": "cursor",
            },
        })
        collector = ApiPullCollector(source, JsonParser())

        params = collector._build_params()

        assert "cursor" not in params


class TestApiPullCollectorPagination:
    """Tests for pagination cursor extraction."""

    def test_extract_cursor_simple(self):
        """Test simple cursor extraction."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "pagination": {
                "type": "cursor",
                "cursor_field": "next_cursor",
            },
        })
        collector = ApiPullCollector(source, JsonParser())

        cursor = collector._extract_pagination_cursor({
            "data": [],
            "next_cursor": "xyz789",
        })

        assert cursor == "xyz789"

    def test_extract_cursor_nested(self):
        """Test nested cursor extraction."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "pagination": {
                "type": "cursor",
                "cursor_field": "meta.pagination.next",
            },
        })
        collector = ApiPullCollector(source, JsonParser())

        cursor = collector._extract_pagination_cursor({
            "data": [],
            "meta": {
                "pagination": {
                    "next": "nested-cursor",
                },
            },
        })

        assert cursor == "nested-cursor"

    def test_extract_cursor_missing(self):
        """Test cursor extraction when cursor is missing."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "pagination": {
                "type": "cursor",
                "cursor_field": "next_cursor",
            },
        })
        collector = ApiPullCollector(source, JsonParser())

        cursor = collector._extract_pagination_cursor({"data": []})

        assert cursor is None


class TestApiPullCollectorRequests:
    """Tests for HTTP request making."""

    @pytest.mark.asyncio
    async def test_make_request_get(self):
        """Test making GET request."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "endpoint": "/events",
            "method": "GET",
            "auth_type": "none",
        })
        collector = ApiPullCollector(source, JsonParser())

        mock_response = MagicMock()
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(httpx.AsyncClient, 'get', new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            result = await collector._make_request()

            assert result == {"data": []}

        await collector.stop()

    @pytest.mark.asyncio
    async def test_test_connection_success(self):
        """Test successful connection test."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = {"data": []}

            success, message = await collector.test_connection()

            assert success is True
            assert "Successfully" in message

        await collector.stop()

    @pytest.mark.asyncio
    async def test_test_connection_http_error(self):
        """Test connection test with HTTP error."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch.object(collector, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = httpx.HTTPStatusError(
                "Unauthorized",
                request=MagicMock(),
                response=mock_response,
            )

            success, message = await collector.test_connection()

            assert success is False
            assert "401" in message

        await collector.stop()

    @pytest.mark.asyncio
    async def test_test_connection_general_error(self):
        """Test connection test with general error."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = Exception("Network error")

            success, message = await collector.test_connection()

            assert success is False
            assert "Network error" in message

        await collector.stop()


class TestApiPullCollectorPolling:
    """Tests for polling functionality."""

    @pytest.mark.asyncio
    async def test_poll_once_success(self):
        """Test successful single poll."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        mock_data = [
            {"timestamp": "2024-01-15T12:00:00Z", "message": "Event 1"},
            {"timestamp": "2024-01-15T12:00:01Z", "message": "Event 2"},
        ]

        with patch.object(collector, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_data

            results = await collector._poll_once()

            assert len(results) == 2

        await collector.stop()

    @pytest.mark.asyncio
    async def test_poll_once_error(self):
        """Test poll with error returns empty list."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = Exception("API error")

            results = await collector._poll_once()

            assert len(results) == 0

        await collector.stop()

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test starting and stopping collector."""
        source = create_mock_source(config={
            "url": "https://api.example.com",
            "poll_interval_seconds": 1,
        })
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, '_poll_once', new_callable=AsyncMock) as mock_poll:
            mock_poll.return_value = []

            await collector.start()
            assert collector.is_running()

            # Let it run briefly
            await asyncio.sleep(0.1)

            await collector.stop()
            assert not collector.is_running()

    @pytest.mark.asyncio
    async def test_updates_last_timestamp(self):
        """Test that last_timestamp is updated after polling."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        mock_data = [
            {"timestamp": "2024-01-15T12:00:00Z", "message": "Event 1"},
            {"timestamp": "2024-01-15T13:00:00Z", "message": "Event 2"},
        ]

        with patch.object(collector, '_make_request', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_data

            await collector._poll_once()

            # Last timestamp should be the most recent event
            assert collector._last_timestamp is not None
            assert collector._last_timestamp.hour == 13

        await collector.stop()
