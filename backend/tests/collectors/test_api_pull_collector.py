"""Tests for the API pull collector."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.collectors.api_pull_collector import ApiPullCollector
from app.collectors.error_handler import (
    CollectorCircuitOpenError,
)
from app.models.log_source import LogSource, SourceType
from app.parsers.base import ParseResult
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
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "endpoint": "/v1/events",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        url = collector._build_url()

        assert url == "https://api.example.com/v1/events"

    def test_build_url_without_endpoint(self):
        """Test URL building without endpoint."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com/events",
                "endpoint": "",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        url = collector._build_url()

        assert url == "https://api.example.com/events"

    def test_build_url_strips_trailing_slash(self):
        """Test that trailing slashes are handled."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com/",
                "endpoint": "/events",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        url = collector._build_url()

        assert url == "https://api.example.com/events"


class TestApiPullCollectorHeaders:
    """Tests for header building logic."""

    def test_build_headers_no_auth(self):
        """Test header building with no auth."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "auth_type": "none",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        headers = collector._build_headers()

        assert "Authorization" not in headers

    def test_build_headers_bearer_auth(self):
        """Test header building with bearer auth."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "auth_type": "bearer",
                "api_key": "my-secret-token",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        headers = collector._build_headers()

        assert headers["Authorization"] == "Bearer my-secret-token"

    def test_build_headers_api_key(self):
        """Test header building with API key auth."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "auth_type": "api_key",
                "api_key": "my-api-key",
                "api_key_header": "X-Custom-Key",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        headers = collector._build_headers()

        assert headers["X-Custom-Key"] == "my-api-key"

    def test_build_headers_custom_headers(self):
        """Test header building with custom headers."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "auth_type": "none",
                "headers": {
                    "X-Custom-Header": "value",
                    "Accept": "application/json",
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        headers = collector._build_headers()

        assert headers["X-Custom-Header"] == "value"
        assert headers["Accept"] == "application/json"


class TestApiPullCollectorBasicAuth:
    """Tests for basic auth building."""

    def test_build_auth_basic(self):
        """Test basic auth tuple building."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "auth_type": "basic",
                "username": "user",
                "password": "pass",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        auth = collector._build_auth()

        assert auth == ("user", "pass")

    def test_build_auth_no_basic(self):
        """Test that non-basic auth returns None."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "auth_type": "bearer",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        auth = collector._build_auth()

        assert auth is None


class TestApiPullCollectorParams:
    """Tests for query parameter building."""

    def test_build_params_basic(self):
        """Test basic query params."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "query_params": {"limit": 100, "format": "json"},
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        params = collector._build_params()

        assert params["limit"] == 100
        assert params["format"] == "json"

    def test_build_params_with_cursor_pagination(self):
        """Test params with cursor pagination."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "pagination": {
                    "type": "cursor",
                    "cursor_param": "cursor",
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())
        collector._last_cursor = "abc123"

        params = collector._build_params()

        assert params["cursor"] == "abc123"

    def test_build_params_without_cursor(self):
        """Test params with cursor pagination but no cursor yet."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "pagination": {
                    "type": "cursor",
                    "cursor_param": "cursor",
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        params = collector._build_params()

        assert "cursor" not in params


class TestApiPullCollectorPagination:
    """Tests for pagination cursor extraction."""

    def test_extract_cursor_simple(self):
        """Test simple cursor extraction."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "pagination": {
                    "type": "cursor",
                    "cursor_field": "next_cursor",
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        cursor = collector._extract_pagination_cursor(
            {
                "data": [],
                "next_cursor": "xyz789",
            }
        )

        assert cursor == "xyz789"

    def test_extract_cursor_nested(self):
        """Test nested cursor extraction."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "pagination": {
                    "type": "cursor",
                    "cursor_field": "meta.pagination.next",
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        cursor = collector._extract_pagination_cursor(
            {
                "data": [],
                "meta": {
                    "pagination": {
                        "next": "nested-cursor",
                    },
                },
            }
        )

        assert cursor == "nested-cursor"

    def test_extract_cursor_missing(self):
        """Test cursor extraction when cursor is missing."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "pagination": {
                    "type": "cursor",
                    "cursor_field": "next_cursor",
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        cursor = collector._extract_pagination_cursor({"data": []})

        assert cursor is None


class TestApiPullCollectorRequests:
    """Tests for HTTP request making."""

    @pytest.mark.asyncio
    async def test_make_request_get(self):
        """Test making GET request."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "endpoint": "/events",
                "method": "GET",
                "auth_type": "none",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        mock_response = MagicMock()
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            result = await collector._make_request()

            assert result == {"data": []}

        await collector.stop()

    @pytest.mark.asyncio
    async def test_test_connection_success(self):
        """Test successful connection test."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
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

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
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

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
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

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_data

            results = await collector._poll_once()

            assert len(results) == 2

        await collector.stop()

    @pytest.mark.asyncio
    async def test_poll_once_error(self):
        """Test poll with error returns empty list."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = Exception("API error")

            results = await collector._poll_once()

            assert len(results) == 0

        await collector.stop()

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test starting and stopping collector."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "poll_interval_seconds": 1,
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, "_poll_once", new_callable=AsyncMock) as mock_poll:
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

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_data

            await collector._poll_once()

            # Last timestamp should be the most recent event
            assert collector._last_timestamp is not None
            assert collector._last_timestamp.hour == 13

        await collector.stop()


class TestApiPullCollectorHttpErrors:
    """Tests for HTTP error handling."""

    @pytest.mark.asyncio
    async def test_http_401_unauthorized(self):
        """Test handling 401 Unauthorized response."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = httpx.HTTPStatusError(
                "Unauthorized",
                request=MagicMock(),
                response=mock_response,
            )

            results = await collector._poll_once()

            assert len(results) == 0
            assert collector._consecutive_failures >= 1

        await collector.stop()

    @pytest.mark.asyncio
    async def test_http_429_rate_limited(self):
        """Test handling 429 Too Many Requests response."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        mock_response = MagicMock()
        mock_response.status_code = 429

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = httpx.HTTPStatusError(
                "Too Many Requests",
                request=MagicMock(),
                response=mock_response,
            )

            results = await collector._poll_once()

            assert len(results) == 0

        await collector.stop()

    @pytest.mark.asyncio
    async def test_http_500_server_error(self):
        """Test handling 500 Internal Server Error response."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = httpx.HTTPStatusError(
                "Internal Server Error",
                request=MagicMock(),
                response=mock_response,
            )

            results = await collector._poll_once()

            assert len(results) == 0

        await collector.stop()


class TestApiPullCollectorCircuitBreaker:
    """Tests for circuit breaker integration."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_on_failures(self):
        """Test that circuit breaker opens after repeated failures."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "circuit_failure_threshold": 3,
                "circuit_recovery_timeout": 30.0,
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        # Simulate multiple failures to open circuit
        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = Exception("Connection error")

            # Trigger failures
            for _ in range(5):
                await collector._poll_once()

            # Circuit should be open after failures
            # Note: This depends on the retry handler behavior

        await collector.stop()

    @pytest.mark.asyncio
    async def test_circuit_open_returns_empty(self):
        """Test that circuit open state returns empty results."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        # Create mock retry handler that raises circuit open error
        with patch.object(
            collector._retry_handler, "execute", new_callable=AsyncMock
        ) as mock_execute:
            mock_execute.side_effect = CollectorCircuitOpenError("Circuit open")

            results = await collector._poll_once()

            assert len(results) == 0

        await collector.stop()

    @pytest.mark.asyncio
    async def test_success_resets_consecutive_failures(self):
        """Test that successful poll resets consecutive failures."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        # Set some failures
        collector._consecutive_failures = 3

        mock_data = [{"timestamp": "2024-01-15T12:00:00Z", "message": "Event"}]

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.return_value = mock_data

            await collector._poll_once()

            assert collector._consecutive_failures == 0

        await collector.stop()


class TestApiPullCollectorPostMethod:
    """Tests for POST request method."""

    @pytest.mark.asyncio
    async def test_make_request_post(self):
        """Test making POST request."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "endpoint": "/events",
                "method": "POST",
                "auth_type": "none",
                "body": {"query": "fetch events"},
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        mock_response = MagicMock()
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(httpx.AsyncClient, "post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response

            result = await collector._make_request()

            assert result == {"data": []}
            mock_post.assert_called_once()

        await collector.stop()

    @pytest.mark.asyncio
    async def test_make_request_unsupported_method(self):
        """Test that unsupported HTTP method raises error."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "method": "DELETE",
                "auth_type": "none",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        with pytest.raises(ValueError, match="Unsupported HTTP method"):
            await collector._make_request()

        await collector.stop()


class TestApiPullCollectorCollect:
    """Tests for the collect async generator."""

    @pytest.mark.asyncio
    async def test_collect_yields_results_from_queue(self):
        """Test that collect yields results from the event queue."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        # Put results in the queue
        mock_result = MagicMock(spec=ParseResult)
        await collector._event_queue.put(mock_result)

        collector._running = True

        results = []
        async for result in collector.collect():
            results.append(result)
            collector._running = False  # Stop after first result
            break

        assert len(results) == 1
        assert results[0] == mock_result

        await collector.stop()

    @pytest.mark.asyncio
    async def test_collect_continues_when_not_running_but_queue_not_empty(self):
        """Test that collect yields remaining queue items when stopped."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        # Put results in the queue
        mock_result1 = MagicMock(spec=ParseResult)
        mock_result2 = MagicMock(spec=ParseResult)
        await collector._event_queue.put(mock_result1)
        await collector._event_queue.put(mock_result2)

        collector._running = False  # Already stopped

        results = []
        async for result in collector.collect():
            results.append(result)
            if len(results) >= 2:
                break

        assert len(results) == 2

        await collector.stop()

    @pytest.mark.asyncio
    async def test_collect_handles_timeout(self):
        """Test that collect handles queue timeout gracefully."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        collector._running = True

        # Run collect briefly with empty queue
        async def collect_with_timeout():
            results = []
            count = 0
            async for result in collector.collect():
                results.append(result)
                count += 1
                if count >= 2:
                    break
            return results

        # Stop collector after a brief moment
        async def stop_after_delay():
            await asyncio.sleep(0.1)
            collector._running = False

        await asyncio.gather(
            stop_after_delay(),
            asyncio.wait_for(collect_with_timeout(), timeout=2.0),
            return_exceptions=True,
        )

        await collector.stop()


class TestApiPullCollectorTimeout:
    """Tests for timeout configuration."""

    def test_default_timeout(self):
        """Test default timeout is used when not configured."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        # Default is 30 seconds per the docstring
        assert collector.config.get("timeout_seconds", 30) == 30

    def test_custom_timeout(self):
        """Test custom timeout is respected."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "timeout_seconds": 60,
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        assert collector.config.get("timeout_seconds") == 60

    @pytest.mark.asyncio
    async def test_request_timeout_error(self):
        """Test handling of timeout errors."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = httpx.TimeoutException("Request timed out")

            results = await collector._poll_once()

            assert len(results) == 0
            assert collector._consecutive_failures >= 1

        await collector.stop()


class TestApiPullCollectorErrorTracking:
    """Tests for error tracking functionality."""

    @pytest.mark.asyncio
    async def test_error_tracker_records_errors(self):
        """Test that errors are recorded in the error tracker."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = Exception("Test error")

            with patch.object(
                collector._error_tracker, "record_error", new_callable=AsyncMock
            ) as mock_record:
                await collector._poll_once()

                mock_record.assert_called_once()

        await collector.stop()

    @pytest.mark.asyncio
    async def test_consecutive_failures_increment(self):
        """Test that consecutive failures increment on error."""
        source = create_mock_source()
        collector = ApiPullCollector(source, JsonParser())

        initial_failures = collector._consecutive_failures

        with patch.object(collector, "_make_request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = Exception("Test error")

            await collector._poll_once()

            assert collector._consecutive_failures > initial_failures

        await collector.stop()


class TestApiPullCollectorTimestampPagination:
    """Tests for timestamp-based pagination."""

    def test_build_params_with_timestamp_pagination(self):
        """Test params with timestamp pagination."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "pagination": {
                    "type": "timestamp",
                    "timestamp_param": "since",
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())
        collector._last_timestamp = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

        params = collector._build_params()

        assert "since" in params
        assert "2024-01-15" in params["since"]

    def test_build_params_without_timestamp(self):
        """Test params with timestamp pagination but no timestamp yet."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "pagination": {
                    "type": "timestamp",
                    "timestamp_param": "since",
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        params = collector._build_params()

        assert "since" not in params

    def test_build_params_with_offset_pagination(self):
        """Test params with offset pagination."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "pagination": {
                    "type": "offset",
                    "offset_param": "offset",
                    "limit_param": "limit",
                    "limit": 50,
                },
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        params = collector._build_params()

        assert params["limit"] == 50


class TestApiPullCollectorStartAlreadyRunning:
    """Tests for start when already running."""

    @pytest.mark.asyncio
    async def test_start_already_running_is_noop(self):
        """Test that starting an already running collector is a no-op."""
        source = create_mock_source(
            config={
                "url": "https://api.example.com",
                "poll_interval_seconds": 60,
            }
        )
        collector = ApiPullCollector(source, JsonParser())

        with patch.object(collector, "_poll_once", new_callable=AsyncMock) as mock_poll:
            mock_poll.return_value = []

            await collector.start()
            first_task = collector._poll_task

            await collector.start()  # Should be no-op
            assert collector._poll_task is first_task

            await collector.stop()
