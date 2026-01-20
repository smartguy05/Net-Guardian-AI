"""API pull collector for fetching logs from REST APIs."""

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, Optional

import httpx
import structlog

from app.collectors.base import BaseCollector
from app.collectors.registry import register_collector
from app.collectors.error_handler import (
    RetryConfig,
    RetryHandler,
    CircuitBreaker,
    ErrorTracker,
    CollectorError,
    CollectorCircuitOpenError,
    categorize_error,
)
from app.models.log_source import LogSource, SourceType
from app.parsers.base import BaseParser, ParseResult
from app.services.metrics_service import COLLECTOR_CIRCUIT_STATE

logger = structlog.get_logger()


@register_collector(SourceType.API_PULL)
class ApiPullCollector(BaseCollector):
    """Collector that polls REST APIs for log data.

    Configuration options:
        url: Base URL of the API
        endpoint: API endpoint to poll (appended to url)
        method: HTTP method (GET, POST)
        auth_type: Authentication type (none, basic, bearer, api_key)
        username: Username for basic auth
        password: Password for basic auth
        api_key: API key for api_key or bearer auth
        api_key_header: Header name for API key (default: X-API-Key)
        headers: Additional headers dict
        query_params: Query parameters dict
        body: Request body for POST requests
        poll_interval_seconds: Polling interval (default: 30)
        timeout_seconds: Request timeout (default: 30)
        pagination: Pagination configuration dict
            type: cursor, offset, or timestamp
            cursor_field: Field in response containing next cursor
            cursor_param: Query param to send cursor
            offset_param: Query param for offset
            limit_param: Query param for limit
            limit: Items per page
    """

    def __init__(self, source: LogSource, parser: BaseParser):
        super().__init__(source, parser)
        self._client: Optional[httpx.AsyncClient] = None
        self._poll_task: Optional[asyncio.Task] = None
        self._last_cursor: Optional[str] = None
        self._last_timestamp: Optional[datetime] = None
        self._event_queue: asyncio.Queue = asyncio.Queue()

        # Error handling setup
        retry_config = RetryConfig(
            max_retries=self.config.get("max_retries", 3),
            initial_delay=self.config.get("retry_initial_delay", 1.0),
            max_delay=self.config.get("retry_max_delay", 60.0),
        )
        self._circuit_breaker = CircuitBreaker(
            failure_threshold=self.config.get("circuit_failure_threshold", 5),
            recovery_timeout=self.config.get("circuit_recovery_timeout", 30.0),
        )
        self._retry_handler = RetryHandler(retry_config, self._circuit_breaker)
        self._error_tracker = ErrorTracker()
        self._consecutive_failures = 0

    def _build_url(self) -> str:
        """Build the full URL for the API request."""
        base_url = self.config.get("url", "").rstrip("/")
        endpoint = self.config.get("endpoint", "").lstrip("/")
        if endpoint:
            return f"{base_url}/{endpoint}"
        return base_url

    def _build_headers(self) -> Dict[str, str]:
        """Build request headers including authentication."""
        headers = dict(self.config.get("headers", {}))
        auth_type = self.config.get("auth_type", "none")

        if auth_type == "bearer":
            api_key = self.config.get("api_key", "")
            headers["Authorization"] = f"Bearer {api_key}"
        elif auth_type == "api_key":
            api_key = self.config.get("api_key", "")
            header_name = self.config.get("api_key_header", "X-API-Key")
            headers[header_name] = api_key

        return headers

    def _build_auth(self) -> Optional[tuple[str, str]]:
        """Build basic auth tuple if needed."""
        auth_type = self.config.get("auth_type", "none")
        if auth_type == "basic":
            username = self.config.get("username", "")
            password = self.config.get("password", "")
            return (username, password)
        return None

    def _build_params(self) -> Dict[str, Any]:
        """Build query parameters including pagination."""
        params = dict(self.config.get("query_params", {}))
        pagination = self.config.get("pagination", {})

        if pagination:
            pag_type = pagination.get("type")

            if pag_type == "cursor" and self._last_cursor:
                cursor_param = pagination.get("cursor_param", "cursor")
                params[cursor_param] = self._last_cursor

            elif pag_type == "offset":
                offset_param = pagination.get("offset_param", "offset")
                limit_param = pagination.get("limit_param", "limit")
                limit = pagination.get("limit", 100)
                # Note: offset tracking would need to be maintained
                params[limit_param] = limit

            elif pag_type == "timestamp" and self._last_timestamp:
                timestamp_param = pagination.get("timestamp_param", "since")
                params[timestamp_param] = self._last_timestamp.isoformat()

        return params

    def _extract_pagination_cursor(self, response_data: Any) -> Optional[str]:
        """Extract pagination cursor from response."""
        pagination = self.config.get("pagination", {})
        if not pagination or pagination.get("type") != "cursor":
            return None

        cursor_field = pagination.get("cursor_field", "next_cursor")

        if isinstance(response_data, dict):
            # Handle nested paths like "meta.next_cursor"
            parts = cursor_field.split(".")
            current = response_data
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None
            return current if isinstance(current, str) else None

        return None

    async def _make_request(self) -> Any:
        """Make the API request and return response data."""
        if not self._client:
            self._client = httpx.AsyncClient(
                timeout=self.config.get("timeout_seconds", 30),
                verify=self.config.get("verify_ssl", True),
            )

        url = self._build_url()
        method = self.config.get("method", "GET").upper()
        headers = self._build_headers()
        auth = self._build_auth()
        params = self._build_params()
        body = self.config.get("body")

        logger.debug(
            "api_pull_request",
            source_id=self.source_id,
            url=url,
            method=method,
        )

        try:
            if method == "GET":
                response = await self._client.get(
                    url, headers=headers, params=params, auth=auth
                )
            elif method == "POST":
                response = await self._client.post(
                    url, headers=headers, params=params, json=body, auth=auth
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(
                "api_pull_http_error",
                source_id=self.source_id,
                status_code=e.response.status_code,
                error=str(e),
            )
            raise
        except Exception as e:
            logger.error(
                "api_pull_error",
                source_id=self.source_id,
                error=str(e),
            )
            raise

    async def _poll_once(self) -> list[ParseResult]:
        """Perform a single poll and return parsed events."""
        try:
            # Use retry handler for the API request
            response_data = await self._retry_handler.execute(
                self._make_request,
                self.source_id,
                "api_poll",
            )

            # Reset consecutive failures on success
            self._consecutive_failures = 0

            # Update circuit breaker metric
            COLLECTOR_CIRCUIT_STATE.labels(source_id=self.source_id).set(
                0 if self._circuit_breaker.is_closed else
                (1 if self._circuit_breaker.state == CircuitBreaker.State.HALF_OPEN else 2)
            )

            # Parse the response
            results = self.parser.parse(response_data)

            # Update pagination cursor if applicable
            new_cursor = self._extract_pagination_cursor(response_data)
            if new_cursor:
                self._last_cursor = new_cursor

            # Update last timestamp from most recent event
            if results:
                self._last_timestamp = max(r.timestamp for r in results)

            logger.info(
                "api_pull_success",
                source_id=self.source_id,
                events_parsed=len(results),
            )

            return results

        except CollectorCircuitOpenError:
            # Circuit is open - don't attempt request
            logger.warning(
                "api_poll_circuit_open",
                source_id=self.source_id,
            )
            COLLECTOR_CIRCUIT_STATE.labels(source_id=self.source_id).set(2)
            return []

        except Exception as e:
            self._consecutive_failures += 1

            # Track the error
            category, retryable = categorize_error(e)
            error = CollectorError(
                category=category,
                message=str(e),
                source_id=self.source_id,
                retryable=retryable,
                original_exception=e,
            )
            await self._error_tracker.record_error(error)

            # Update circuit breaker metric
            COLLECTOR_CIRCUIT_STATE.labels(source_id=self.source_id).set(
                0 if self._circuit_breaker.is_closed else
                (1 if self._circuit_breaker.state == CircuitBreaker.State.HALF_OPEN else 2)
            )

            logger.error(
                "api_poll_failed",
                source_id=self.source_id,
                error_category=category.value,
                consecutive_failures=self._consecutive_failures,
                error=str(e),
            )
            return []

    async def _poll_loop(self) -> None:
        """Main polling loop."""
        interval = self.config.get("poll_interval_seconds", 30)

        while self._running:
            try:
                results = await self._poll_once()

                # Put results in queue for consumers
                for result in results:
                    await self._event_queue.put(result)

            except Exception as e:
                logger.error(
                    "poll_loop_error",
                    source_id=self.source_id,
                    error=str(e),
                )

            # Wait for next poll interval
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break

    async def collect(self) -> AsyncGenerator[ParseResult, None]:
        """Collect events from the queue."""
        while self._running or not self._event_queue.empty():
            try:
                result = await asyncio.wait_for(
                    self._event_queue.get(),
                    timeout=1.0,
                )
                yield result
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def start(self) -> None:
        """Start the polling loop."""
        if self._running:
            return

        self._running = True
        self._poll_task = asyncio.create_task(self._poll_loop())

        logger.info(
            "api_pull_collector_started",
            source_id=self.source_id,
            url=self._build_url(),
            interval=self.config.get("poll_interval_seconds", 30),
        )

    async def stop(self) -> None:
        """Stop the collector."""
        self._running = False

        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None

        if self._client:
            await self._client.aclose()
            self._client = None

        logger.info("api_pull_collector_stopped", source_id=self.source_id)

    async def test_connection(self) -> tuple[bool, str]:
        """Test the API connection."""
        try:
            await self._make_request()
            return True, "Successfully connected to API"
        except httpx.HTTPStatusError as e:
            return False, f"HTTP error: {e.response.status_code}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
