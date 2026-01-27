"""Tests for collector error handling and retry logic.

Tests cover:
- Error categorization
- Retry configuration
- Circuit breaker state machine
- Retry handler with exponential backoff
- Error tracker
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.collectors.error_handler import (
    categorize_error,
    CircuitBreaker,
    CollectorCircuitOpenError,
    CollectorError,
    ErrorCategory,
    ErrorTracker,
    RetryConfig,
    RetryHandler,
    with_retry,
)


class TestCategorizeError:
    """Tests for the categorize_error function."""

    def test_connect_error_is_network_retryable(self):
        """ConnectError should be categorized as network and retryable."""
        error = httpx.ConnectError("Connection failed")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.NETWORK
        assert retryable is True

    def test_connect_timeout_is_network_retryable(self):
        """ConnectTimeout should be categorized as network and retryable."""
        error = httpx.ConnectTimeout("Connection timed out")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.NETWORK
        assert retryable is True

    def test_timeout_exception_is_network_retryable(self):
        """TimeoutException should be categorized as network and retryable."""
        error = httpx.TimeoutException("Timeout")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.NETWORK
        assert retryable is True

    def test_401_is_auth_not_retryable(self):
        """HTTP 401 should be categorized as auth and not retryable."""
        response = MagicMock()
        response.status_code = 401
        error = httpx.HTTPStatusError("Unauthorized", request=MagicMock(), response=response)
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.AUTH
        assert retryable is False

    def test_403_is_auth_not_retryable(self):
        """HTTP 403 should be categorized as auth and not retryable."""
        response = MagicMock()
        response.status_code = 403
        error = httpx.HTTPStatusError("Forbidden", request=MagicMock(), response=response)
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.AUTH
        assert retryable is False

    def test_429_is_rate_limit_retryable(self):
        """HTTP 429 should be categorized as rate_limit and retryable."""
        response = MagicMock()
        response.status_code = 429
        error = httpx.HTTPStatusError("Too Many Requests", request=MagicMock(), response=response)
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.RATE_LIMIT
        assert retryable is True

    def test_400_is_client_not_retryable(self):
        """HTTP 400 should be categorized as client and not retryable."""
        response = MagicMock()
        response.status_code = 400
        error = httpx.HTTPStatusError("Bad Request", request=MagicMock(), response=response)
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.CLIENT
        assert retryable is False

    def test_404_is_client_not_retryable(self):
        """HTTP 404 should be categorized as client and not retryable."""
        response = MagicMock()
        response.status_code = 404
        error = httpx.HTTPStatusError("Not Found", request=MagicMock(), response=response)
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.CLIENT
        assert retryable is False

    def test_500_is_server_retryable(self):
        """HTTP 500 should be categorized as server and retryable."""
        response = MagicMock()
        response.status_code = 500
        error = httpx.HTTPStatusError("Internal Server Error", request=MagicMock(), response=response)
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.SERVER
        assert retryable is True

    def test_503_is_server_retryable(self):
        """HTTP 503 should be categorized as server and retryable."""
        response = MagicMock()
        response.status_code = 503
        error = httpx.HTTPStatusError("Service Unavailable", request=MagicMock(), response=response)
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.SERVER
        assert retryable is True

    def test_file_not_found_is_config_not_retryable(self):
        """FileNotFoundError should be categorized as config and not retryable."""
        error = FileNotFoundError("File not found")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.CONFIG
        assert retryable is False

    def test_permission_error_is_config_not_retryable(self):
        """PermissionError should be categorized as config and not retryable."""
        error = PermissionError("Permission denied")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.CONFIG
        assert retryable is False

    def test_value_error_is_parse_not_retryable(self):
        """ValueError should be categorized as parse and not retryable."""
        error = ValueError("Invalid value")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.PARSE
        assert retryable is False

    def test_key_error_is_parse_not_retryable(self):
        """KeyError should be categorized as parse and not retryable."""
        error = KeyError("Missing key")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.PARSE
        assert retryable is False

    def test_type_error_is_parse_not_retryable(self):
        """TypeError should be categorized as parse and not retryable."""
        error = TypeError("Invalid type")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.PARSE
        assert retryable is False

    def test_memory_error_is_resource_retryable(self):
        """MemoryError should be categorized as resource and retryable."""
        error = MemoryError("Out of memory")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.RESOURCE
        assert retryable is True

    def test_queue_full_is_resource_retryable(self):
        """QueueFull should be categorized as resource and retryable."""
        error = asyncio.QueueFull()
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.RESOURCE
        assert retryable is True

    def test_connection_error_is_network_retryable(self):
        """ConnectionError should be categorized as network and retryable."""
        error = ConnectionError("Connection refused")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.NETWORK
        assert retryable is True

    def test_os_error_is_network_retryable(self):
        """OSError should be categorized as network and retryable."""
        error = OSError("OS error")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.NETWORK
        assert retryable is True

    def test_unknown_error_is_unknown_retryable(self):
        """Unknown exceptions should be categorized as unknown and retryable."""
        error = RuntimeError("Unknown error")
        category, retryable = categorize_error(error)

        assert category == ErrorCategory.UNKNOWN
        assert retryable is True


class TestCollectorError:
    """Tests for the CollectorError dataclass."""

    def test_creates_error_with_defaults(self):
        """Should create an error with default values."""
        error = CollectorError(
            category=ErrorCategory.NETWORK,
            message="Connection failed",
            source_id="test-source",
        )

        assert error.category == ErrorCategory.NETWORK
        assert error.message == "Connection failed"
        assert error.source_id == "test-source"
        assert error.retryable is True
        assert error.details == {}
        assert error.original_exception is None
        assert isinstance(error.timestamp, datetime)

    def test_creates_error_with_all_fields(self):
        """Should create an error with all fields specified."""
        original = ValueError("Test")
        error = CollectorError(
            category=ErrorCategory.PARSE,
            message="Parse failed",
            source_id="test-source",
            retryable=False,
            details={"line": 42},
            original_exception=original,
        )

        assert error.category == ErrorCategory.PARSE
        assert error.retryable is False
        assert error.details == {"line": 42}
        assert error.original_exception is original

    def test_to_dict(self):
        """Should convert error to dictionary."""
        error = CollectorError(
            category=ErrorCategory.NETWORK,
            message="Connection failed",
            source_id="test-source",
            details={"attempt": 1},
        )
        result = error.to_dict()

        assert result["category"] == "network"
        assert result["message"] == "Connection failed"
        assert result["source_id"] == "test-source"
        assert result["retryable"] is True
        assert result["details"] == {"attempt": 1}
        assert "timestamp" in result


class TestRetryConfig:
    """Tests for the RetryConfig dataclass."""

    def test_default_values(self):
        """Should have correct default values."""
        config = RetryConfig()

        assert config.max_retries == 3
        assert config.initial_delay == 1.0
        assert config.max_delay == 60.0
        assert config.exponential_base == 2.0
        assert config.jitter == 0.1

    def test_custom_values(self):
        """Should accept custom values."""
        config = RetryConfig(
            max_retries=5,
            initial_delay=0.5,
            max_delay=30.0,
            exponential_base=3.0,
            jitter=0.2,
        )

        assert config.max_retries == 5
        assert config.initial_delay == 0.5
        assert config.max_delay == 30.0
        assert config.exponential_base == 3.0
        assert config.jitter == 0.2


class TestCircuitBreaker:
    """Tests for the CircuitBreaker class."""

    @pytest.fixture
    def circuit_breaker(self):
        """Create a circuit breaker with test-friendly settings."""
        return CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=1.0,
            half_open_max_calls=2,
        )

    def test_initial_state_is_closed(self, circuit_breaker):
        """Should start in closed state."""
        assert circuit_breaker.state == CircuitBreaker.State.CLOSED
        assert circuit_breaker.is_closed is True

    async def test_can_proceed_when_closed(self, circuit_breaker):
        """Should allow requests when closed."""
        assert await circuit_breaker.can_proceed() is True

    async def test_stays_closed_below_threshold(self, circuit_breaker):
        """Should stay closed when failures are below threshold."""
        await circuit_breaker.record_failure()
        await circuit_breaker.record_failure()

        assert circuit_breaker.state == CircuitBreaker.State.CLOSED
        assert await circuit_breaker.can_proceed() is True

    async def test_opens_at_threshold(self, circuit_breaker):
        """Should open when failure threshold is reached."""
        for _ in range(3):
            await circuit_breaker.record_failure()

        assert circuit_breaker.state == CircuitBreaker.State.OPEN

    async def test_cannot_proceed_when_open(self, circuit_breaker):
        """Should reject requests when open."""
        for _ in range(3):
            await circuit_breaker.record_failure()

        assert await circuit_breaker.can_proceed() is False

    async def test_transitions_to_half_open_after_timeout(self, circuit_breaker):
        """Should transition to half-open after recovery timeout."""
        for _ in range(3):
            await circuit_breaker.record_failure()

        # Wait for recovery timeout
        await asyncio.sleep(1.1)

        # Should now allow a test call
        assert await circuit_breaker.can_proceed() is True
        assert circuit_breaker.state == CircuitBreaker.State.HALF_OPEN

    async def test_closes_after_successful_half_open_calls(self, circuit_breaker):
        """Should close after successful calls in half-open state."""
        # Open the circuit
        for _ in range(3):
            await circuit_breaker.record_failure()

        # Wait for recovery timeout
        await asyncio.sleep(1.1)

        # Transition to half-open
        await circuit_breaker.can_proceed()

        # Record successful calls
        await circuit_breaker.record_success()
        await circuit_breaker.record_success()

        assert circuit_breaker.state == CircuitBreaker.State.CLOSED

    async def test_reopens_on_half_open_failure(self, circuit_breaker):
        """Should reopen if a call fails in half-open state."""
        # Open the circuit
        for _ in range(3):
            await circuit_breaker.record_failure()

        # Wait for recovery timeout
        await asyncio.sleep(1.1)

        # Transition to half-open
        await circuit_breaker.can_proceed()

        # Record failure
        await circuit_breaker.record_failure()

        assert circuit_breaker.state == CircuitBreaker.State.OPEN

    async def test_success_resets_failure_count_when_closed(self, circuit_breaker):
        """Should reset failure count on success when closed."""
        await circuit_breaker.record_failure()
        await circuit_breaker.record_failure()
        await circuit_breaker.record_success()

        # Now it should take 3 more failures to open
        await circuit_breaker.record_failure()
        await circuit_breaker.record_failure()
        assert circuit_breaker.state == CircuitBreaker.State.CLOSED

        await circuit_breaker.record_failure()
        assert circuit_breaker.state == CircuitBreaker.State.OPEN

    def test_reset(self, circuit_breaker):
        """Should reset to closed state."""
        circuit_breaker._state = CircuitBreaker.State.OPEN
        circuit_breaker._failure_count = 10
        circuit_breaker._last_failure_time = datetime.now(timezone.utc)
        circuit_breaker._half_open_calls = 5

        circuit_breaker.reset()

        assert circuit_breaker.state == CircuitBreaker.State.CLOSED
        assert circuit_breaker._failure_count == 0
        assert circuit_breaker._last_failure_time is None
        assert circuit_breaker._half_open_calls == 0

    async def test_limits_half_open_calls(self, circuit_breaker):
        """Should limit calls in half-open state."""
        # Open the circuit
        for _ in range(3):
            await circuit_breaker.record_failure()

        # Wait for recovery timeout
        await asyncio.sleep(1.1)

        # Should allow up to half_open_max_calls
        assert await circuit_breaker.can_proceed() is True  # Transitions to half-open
        circuit_breaker._half_open_calls = 2  # Simulate calls made

        # Should not allow more calls
        assert await circuit_breaker.can_proceed() is False


class TestRetryHandler:
    """Tests for the RetryHandler class."""

    @pytest.fixture
    def retry_handler(self):
        """Create a retry handler with test-friendly settings."""
        config = RetryConfig(
            max_retries=3,
            initial_delay=0.01,  # Short delays for testing
            max_delay=0.1,
            jitter=0.0,  # Disable jitter for predictable tests
        )
        return RetryHandler(config)

    def test_calculate_delay_exponential_backoff(self, retry_handler):
        """Should calculate exponential backoff delays."""
        # With jitter=0, delays should be predictable
        assert retry_handler.calculate_delay(0) == 0.01  # 0.01 * 2^0 = 0.01
        assert retry_handler.calculate_delay(1) == 0.02  # 0.01 * 2^1 = 0.02
        assert retry_handler.calculate_delay(2) == 0.04  # 0.01 * 2^2 = 0.04

    def test_calculate_delay_respects_max(self, retry_handler):
        """Should cap delay at max_delay."""
        # Large attempt number should still respect max_delay
        delay = retry_handler.calculate_delay(10)  # 0.01 * 2^10 = 10.24 > 0.1
        assert delay == 0.1

    def test_calculate_delay_with_jitter(self):
        """Should add jitter to delay."""
        config = RetryConfig(jitter=0.5)  # 50% jitter
        handler = RetryHandler(config)

        # Run multiple times to verify jitter varies
        delays = [handler.calculate_delay(0) for _ in range(10)]

        # With 50% jitter on 1.0 second, range should be 0.5 to 1.5
        assert all(0.5 <= d <= 1.5 for d in delays)

    async def test_execute_success_first_try(self, retry_handler):
        """Should return result on successful first try."""
        func = AsyncMock(return_value="success")

        result = await retry_handler.execute(func, "test-source", "test-op")

        assert result == "success"
        func.assert_called_once()

    async def test_execute_retries_on_retryable_error(self, retry_handler):
        """Should retry on retryable errors."""
        func = AsyncMock(
            side_effect=[
                httpx.ConnectError("First fail"),
                httpx.ConnectError("Second fail"),
                "success",
            ]
        )

        result = await retry_handler.execute(func, "test-source", "test-op")

        assert result == "success"
        assert func.call_count == 3

    async def test_execute_does_not_retry_non_retryable_error(self, retry_handler):
        """Should not retry non-retryable errors."""
        func = AsyncMock(side_effect=ValueError("Parse error"))

        with pytest.raises(ValueError, match="Parse error"):
            await retry_handler.execute(func, "test-source", "test-op")

        func.assert_called_once()

    async def test_execute_raises_after_max_retries(self, retry_handler):
        """Should raise after max retries exhausted."""
        func = AsyncMock(side_effect=httpx.ConnectError("Always fails"))

        with pytest.raises(httpx.ConnectError, match="Always fails"):
            await retry_handler.execute(func, "test-source", "test-op")

        # Initial call + 3 retries = 4 total
        assert func.call_count == 4

    async def test_execute_with_circuit_breaker(self):
        """Should integrate with circuit breaker."""
        config = RetryConfig(max_retries=0)  # No retries
        circuit_breaker = CircuitBreaker(failure_threshold=1)
        handler = RetryHandler(config, circuit_breaker)

        func = AsyncMock(side_effect=httpx.ConnectError("Fail"))

        # First call should fail and record failure
        with pytest.raises(httpx.ConnectError):
            await handler.execute(func, "test-source", "test-op")

        # Circuit should now be open
        assert circuit_breaker.state == CircuitBreaker.State.OPEN

        # Second call should fail with circuit open error
        with pytest.raises(CollectorCircuitOpenError):
            await handler.execute(func, "test-source", "test-op")

    async def test_execute_records_success_with_circuit_breaker(self):
        """Should record success with circuit breaker."""
        circuit_breaker = CircuitBreaker()
        handler = RetryHandler(circuit_breaker=circuit_breaker)

        # Record some failures (but not enough to open)
        circuit_breaker._failure_count = 4

        func = AsyncMock(return_value="success")

        await handler.execute(func, "test-source", "test-op")

        # Failure count should be reset
        assert circuit_breaker._failure_count == 0


class TestWithRetryDecorator:
    """Tests for the @with_retry decorator."""

    async def test_decorator_adds_retry_logic(self):
        """Should add retry logic to decorated method."""
        call_count = 0

        class TestCollector:
            source_id = "test-source"

            @with_retry(max_retries=2, initial_delay=0.01, max_delay=0.1)
            async def fetch(self):
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise httpx.ConnectError("Fail")
                return "success"

        collector = TestCollector()
        result = await collector.fetch()

        assert result == "success"
        assert call_count == 3


class TestErrorTracker:
    """Tests for the ErrorTracker class."""

    @pytest.fixture
    def error_tracker(self):
        """Create an error tracker for testing."""
        return ErrorTracker(max_errors=10, error_window_minutes=60)

    async def test_record_error(self, error_tracker):
        """Should record errors."""
        error = CollectorError(
            category=ErrorCategory.NETWORK,
            message="Test error",
            source_id="test-source",
        )

        await error_tracker.record_error(error)
        errors = await error_tracker.get_recent_errors()

        assert len(errors) == 1
        assert errors[0] == error

    async def test_trims_old_errors_at_max(self, error_tracker):
        """Should trim errors when exceeding max_errors."""
        for i in range(15):
            error = CollectorError(
                category=ErrorCategory.NETWORK,
                message=f"Error {i}",
                source_id="test-source",
            )
            await error_tracker.record_error(error)

        errors = await error_tracker.get_recent_errors()

        assert len(errors) == 10
        # Should keep the most recent 10 (5-14)
        assert errors[0].message == "Error 5"
        assert errors[-1].message == "Error 14"

    async def test_get_recent_errors_with_minutes_filter(self, error_tracker):
        """Should filter errors by time window."""
        # Old error
        old_error = CollectorError(
            category=ErrorCategory.NETWORK,
            message="Old error",
            source_id="test-source",
        )
        old_error.timestamp = datetime.now(timezone.utc) - timedelta(minutes=10)
        await error_tracker.record_error(old_error)

        # Recent error
        recent_error = CollectorError(
            category=ErrorCategory.NETWORK,
            message="Recent error",
            source_id="test-source",
        )
        await error_tracker.record_error(recent_error)

        # Filter to last 5 minutes
        errors = await error_tracker.get_recent_errors(minutes=5)

        assert len(errors) == 1
        assert errors[0].message == "Recent error"

    async def test_get_error_rate(self, error_tracker):
        """Should calculate error rate per minute."""
        # Add 5 errors
        for i in range(5):
            error = CollectorError(
                category=ErrorCategory.NETWORK,
                message=f"Error {i}",
                source_id="test-source",
            )
            await error_tracker.record_error(error)

        rate = await error_tracker.get_error_rate(minutes=5)

        assert rate == 1.0  # 5 errors / 5 minutes

    async def test_get_error_summary(self, error_tracker):
        """Should generate error summary."""
        # Add different types of errors
        errors = [
            CollectorError(ErrorCategory.NETWORK, "Network error 1", "test-source"),
            CollectorError(ErrorCategory.NETWORK, "Network error 2", "test-source"),
            CollectorError(ErrorCategory.AUTH, "Auth error", "test-source"),
            CollectorError(ErrorCategory.SERVER, "Server error", "test-source"),
        ]

        for error in errors:
            await error_tracker.record_error(error)

        summary = await error_tracker.get_error_summary()

        assert summary["total_errors_last_hour"] == 4
        assert summary["errors_by_category"]["network"] == 2
        assert summary["errors_by_category"]["auth"] == 1
        assert summary["errors_by_category"]["server"] == 1
        assert summary["last_error"]["message"] == "Server error"

    async def test_get_error_summary_empty(self, error_tracker):
        """Should handle empty error list."""
        summary = await error_tracker.get_error_summary()

        assert summary["total_errors_last_hour"] == 0
        assert summary["errors_by_category"] == {}
        assert summary["last_error"] is None

    def test_clear(self, error_tracker):
        """Should clear all tracked errors."""
        error_tracker._errors = [
            CollectorError(ErrorCategory.NETWORK, "Error", "test-source")
        ]

        error_tracker.clear()

        assert len(error_tracker._errors) == 0


class TestCollectorCircuitOpenError:
    """Tests for the CollectorCircuitOpenError exception."""

    def test_creates_with_message(self):
        """Should create exception with message."""
        error = CollectorCircuitOpenError("Circuit open for test-source")

        assert str(error) == "Circuit open for test-source"
        assert isinstance(error, Exception)
