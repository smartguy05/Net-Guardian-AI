"""Comprehensive error handling and retry logic for collectors.

Provides:
- Retry mechanism with exponential backoff
- Circuit breaker pattern
- Error categorization and tracking
- Metrics integration
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

import httpx
import structlog

from app.services.metrics_service import (
    COLLECTOR_ERRORS_TOTAL,
    COLLECTOR_RETRIES_TOTAL,
)

logger = structlog.get_logger()

T = TypeVar("T")


class ErrorCategory(str, Enum):
    """Categories of collector errors."""

    NETWORK = "network"  # Connection errors, timeouts
    AUTH = "auth"  # Authentication failures
    RATE_LIMIT = "rate_limit"  # Rate limiting
    SERVER = "server"  # Server errors (5xx)
    CLIENT = "client"  # Client errors (4xx)
    PARSE = "parse"  # Parsing errors
    CONFIG = "config"  # Configuration errors
    RESOURCE = "resource"  # Resource exhaustion
    UNKNOWN = "unknown"  # Unknown errors


@dataclass
class CollectorError:
    """Structured collector error."""

    category: ErrorCategory
    message: str
    source_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retryable: bool = True
    details: dict = field(default_factory=dict)
    original_exception: Optional[Exception] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for logging/storage."""
        return {
            "category": self.category.value,
            "message": self.message,
            "source_id": self.source_id,
            "timestamp": self.timestamp.isoformat(),
            "retryable": self.retryable,
            "details": self.details,
        }


def categorize_error(error: Exception) -> tuple[ErrorCategory, bool]:
    """Categorize an exception and determine if it's retryable.

    Returns:
        Tuple of (category, is_retryable).
    """
    # Network errors - usually transient
    if isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout)):
        return ErrorCategory.NETWORK, True

    if isinstance(error, httpx.TimeoutException):
        return ErrorCategory.NETWORK, True

    # HTTP status errors
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code

        if status == 401 or status == 403:
            return ErrorCategory.AUTH, False  # Auth errors need config fix

        if status == 429:
            return ErrorCategory.RATE_LIMIT, True  # Rate limits are transient

        if 400 <= status < 500:
            return ErrorCategory.CLIENT, False  # Client errors need config fix

        if 500 <= status < 600:
            return ErrorCategory.SERVER, True  # Server errors may be transient

    # File errors
    if isinstance(error, FileNotFoundError):
        return ErrorCategory.CONFIG, False

    if isinstance(error, PermissionError):
        return ErrorCategory.CONFIG, False

    # Parsing errors
    if isinstance(error, (ValueError, KeyError, TypeError)):
        return ErrorCategory.PARSE, False

    # Resource errors
    if isinstance(error, (MemoryError, asyncio.QueueFull)):
        return ErrorCategory.RESOURCE, True

    # Connection errors (general)
    if isinstance(error, (ConnectionError, OSError)):
        return ErrorCategory.NETWORK, True

    return ErrorCategory.UNKNOWN, True


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_retries: int = 3
    initial_delay: float = 1.0  # seconds
    max_delay: float = 60.0  # seconds
    exponential_base: float = 2.0
    jitter: float = 0.1  # Add randomness to prevent thundering herd


class CircuitBreaker:
    """Circuit breaker to prevent overwhelming failed services.

    States:
    - CLOSED: Normal operation, requests go through
    - OPEN: Service is failing, requests are rejected
    - HALF_OPEN: Testing if service has recovered
    """

    class State(str, Enum):
        CLOSED = "closed"
        OPEN = "open"
        HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
    ):
        """Initialize circuit breaker.

        Args:
            failure_threshold: Failures before opening circuit.
            recovery_timeout: Seconds before trying half-open.
            half_open_max_calls: Test calls in half-open state.
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = self.State.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> State:
        """Get current circuit breaker state."""
        return self._state

    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (allowing requests)."""
        return self._state == self.State.CLOSED

    async def record_success(self) -> None:
        """Record a successful call."""
        async with self._lock:
            if self._state == self.State.HALF_OPEN:
                self._half_open_calls += 1
                if self._half_open_calls >= self.half_open_max_calls:
                    # Recovered - close the circuit
                    self._state = self.State.CLOSED
                    self._failure_count = 0
                    self._half_open_calls = 0
                    logger.info("circuit_breaker_closed", reason="recovery_confirmed")
            elif self._state == self.State.CLOSED:
                # Reset failure count on success
                self._failure_count = 0

    async def record_failure(self) -> None:
        """Record a failed call."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = datetime.now(timezone.utc)

            if self._state == self.State.HALF_OPEN:
                # Failed during recovery test - reopen
                self._state = self.State.OPEN
                self._half_open_calls = 0
                logger.warning("circuit_breaker_reopened", reason="half_open_failure")

            elif self._state == self.State.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    self._state = self.State.OPEN
                    logger.warning(
                        "circuit_breaker_opened",
                        failure_count=self._failure_count,
                        threshold=self.failure_threshold,
                    )

    async def can_proceed(self) -> bool:
        """Check if a request can proceed.

        Returns:
            True if request should proceed, False if rejected.
        """
        async with self._lock:
            if self._state == self.State.CLOSED:
                return True

            if self._state == self.State.OPEN:
                # Check if recovery timeout has passed
                if self._last_failure_time:
                    elapsed = (
                        datetime.now(timezone.utc) - self._last_failure_time
                    ).total_seconds()
                    if elapsed >= self.recovery_timeout:
                        # Try half-open
                        self._state = self.State.HALF_OPEN
                        self._half_open_calls = 0
                        logger.info("circuit_breaker_half_open")
                        return True
                return False

            # HALF_OPEN - allow limited calls
            return self._half_open_calls < self.half_open_max_calls

    def reset(self) -> None:
        """Reset the circuit breaker to closed state."""
        self._state = self.State.CLOSED
        self._failure_count = 0
        self._last_failure_time = None
        self._half_open_calls = 0


class RetryHandler:
    """Handles retry logic with exponential backoff."""

    def __init__(
        self,
        config: Optional[RetryConfig] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
    ):
        """Initialize retry handler.

        Args:
            config: Retry configuration.
            circuit_breaker: Optional circuit breaker.
        """
        self.config = config or RetryConfig()
        self.circuit_breaker = circuit_breaker

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for a given retry attempt.

        Uses exponential backoff with jitter.

        Args:
            attempt: Current retry attempt (0-indexed).

        Returns:
            Delay in seconds.
        """
        import random

        delay = self.config.initial_delay * (
            self.config.exponential_base ** attempt
        )
        delay = min(delay, self.config.max_delay)

        # Add jitter
        jitter_range = delay * self.config.jitter
        delay += random.uniform(-jitter_range, jitter_range)

        return max(0, delay)

    async def execute(
        self,
        func: Callable[[], T],
        source_id: str,
        operation_name: str = "operation",
    ) -> T:
        """Execute a function with retry logic.

        Args:
            func: Async function to execute.
            source_id: Source identifier for logging.
            operation_name: Name of operation for logging.

        Returns:
            Result of the function.

        Raises:
            The last exception if all retries fail.
        """
        last_error: Optional[Exception] = None
        attempts = 0

        while attempts <= self.config.max_retries:
            # Check circuit breaker
            if self.circuit_breaker and not await self.circuit_breaker.can_proceed():
                raise CollectorCircuitOpenError(
                    f"Circuit breaker open for {source_id}"
                )

            try:
                result = await func()

                # Record success with circuit breaker
                if self.circuit_breaker:
                    await self.circuit_breaker.record_success()

                return result

            except Exception as e:
                last_error = e
                category, retryable = categorize_error(e)

                # Record metrics
                COLLECTOR_ERRORS_TOTAL.labels(
                    source_id=source_id,
                    error_type=category.value,
                ).inc()

                # Record failure with circuit breaker
                if self.circuit_breaker:
                    await self.circuit_breaker.record_failure()

                # Log the error
                logger.warning(
                    "collector_operation_failed",
                    source_id=source_id,
                    operation=operation_name,
                    attempt=attempts + 1,
                    max_retries=self.config.max_retries,
                    error_category=category.value,
                    retryable=retryable,
                    error=str(e),
                )

                # Don't retry non-retryable errors
                if not retryable:
                    break

                attempts += 1

                # Check if we have retries left
                if attempts <= self.config.max_retries:
                    delay = self.calculate_delay(attempts - 1)
                    COLLECTOR_RETRIES_TOTAL.labels(source_id=source_id).inc()
                    logger.debug(
                        "collector_retry_scheduled",
                        source_id=source_id,
                        operation=operation_name,
                        attempt=attempts,
                        delay=delay,
                    )
                    await asyncio.sleep(delay)

        # All retries exhausted
        logger.error(
            "collector_operation_failed_permanently",
            source_id=source_id,
            operation=operation_name,
            total_attempts=attempts,
            error=str(last_error),
        )

        if last_error:
            raise last_error
        raise RuntimeError(f"Operation {operation_name} failed unexpectedly")


class CollectorCircuitOpenError(Exception):
    """Raised when circuit breaker is open."""

    pass


def with_retry(
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 60.0,
):
    """Decorator for adding retry logic to async methods.

    Args:
        max_retries: Maximum retry attempts.
        initial_delay: Initial delay between retries.
        max_delay: Maximum delay between retries.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            config = RetryConfig(
                max_retries=max_retries,
                initial_delay=initial_delay,
                max_delay=max_delay,
            )
            handler = RetryHandler(config)

            source_id = getattr(self, "source_id", "unknown")
            operation_name = func.__name__

            async def call():
                return await func(self, *args, **kwargs)

            return await handler.execute(call, source_id, operation_name)

        return wrapper

    return decorator


class ErrorTracker:
    """Tracks errors for a collector with automatic recovery detection."""

    def __init__(
        self,
        max_errors: int = 100,
        error_window_minutes: int = 60,
    ):
        """Initialize error tracker.

        Args:
            max_errors: Maximum errors to store.
            error_window_minutes: Window for error rate calculation.
        """
        self.max_errors = max_errors
        self.error_window = timedelta(minutes=error_window_minutes)
        self._errors: list[CollectorError] = []
        self._lock = asyncio.Lock()

    async def record_error(self, error: CollectorError) -> None:
        """Record an error."""
        async with self._lock:
            self._errors.append(error)

            # Trim old errors
            if len(self._errors) > self.max_errors:
                self._errors = self._errors[-self.max_errors :]

    async def get_recent_errors(
        self,
        minutes: Optional[int] = None,
    ) -> list[CollectorError]:
        """Get recent errors.

        Args:
            minutes: Only return errors from last N minutes.

        Returns:
            List of recent errors.
        """
        async with self._lock:
            if minutes is None:
                return list(self._errors)

            cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
            return [e for e in self._errors if e.timestamp >= cutoff]

    async def get_error_rate(self, minutes: int = 5) -> float:
        """Get error rate per minute.

        Args:
            minutes: Time window to calculate rate.

        Returns:
            Errors per minute.
        """
        errors = await self.get_recent_errors(minutes)
        return len(errors) / minutes if minutes > 0 else 0

    async def get_error_summary(self) -> dict:
        """Get a summary of error statistics."""
        errors = await self.get_recent_errors(60)  # Last hour

        by_category: dict[str, int] = {}
        for error in errors:
            by_category[error.category.value] = (
                by_category.get(error.category.value, 0) + 1
            )

        return {
            "total_errors_last_hour": len(errors),
            "error_rate_per_minute": await self.get_error_rate(5),
            "errors_by_category": by_category,
            "last_error": errors[-1].to_dict() if errors else None,
        }

    def clear(self) -> None:
        """Clear all tracked errors."""
        self._errors.clear()
