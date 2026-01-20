"""API rate limiting middleware and utilities.

Provides:
- Token bucket rate limiting
- Redis-backed distributed rate limiting
- Per-user and per-IP rate limits
- Configurable limits per endpoint
"""

import asyncio
import time
from dataclasses import dataclass
from functools import wraps
from typing import Callable, Optional

import structlog
from fastapi import HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.services.metrics_service import (
    HTTP_REQUESTS_TOTAL,
)

logger = structlog.get_logger()


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_size: int = 10  # Allow burst of requests
    key_prefix: str = "ratelimit"


# Default rate limits for different endpoint categories
DEFAULT_LIMITS = {
    "default": RateLimitConfig(requests_per_minute=60, requests_per_hour=1000),
    "auth": RateLimitConfig(requests_per_minute=10, requests_per_hour=100),
    "chat": RateLimitConfig(requests_per_minute=20, requests_per_hour=200),
    "export": RateLimitConfig(requests_per_minute=5, requests_per_hour=50),
    "webhook": RateLimitConfig(requests_per_minute=100, requests_per_hour=3000),
    "admin": RateLimitConfig(requests_per_minute=30, requests_per_hour=300),
}


class TokenBucket:
    """In-memory token bucket rate limiter.

    Used as fallback when Redis is unavailable.
    """

    def __init__(
        self,
        capacity: int,
        refill_rate: float,
    ):
        """Initialize token bucket.

        Args:
            capacity: Maximum tokens in bucket.
            refill_rate: Tokens added per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket.

        Args:
            tokens: Number of tokens to consume.

        Returns:
            True if tokens were consumed, False if rate limited.
        """
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill

            # Refill tokens
            self.tokens = min(
                self.capacity,
                self.tokens + elapsed * self.refill_rate,
            )
            self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def get_wait_time(self, tokens: int = 1) -> float:
        """Get time to wait before tokens are available.

        Args:
            tokens: Number of tokens needed.

        Returns:
            Seconds to wait.
        """
        async with self._lock:
            if self.tokens >= tokens:
                return 0
            needed = tokens - self.tokens
            return needed / self.refill_rate


class InMemoryRateLimiter:
    """In-memory rate limiter for single-instance deployments."""

    def __init__(self):
        """Initialize the rate limiter."""
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def _get_bucket(self, key: str, config: RateLimitConfig) -> TokenBucket:
        """Get or create a token bucket for the key."""
        if key not in self._buckets:
            # Convert requests per minute to tokens per second
            refill_rate = config.requests_per_minute / 60.0
            self._buckets[key] = TokenBucket(
                capacity=config.burst_size + config.requests_per_minute,
                refill_rate=refill_rate,
            )
        return self._buckets[key]

    async def is_allowed(
        self,
        key: str,
        config: Optional[RateLimitConfig] = None,
    ) -> tuple[bool, dict]:
        """Check if request is allowed.

        Args:
            key: Unique identifier (user_id, IP, etc.).
            config: Rate limit configuration.

        Returns:
            Tuple of (allowed, headers_dict).
        """
        config = config or DEFAULT_LIMITS["default"]

        async with self._lock:
            bucket = self._get_bucket(key, config)

        allowed = await bucket.consume()

        headers = {
            "X-RateLimit-Limit": str(config.requests_per_minute),
            "X-RateLimit-Remaining": str(max(0, int(bucket.tokens))),
            "X-RateLimit-Reset": str(int(time.time() + 60)),
        }

        if not allowed:
            headers["Retry-After"] = str(int(await bucket.get_wait_time()))

        return allowed, headers

    async def cleanup(self, max_age_seconds: int = 3600) -> int:
        """Remove old buckets to free memory.

        Args:
            max_age_seconds: Remove buckets not used for this long.

        Returns:
            Number of buckets removed.
        """
        async with self._lock:
            now = time.time()
            to_remove = [
                key
                for key, bucket in self._buckets.items()
                if now - bucket.last_refill > max_age_seconds
            ]
            for key in to_remove:
                del self._buckets[key]
            return len(to_remove)


class RedisRateLimiter:
    """Redis-backed rate limiter for distributed deployments."""

    def __init__(self, redis_client):
        """Initialize with Redis client.

        Args:
            redis_client: Async Redis client.
        """
        self.redis = redis_client

    async def is_allowed(
        self,
        key: str,
        config: Optional[RateLimitConfig] = None,
    ) -> tuple[bool, dict]:
        """Check if request is allowed using Redis.

        Uses sliding window counter algorithm.

        Args:
            key: Unique identifier.
            config: Rate limit configuration.

        Returns:
            Tuple of (allowed, headers_dict).
        """
        config = config or DEFAULT_LIMITS["default"]

        now = time.time()
        window_start = int(now // 60) * 60  # Current minute
        redis_key = f"{config.key_prefix}:{key}:{window_start}"

        try:
            # Increment counter and get current value
            pipe = self.redis.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, 120)  # Expire after 2 minutes
            results = await pipe.execute()

            current_count = results[0]
            remaining = max(0, config.requests_per_minute - current_count)
            allowed = current_count <= config.requests_per_minute

            headers = {
                "X-RateLimit-Limit": str(config.requests_per_minute),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(window_start + 60),
            }

            if not allowed:
                headers["Retry-After"] = str(int(window_start + 60 - now))

            return allowed, headers

        except Exception as e:
            logger.warning("redis_rate_limit_error", error=str(e))
            # Fail open - allow the request if Redis fails
            return True, {}


def get_endpoint_category(path: str) -> str:
    """Determine rate limit category from path.

    Args:
        path: Request path.

    Returns:
        Category name.
    """
    if "/auth" in path:
        return "auth"
    if "/chat" in path:
        return "chat"
    if "/export" in path:
        return "export"
    if "/admin" in path:
        return "admin"
    if "/logs" in path or "/webhook" in path:
        return "webhook"
    return "default"


def get_rate_limit_key(request: Request) -> str:
    """Get rate limit key from request.

    Uses user ID if authenticated, otherwise client IP.

    Args:
        request: The FastAPI request.

    Returns:
        Rate limit key.
    """
    # Check for authenticated user
    user = getattr(request.state, "user", None)
    if user:
        return f"user:{user.id}"

    # Fall back to IP address
    client_ip = request.client.host if request.client else "unknown"

    # Check for proxy headers
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Use first IP in chain
        client_ip = forwarded_for.split(",")[0].strip()

    return f"ip:{client_ip}"


# Global rate limiter instance
_rate_limiter: Optional[InMemoryRateLimiter] = None


def get_rate_limiter() -> InMemoryRateLimiter:
    """Get or create the rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = InMemoryRateLimiter()
    return _rate_limiter


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting."""

    def __init__(
        self,
        app,
        enabled: bool = True,
        exclude_paths: Optional[list[str]] = None,
    ):
        """Initialize middleware.

        Args:
            app: FastAPI application.
            enabled: Whether rate limiting is enabled.
            exclude_paths: Paths to exclude from rate limiting.
        """
        super().__init__(app)
        self.enabled = enabled
        self.exclude_paths = exclude_paths or [
            "/health",
            "/metrics",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request with rate limiting."""
        # Skip if disabled
        if not self.enabled:
            return await call_next(request)

        # Skip excluded paths
        path = request.url.path
        if any(path.startswith(exc) for exc in self.exclude_paths):
            return await call_next(request)

        # Get rate limit configuration
        category = get_endpoint_category(path)
        config = DEFAULT_LIMITS.get(category, DEFAULT_LIMITS["default"])

        # Get rate limit key
        key = get_rate_limit_key(request)

        # Check rate limit
        limiter = get_rate_limiter()
        allowed, headers = await limiter.is_allowed(f"{category}:{key}", config)

        if not allowed:
            logger.warning(
                "rate_limit_exceeded",
                key=key,
                category=category,
                path=path,
            )
            response = Response(
                content='{"detail": "Rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
            )
            for name, value in headers.items():
                response.headers[name] = value
            return response

        # Process request
        response = await call_next(request)

        # Add rate limit headers
        for name, value in headers.items():
            response.headers[name] = value

        return response


def rate_limit(
    requests_per_minute: int = 60,
    key_func: Optional[Callable[[Request], str]] = None,
):
    """Decorator for rate limiting specific endpoints.

    Args:
        requests_per_minute: Maximum requests per minute.
        key_func: Function to get rate limit key from request.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            # Get key
            if key_func:
                key = key_func(request)
            else:
                key = get_rate_limit_key(request)

            # Check rate limit
            config = RateLimitConfig(requests_per_minute=requests_per_minute)
            limiter = get_rate_limiter()
            allowed, headers = await limiter.is_allowed(
                f"endpoint:{func.__name__}:{key}",
                config,
            )

            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded",
                    headers=headers,
                )

            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


async def cleanup_rate_limiters() -> None:
    """Periodic cleanup of rate limiter buckets."""
    limiter = get_rate_limiter()
    if isinstance(limiter, InMemoryRateLimiter):
        removed = await limiter.cleanup()
        if removed > 0:
            logger.debug("rate_limiter_cleanup", removed_buckets=removed)
