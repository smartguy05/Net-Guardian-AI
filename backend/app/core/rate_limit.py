"""Rate limiting utilities for API endpoints.

This module provides rate limiting to protect against brute force attacks
and API abuse.
"""

import time
from dataclasses import dataclass

import structlog
from fastapi import HTTPException, Request, status

logger = structlog.get_logger()


@dataclass
class RateLimitEntry:
    """Track rate limit state for a client."""

    count: int
    window_start: float
    blocked_until: float | None = None


class RateLimiter:
    """In-memory rate limiter for API endpoints.

    For production, consider using Redis-based rate limiting for
    distributed deployments.
    """

    def __init__(
        self,
        requests_per_window: int = 10,
        window_seconds: int = 60,
        block_seconds: int = 300,
    ):
        """Initialize the rate limiter.

        Args:
            requests_per_window: Max requests allowed per time window
            window_seconds: Size of the time window in seconds
            block_seconds: How long to block after exceeding limit
        """
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds
        self._entries: dict[str, RateLimitEntry] = {}

    def _get_client_key(self, request: Request) -> str:
        """Get a unique key for the client.

        Uses X-Forwarded-For if behind a proxy, otherwise client host.
        """
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Get the first IP in the chain (original client)
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _cleanup_old_entries(self) -> None:
        """Remove expired entries to prevent memory leaks."""
        now = time.time()
        cutoff = now - (self.window_seconds * 10)  # Keep 10 windows of history

        expired_keys = [
            key
            for key, entry in self._entries.items()
            if entry.window_start < cutoff
            and (entry.blocked_until is None or entry.blocked_until < now)
        ]

        for key in expired_keys:
            del self._entries[key]

    def check(self, request: Request) -> None:
        """Check if request should be rate limited.

        Args:
            request: The incoming FastAPI request

        Raises:
            HTTPException: If rate limit exceeded (429 Too Many Requests)
        """
        client_key = self._get_client_key(request)
        now = time.time()

        # Periodic cleanup
        if len(self._entries) > 1000:
            self._cleanup_old_entries()

        entry = self._entries.get(client_key)

        if entry:
            # Check if currently blocked
            if entry.blocked_until and entry.blocked_until > now:
                retry_after = int(entry.blocked_until - now)
                logger.warning(
                    "Rate limit block active",
                    client=client_key,
                    retry_after=retry_after,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many requests. Try again in {retry_after} seconds.",
                    headers={"Retry-After": str(retry_after)},
                )

            # Check if window has expired
            if now - entry.window_start > self.window_seconds:
                # Start new window
                entry.count = 1
                entry.window_start = now
                entry.blocked_until = None
            else:
                # Increment counter
                entry.count += 1

                # Check if limit exceeded
                if entry.count > self.requests_per_window:
                    entry.blocked_until = now + self.block_seconds
                    logger.warning(
                        "Rate limit exceeded",
                        client=client_key,
                        count=entry.count,
                        block_seconds=self.block_seconds,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Too many requests. Try again in {self.block_seconds} seconds.",
                        headers={"Retry-After": str(self.block_seconds)},
                    )
        else:
            # First request from this client
            self._entries[client_key] = RateLimitEntry(
                count=1,
                window_start=now,
            )

    def reset(self, request: Request) -> None:
        """Reset rate limit for a client (e.g., after successful login).

        Args:
            request: The FastAPI request to reset limits for
        """
        client_key = self._get_client_key(request)
        if client_key in self._entries:
            del self._entries[client_key]


# Pre-configured rate limiters for different endpoints
login_rate_limiter = RateLimiter(
    requests_per_window=5,  # 5 login attempts
    window_seconds=60,  # per minute
    block_seconds=300,  # 5 minute block
)

api_rate_limiter = RateLimiter(
    requests_per_window=100,  # 100 requests
    window_seconds=60,  # per minute
    block_seconds=60,  # 1 minute block
)

ingest_rate_limiter = RateLimiter(
    requests_per_window=1000,  # 1000 events
    window_seconds=60,  # per minute
    block_seconds=60,  # 1 minute block
)
