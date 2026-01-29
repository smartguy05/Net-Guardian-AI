"""Redis-based caching layer for API responses.

This module provides caching utilities to reduce database load for
frequently-accessed data like device lists, event summaries, and stats.
"""

import json
from collections.abc import Awaitable, Callable
from datetime import timedelta
from functools import wraps
from typing import Any, ParamSpec, TypeVar, cast

import structlog
from redis.asyncio import Redis

logger = structlog.get_logger()

T = TypeVar("T")
P = ParamSpec("P")

# Default TTLs for different cache types
CACHE_TTL_SHORT = timedelta(seconds=30)  # For real-time data
CACHE_TTL_MEDIUM = timedelta(minutes=5)  # For list endpoints
CACHE_TTL_LONG = timedelta(minutes=30)  # For stats and summaries


class CacheService:
    """Redis-based caching service for API responses."""

    def __init__(self, redis: Redis, prefix: str = "netguardian:cache"):
        """Initialize the cache service.

        Args:
            redis: Redis client instance
            prefix: Key prefix for all cache entries
        """
        self._redis = redis
        self._prefix = prefix
        self._enabled = True

    def _make_key(self, key: str) -> str:
        """Create a full cache key with prefix."""
        return f"{self._prefix}:{key}"

    async def get(self, key: str) -> Any | None:
        """Get a value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        if not self._enabled:
            return None

        try:
            full_key = self._make_key(key)
            data = await self._redis.get(full_key)
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.warning("Cache get failed", key=key, error=str(e))
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: int | timedelta = CACHE_TTL_MEDIUM,
    ) -> bool:
        """Set a value in cache.

        Args:
            key: Cache key
            value: Value to cache (must be JSON serializable)
            ttl: Time to live (seconds or timedelta)

        Returns:
            True if successful, False otherwise
        """
        if not self._enabled:
            return False

        try:
            full_key = self._make_key(key)
            data = json.dumps(value, default=str)

            if isinstance(ttl, timedelta):
                ttl_seconds = int(ttl.total_seconds())
            else:
                ttl_seconds = ttl

            await self._redis.setex(full_key, ttl_seconds, data)
            return True
        except Exception as e:
            logger.warning("Cache set failed", key=key, error=str(e))
            return False

    async def delete(self, key: str) -> bool:
        """Delete a value from cache.

        Args:
            key: Cache key

        Returns:
            True if successful, False otherwise
        """
        try:
            full_key = self._make_key(key)
            await self._redis.delete(full_key)
            return True
        except Exception as e:
            logger.warning("Cache delete failed", key=key, error=str(e))
            return False

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern.

        Args:
            pattern: Key pattern (e.g., "devices:*")

        Returns:
            Number of keys deleted
        """
        try:
            full_pattern = self._make_key(pattern)
            keys = []
            async for key in self._redis.scan_iter(match=full_pattern):
                keys.append(key)

            if keys:
                await self._redis.delete(*keys)
                logger.debug("Cache pattern delete", pattern=pattern, count=len(keys))

            return len(keys)
        except Exception as e:
            logger.warning("Cache pattern delete failed", pattern=pattern, error=str(e))
            return 0

    async def invalidate_devices(self) -> int:
        """Invalidate all device-related cache entries."""
        return await self.delete_pattern("devices:*")

    async def invalidate_events(self) -> int:
        """Invalidate all event-related cache entries."""
        return await self.delete_pattern("events:*")

    async def invalidate_alerts(self) -> int:
        """Invalidate all alert-related cache entries."""
        return await self.delete_pattern("alerts:*")

    async def invalidate_stats(self) -> int:
        """Invalidate all stats-related cache entries."""
        return await self.delete_pattern("stats:*")


# Global cache service instance
_cache_service: CacheService | None = None


def get_cache_service() -> CacheService | None:
    """Get the global cache service instance."""
    return _cache_service


def set_cache_service(cache: CacheService) -> None:
    """Set the global cache service instance."""
    global _cache_service
    _cache_service = cache


def cached(
    key_template: str,
    ttl: int | timedelta = CACHE_TTL_MEDIUM,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Decorator to cache function results.

    Args:
        key_template: Cache key template with {param} placeholders
        ttl: Time to live for cached value

    Example:
        @cached("devices:list:{page}:{limit}", ttl=CACHE_TTL_MEDIUM)
        async def list_devices(page: int, limit: int):
            ...
    """

    def decorator(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            cache = get_cache_service()
            if cache is None:
                return await func(*args, **kwargs)

            # Build cache key from template and kwargs
            try:
                cache_key = key_template.format(**kwargs)
            except KeyError:
                # If key can't be built, skip caching
                return await func(*args, **kwargs)

            # Try to get from cache
            cached_value = await cache.get(cache_key)
            if cached_value is not None:
                logger.debug("Cache hit", key=cache_key)
                return cast(T, cached_value)

            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache.set(cache_key, result, ttl)
            logger.debug("Cache miss - stored", key=cache_key)

            return result

        return wrapper

    return decorator
