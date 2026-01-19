"""Shared HTTP client pool for efficient connection reuse.

This module provides a centralized HTTP client management system to avoid
creating new connections for each request, improving performance and
reducing resource usage.
"""

from typing import Dict, Optional

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()


class HttpClientPool:
    """Manages a pool of HTTP clients for different services.

    Each service (identified by a unique key) gets its own client with
    connection pooling enabled. Clients are reused across requests.
    """

    def __init__(self):
        """Initialize the client pool."""
        self._clients: Dict[str, httpx.AsyncClient] = {}

    def _create_limits(self) -> httpx.Limits:
        """Create connection limits from settings."""
        return httpx.Limits(
            max_connections=settings.http_max_connections,
            max_keepalive_connections=settings.http_max_connections // 2,
            keepalive_expiry=settings.http_keepalive_expiry,
        )

    def _create_timeout(self) -> httpx.Timeout:
        """Create timeout configuration from settings."""
        return httpx.Timeout(
            timeout=settings.http_timeout_seconds,
            connect=10.0,  # Connection timeout
        )

    async def get_client(
        self,
        key: str,
        base_url: Optional[str] = None,
        auth: Optional[tuple] = None,
        verify: bool = True,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.AsyncClient:
        """Get or create an HTTP client for the given service key.

        Args:
            key: Unique identifier for the service (e.g., "adguard", "unifi")
            base_url: Optional base URL for the client
            auth: Optional basic auth tuple (username, password)
            verify: Whether to verify SSL certificates
            headers: Optional default headers

        Returns:
            An httpx.AsyncClient instance configured for the service
        """
        if key not in self._clients or self._clients[key].is_closed:
            logger.debug(
                "Creating new HTTP client",
                key=key,
                base_url=base_url,
            )

            client_kwargs = {
                "limits": self._create_limits(),
                "timeout": self._create_timeout(),
                "verify": verify,
            }

            if base_url:
                client_kwargs["base_url"] = base_url
            if auth:
                client_kwargs["auth"] = auth
            if headers:
                client_kwargs["headers"] = headers

            self._clients[key] = httpx.AsyncClient(**client_kwargs)

        return self._clients[key]

    async def close_client(self, key: str) -> None:
        """Close a specific client.

        Args:
            key: The service key of the client to close
        """
        if key in self._clients:
            client = self._clients.pop(key)
            if not client.is_closed:
                await client.aclose()
                logger.debug("Closed HTTP client", key=key)

    async def close_all(self) -> None:
        """Close all clients in the pool."""
        for key in list(self._clients.keys()):
            await self.close_client(key)
        logger.info("Closed all HTTP clients")

    @property
    def active_clients(self) -> int:
        """Return the number of active clients."""
        return sum(1 for c in self._clients.values() if not c.is_closed)


# Global client pool instance
_client_pool: Optional[HttpClientPool] = None


def get_http_client_pool() -> HttpClientPool:
    """Get the global HTTP client pool instance."""
    global _client_pool
    if _client_pool is None:
        _client_pool = HttpClientPool()
    return _client_pool


async def close_http_client_pool() -> None:
    """Close the global HTTP client pool."""
    global _client_pool
    if _client_pool is not None:
        await _client_pool.close_all()
        _client_pool = None
