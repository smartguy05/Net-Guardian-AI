"""Base collector interface for data collection."""

from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from typing import Any

import structlog

from app.models.log_source import LogSource
from app.parsers.base import BaseParser, ParseResult

logger = structlog.get_logger()


class BaseCollector(ABC):
    """Abstract base class for log collectors.

    Collectors are responsible for fetching raw log data from various
    sources (APIs, files, etc.) and passing it to parsers for normalization.
    """

    def __init__(
        self,
        source: LogSource,
        parser: BaseParser,
    ):
        """Initialize the collector.

        Args:
            source: The log source configuration.
            parser: The parser to use for normalizing events.
        """
        self.source = source
        self.parser = parser
        self._running = False

    @property
    def source_id(self) -> str:
        """Get the source ID."""
        return self.source.id

    @property
    def config(self) -> dict[str, Any]:
        """Get the source configuration."""
        return self.source.config

    @abstractmethod
    async def collect(self) -> AsyncGenerator[ParseResult, None]:
        """Collect and parse events from the source.

        Yields:
            Parsed events.
        """
        yield  # type: ignore

    @abstractmethod
    async def start(self) -> None:
        """Start the collector.

        For polling collectors, this starts the polling loop.
        For file collectors, this starts watching the file.
        """
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the collector gracefully."""
        pass

    async def test_connection(self) -> tuple[bool, str]:
        """Test the connection to the source.

        Returns:
            Tuple of (success, message).
        """
        return True, "Connection test not implemented"

    def is_running(self) -> bool:
        """Check if the collector is running."""
        return self._running

    @classmethod
    def get_source_type(cls) -> str:
        """Get the source type this collector handles."""
        return cls.__name__.replace("Collector", "").lower()
