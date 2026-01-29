"""Collector registry for managing available collectors."""

from collections.abc import Callable

import structlog

from app.collectors.base import BaseCollector
from app.models.log_source import LogSource, SourceType
from app.parsers import get_parser

logger = structlog.get_logger()


class CollectorRegistry:
    """Registry for managing collector implementations."""

    _collectors: dict[SourceType, type[BaseCollector]] = {}

    @classmethod
    def register(cls, source_type: SourceType, collector_class: type[BaseCollector]) -> None:
        """Register a collector class for a source type.

        Args:
            source_type: The source type this collector handles.
            collector_class: The collector class to register.
        """
        cls._collectors[source_type] = collector_class
        logger.debug("collector_registered", source_type=source_type.value)

    @classmethod
    def get(cls, source: LogSource) -> BaseCollector:
        """Get a collector instance for a log source.

        Args:
            source: The log source configuration.

        Returns:
            Configured collector instance.

        Raises:
            ValueError: If no collector exists for the source type.
        """
        collector_class = cls._collectors.get(source.source_type)
        if collector_class is None:
            available = [st.value for st in cls._collectors.keys()]
            raise ValueError(
                f"No collector for source type: {source.source_type.value}. Available: {available}"
            )

        # Get the parser for this source
        parser = get_parser(source.parser_type.value, source.parser_config)

        return collector_class(source, parser)

    @classmethod
    def list_collectors(cls) -> list[SourceType]:
        """List all registered source types."""
        return list(cls._collectors.keys())

    @classmethod
    def is_registered(cls, source_type: SourceType) -> bool:
        """Check if a collector is registered for a source type."""
        return source_type in cls._collectors


def get_collector(source: LogSource) -> BaseCollector:
    """Get a collector instance for a log source.

    Convenience function wrapping CollectorRegistry.get().
    """
    return CollectorRegistry.get(source)


def register_collector(
    source_type: SourceType,
) -> Callable[[type[BaseCollector]], type[BaseCollector]]:
    """Decorator to register a collector class.

    Usage:
        @register_collector(SourceType.API_PULL)
        class ApiPullCollector(BaseCollector):
            ...
    """

    def decorator(cls: type[BaseCollector]) -> type[BaseCollector]:
        CollectorRegistry.register(source_type, cls)
        return cls

    return decorator
