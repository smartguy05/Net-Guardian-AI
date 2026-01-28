"""Parser registry for managing available parsers."""

from typing import Any

import structlog

from app.parsers.base import BaseParser

logger = structlog.get_logger()


class ParserRegistry:
    """Registry for managing parser implementations."""

    _parsers: dict[str, type[BaseParser]] = {}

    @classmethod
    def register(cls, name: str, parser_class: type[BaseParser]) -> None:
        """Register a parser class.

        Args:
            name: Parser name (e.g., "json", "syslog", "adguard").
            parser_class: Parser class to register.
        """
        cls._parsers[name] = parser_class
        logger.debug("parser_registered", parser=name)

    @classmethod
    def get(cls, name: str, config: dict[str, Any] | None = None) -> BaseParser:
        """Get a parser instance by name.

        Args:
            name: Parser name.
            config: Parser configuration.

        Returns:
            Parser instance.

        Raises:
            ValueError: If parser not found.
        """
        parser_class = cls._parsers.get(name)
        if parser_class is None:
            available = list(cls._parsers.keys())
            raise ValueError(
                f"Unknown parser: {name}. Available parsers: {available}"
            )
        return parser_class(config)

    @classmethod
    def list_parsers(cls) -> list[str]:
        """List all registered parser names."""
        return list(cls._parsers.keys())

    @classmethod
    def is_registered(cls, name: str) -> bool:
        """Check if a parser is registered."""
        return name in cls._parsers


def get_parser(name: str, config: dict[str, Any] | None = None) -> BaseParser:
    """Get a parser instance by name.

    Convenience function wrapping ParserRegistry.get().
    """
    return ParserRegistry.get(name, config)


def register_parser(name: str):
    """Decorator to register a parser class.

    Usage:
        @register_parser("myparser")
        class MyParser(BaseParser):
            ...
    """
    def decorator(cls: type[BaseParser]) -> type[BaseParser]:
        ParserRegistry.register(name, cls)
        return cls
    return decorator
