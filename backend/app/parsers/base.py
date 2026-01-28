"""Base parser interface for log parsing."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.raw_event import EventSeverity, EventType


@dataclass
class ParseResult:
    """Result of parsing a log entry."""

    timestamp: datetime
    event_type: EventType
    severity: EventSeverity
    raw_message: str
    client_ip: str | None = None
    target_ip: str | None = None
    domain: str | None = None
    port: int | None = None
    protocol: str | None = None
    action: str | None = None
    response_status: str | None = None
    parsed_fields: dict[str, Any] = field(default_factory=dict)


class BaseParser(ABC):
    """Abstract base class for log parsers.

    All parsers must implement the parse method to convert raw log
    data into normalized ParseResult objects.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the parser with optional configuration.

        Args:
            config: Parser-specific configuration dictionary.
        """
        self.config = config or {}

    @abstractmethod
    def parse(self, raw_data: Any) -> list[ParseResult]:
        """Parse raw log data into normalized events.

        Args:
            raw_data: The raw log data (format depends on parser type).

        Returns:
            List of ParseResult objects.
        """
        pass

    def parse_single(self, raw_data: Any) -> ParseResult | None:
        """Parse a single log entry.

        Args:
            raw_data: A single log entry.

        Returns:
            ParseResult or None if parsing fails.
        """
        results = self.parse(raw_data)
        return results[0] if results else None

    @classmethod
    def get_name(cls) -> str:
        """Get the parser name for registration."""
        return cls.__name__.replace("Parser", "").lower()
