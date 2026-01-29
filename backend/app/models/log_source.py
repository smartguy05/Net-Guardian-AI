"""Log source model for configuring data collection sources."""

from datetime import datetime
from enum import Enum
from typing import Any

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class SourceType(str, Enum):
    """Type of log source."""

    API_PULL = "api_pull"  # Pull logs from external API
    FILE_WATCH = "file_watch"  # Watch mounted log files
    API_PUSH = "api_push"  # Receive logs via API
    UDP_LISTEN = "udp_listen"  # Listen for UDP packets (NetFlow/sFlow)


class ParserType(str, Enum):
    """Type of log parser."""

    # Built-in parsers
    ADGUARD = "adguard"
    AUTHENTIK = "authentik"  # Authentik identity provider events
    UNIFI = "unifi"
    PFSENSE = "pfsense"
    OLLAMA = "ollama"  # Ollama LLM server parser
    ENDPOINT = "endpoint"  # Endpoint agent data parser
    NETFLOW = "netflow"  # NetFlow v5/v9/IPFIX parser
    SFLOW = "sflow"  # sFlow v5 parser
    LOKI = "loki"  # Grafana Loki log aggregation

    # Generic parsers
    JSON = "json"
    SYSLOG = "syslog"
    NGINX = "nginx"
    CUSTOM = "custom"


class LogSource(Base, TimestampMixin):
    """Log source configuration model.

    Attributes:
        id: Unique identifier (string, user-defined slug).
        name: Human-readable display name.
        description: Optional description of the source.
        source_type: Type of source (api_pull, file_watch, api_push).
        enabled: Whether the source is active.
        config: Source-specific configuration (JSON).
        parser_type: Type of parser to use.
        parser_config: Parser-specific configuration (JSON).
        api_key: API key for push sources (auto-generated).
        last_event_at: Timestamp of last received event.
        last_error: Last error message if any.
        event_count: Total number of events received.
    """

    __tablename__ = "log_sources"

    id: Mapped[str] = mapped_column(
        String(100),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    source_type: Mapped[SourceType] = mapped_column(
        SQLEnum(SourceType, name="sourcetype", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    parser_type: Mapped[ParserType] = mapped_column(
        SQLEnum(ParserType, name="parsertype", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    parser_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    api_key: Mapped[str | None] = mapped_column(
        String(64),
        unique=True,
        nullable=True,
        index=True,
    )
    last_event_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    event_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<LogSource {self.id} ({self.source_type.value})>"
