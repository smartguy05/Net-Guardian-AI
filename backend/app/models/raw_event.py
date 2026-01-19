"""Raw event model for normalized log events."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SQLEnum, Float, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class EventType(str, Enum):
    """Type of event."""

    DNS = "dns"
    FIREWALL = "firewall"
    AUTH = "auth"
    HTTP = "http"
    SYSTEM = "system"
    NETWORK = "network"
    LLM = "llm"  # LLM/AI model interactions (Ollama monitoring)
    ENDPOINT = "endpoint"  # Endpoint agent events (process, file, network)
    FLOW = "flow"  # NetFlow/sFlow network flow data
    UNKNOWN = "unknown"


class EventSeverity(str, Enum):
    """Event severity level."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RawEvent(Base):
    """Normalized raw event model.

    This is a TimescaleDB hypertable partitioned by timestamp.
    All log sources produce events in this normalized format.

    Attributes:
        id: Unique identifier (UUID).
        timestamp: Event timestamp (used for hypertable partitioning).
        source_id: Reference to the LogSource that produced this event.
        event_type: Type of event (dns, firewall, auth, etc.).
        severity: Event severity level.
        client_ip: Source IP address if applicable.
        target_ip: Destination IP address if applicable.
        domain: Domain name if applicable (e.g., DNS queries).
        port: Port number if applicable.
        protocol: Protocol (TCP, UDP, etc.) if applicable.
        action: Action taken (allow, block, drop, etc.).
        raw_message: Original raw log line/message.
        parsed_fields: Additional parsed fields as JSON.
        device_id: Associated device (resolved from IP/MAC).
    """

    __tablename__ = "raw_events"

    # Primary key includes timestamp for TimescaleDB hypertable
    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,  # Part of composite PK for hypertable
        nullable=False,
    )
    source_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("log_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[EventType] = mapped_column(
        SQLEnum(EventType, name="eventtype", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    severity: Mapped[EventSeverity] = mapped_column(
        SQLEnum(EventSeverity, name="eventseverity", values_callable=lambda x: [e.value for e in x]),
        default=EventSeverity.INFO,
        nullable=False,
    )

    # Network context
    client_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
        index=True,
    )
    target_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )
    domain: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
    )
    port: Mapped[Optional[int]] = mapped_column(
        nullable=True,
    )
    protocol: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
    )
    action: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    # Raw and parsed data
    raw_message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    parsed_fields: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # DNS-specific fields (for quick access without parsing JSON)
    query_type: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
    )
    response_status: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )
    blocked_reason: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    entropy_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )

    # Device association
    device_id: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    device: Mapped[Optional["Device"]] = relationship(
        "Device",
        back_populates="raw_events",
    )

    __table_args__ = (
        # Composite index for common queries
        Index("ix_raw_events_device_timestamp", "device_id", "timestamp"),
        Index("ix_raw_events_source_timestamp", "source_id", "timestamp"),
        # Note: TimescaleDB hypertable creation is done in migration
    )

    def __repr__(self) -> str:
        return f"<RawEvent {self.event_type.value} from {self.source_id} at {self.timestamp}>"
