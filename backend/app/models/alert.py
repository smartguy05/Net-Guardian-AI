"""Alert model for security alerts."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy import DateTime, Enum as SQLEnum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class AlertSeverity(str, Enum):
    """Alert severity level."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Alert status."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(Base, TimestampMixin):
    """Security alert model.

    Attributes:
        id: Unique identifier (UUID).
        timestamp: When the alert was generated.
        device_id: Associated device (if applicable).
        rule_id: Detection rule that triggered the alert.
        severity: Alert severity level.
        title: Short alert title.
        description: Detailed alert description.
        llm_analysis: LLM-generated analysis (JSON).
        status: Current alert status.
        actions_taken: Log of response actions taken.
        acknowledged_by: User who acknowledged the alert.
        acknowledged_at: When the alert was acknowledged.
        resolved_by: User who resolved the alert.
        resolved_at: When the alert was resolved.
    """

    __tablename__ = "alerts"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    device_id: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    rule_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(AlertSeverity, name="alertseverity", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    llm_analysis: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )
    status: Mapped[AlertStatus] = mapped_column(
        SQLEnum(AlertStatus, name="alertstatus", values_callable=lambda x: [e.value for e in x]),
        default=AlertStatus.NEW,
        nullable=False,
        index=True,
    )
    actions_taken: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )

    # Audit fields
    acknowledged_by: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_by: Mapped[Optional[UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    device: Mapped[Optional["Device"]] = relationship(
        "Device",
        back_populates="alerts",
    )
    anomaly: Mapped[Optional["AnomalyDetection"]] = relationship(
        "AnomalyDetection",
        back_populates="alert",
        uselist=False,
    )

    def __repr__(self) -> str:
        return f"<Alert {self.title} ({self.severity.value})>"
