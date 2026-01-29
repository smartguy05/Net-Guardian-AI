"""Anomaly detection model for storing detected anomalies."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.device import Device

from sqlalchemy import DateTime, Float, ForeignKey, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.alert import AlertSeverity
from app.models.base import Base, TimestampMixin


class AnomalyType(str, Enum):
    """Type of detected anomaly."""

    NEW_DOMAIN = "new_domain"
    VOLUME_SPIKE = "volume_spike"
    TIME_ANOMALY = "time_anomaly"
    NEW_CONNECTION = "new_connection"
    NEW_PORT = "new_port"
    BLOCKED_SPIKE = "blocked_spike"
    PATTERN_CHANGE = "pattern_change"


class AnomalyStatus(str, Enum):
    """Status of anomaly detection."""

    ACTIVE = "active"
    REVIEWED = "reviewed"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"


class AnomalyDetection(Base, TimestampMixin):
    """Detected anomaly model.

    Stores individual anomaly detections with scoring and context
    for human review.

    Attributes:
        id: Unique identifier (UUID).
        device_id: Associated device.
        anomaly_type: Type of anomaly detected.
        severity: Calculated severity based on score.
        score: Anomaly score (e.g., z-score or deviation magnitude).
        status: Current status of the anomaly.
        description: Human-readable description.
        details: Detailed anomaly information (JSON).
        baseline_comparison: What's normal vs observed (JSON).
        detected_at: When the anomaly was detected.
        alert_id: Associated alert (if one was generated).
        reviewed_by: User who reviewed the anomaly.
        reviewed_at: When the anomaly was reviewed.
    """

    __tablename__ = "anomaly_detections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    anomaly_type: Mapped[AnomalyType] = mapped_column(
        SQLEnum(AnomalyType, name="anomalytype", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(AlertSeverity, name="alertseverity", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    status: Mapped[AnomalyStatus] = mapped_column(
        SQLEnum(AnomalyStatus, name="anomalystatus", values_callable=lambda x: [e.value for e in x]),
        default=AnomalyStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    baseline_comparison: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Review tracking
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    device: Mapped[Device] = relationship(
        "Device",
        back_populates="anomalies",
    )
    alert: Mapped[Alert | None] = relationship(
        "Alert",
        back_populates="anomaly",
    )

    def __repr__(self) -> str:
        return f"<AnomalyDetection {self.anomaly_type.value} ({self.severity.value})>"

    @classmethod
    def calculate_severity(cls, score: float, anomaly_type: AnomalyType) -> AlertSeverity:
        """Calculate severity based on anomaly score and type.

        Args:
            score: The anomaly score (typically z-score).
            anomaly_type: Type of anomaly for context-aware severity.

        Returns:
            Appropriate AlertSeverity level.
        """
        # Higher scores for certain anomaly types warrant higher severity
        high_risk_types = {AnomalyType.NEW_CONNECTION, AnomalyType.BLOCKED_SPIKE}

        if anomaly_type in high_risk_types:
            # More aggressive severity for risky anomaly types
            if score >= 4.0:
                return AlertSeverity.CRITICAL
            elif score >= 3.0:
                return AlertSeverity.HIGH
            elif score >= 2.0:
                return AlertSeverity.MEDIUM
            else:
                return AlertSeverity.LOW
        else:
            # Standard severity calculation
            if score >= 5.0:
                return AlertSeverity.CRITICAL
            elif score >= 4.0:
                return AlertSeverity.HIGH
            elif score >= 3.0:
                return AlertSeverity.MEDIUM
            elif score >= 2.0:
                return AlertSeverity.LOW
            else:
                return AlertSeverity.INFO
