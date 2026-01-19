"""Detection rule model for configurable alert triggers."""

from typing import Any, Dict, List
from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin
from app.models.alert import AlertSeverity
from sqlalchemy import Enum as SQLEnum


class DetectionRule(Base, TimestampMixin):
    """Detection rule model.

    Attributes:
        id: Unique identifier (string slug).
        name: Human-readable rule name.
        description: Detailed rule description.
        severity: Alert severity when triggered.
        enabled: Whether the rule is active.
        conditions: Rule conditions (JSON).
        response_actions: Actions to take when triggered (JSON).
        cooldown_minutes: Minimum time between alerts for same device.
    """

    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(
        String(100),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=True,
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(AlertSeverity, name="alertseverity", create_type=False, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    conditions: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )
    response_actions: Mapped[List[Dict[str, Any]]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )
    cooldown_minutes: Mapped[int] = mapped_column(
        Integer,
        default=60,
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<DetectionRule {self.id} ({self.severity.value})>"
