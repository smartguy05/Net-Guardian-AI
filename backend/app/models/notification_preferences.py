"""Notification preferences model for user notification settings."""

from typing import Optional
from uuid import uuid4

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class NotificationPreferences(Base, TimestampMixin):
    """User notification preferences.

    Stores email and ntfy.sh notification settings per user.

    Attributes:
        id: Unique identifier (UUID).
        user_id: Reference to the user.
        email_enabled: Whether email notifications are enabled.
        email_address: Override email address (uses user's email if not set).
        email_on_critical: Email on critical alerts.
        email_on_high: Email on high severity alerts.
        email_on_medium: Email on medium severity alerts.
        email_on_low: Email on low severity alerts.
        email_on_anomaly: Email on anomaly detection.
        email_on_quarantine: Email when device is quarantined.
        ntfy_enabled: Whether ntfy.sh notifications are enabled.
        ntfy_topic: User-specific ntfy topic (overrides default).
        ntfy_on_critical: Push on critical alerts.
        ntfy_on_high: Push on high severity alerts.
        ntfy_on_medium: Push on medium severity alerts.
        ntfy_on_low: Push on low severity alerts.
        ntfy_on_anomaly: Push on anomaly detection.
        ntfy_on_quarantine: Push when device is quarantined.
    """

    __tablename__ = "notification_preferences"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    user_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )

    # Email settings
    email_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    email_address: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    email_on_critical: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    email_on_high: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    email_on_medium: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    email_on_low: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    email_on_anomaly: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    email_on_quarantine: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # ntfy.sh settings
    ntfy_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    ntfy_topic: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    ntfy_on_critical: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    ntfy_on_high: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    ntfy_on_medium: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    ntfy_on_low: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    ntfy_on_anomaly: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    ntfy_on_quarantine: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationship
    user = relationship("User", backref="notification_preferences", lazy="joined")

    def __repr__(self) -> str:
        return f"<NotificationPreferences user_id={self.user_id}>"

    def should_notify_email(self, severity: str, event_type: str = "alert") -> bool:
        """Check if email notification should be sent based on preferences."""
        if not self.email_enabled:
            return False

        if event_type == "anomaly":
            return self.email_on_anomaly
        elif event_type == "quarantine":
            return self.email_on_quarantine

        severity_map = {
            "critical": self.email_on_critical,
            "high": self.email_on_high,
            "medium": self.email_on_medium,
            "low": self.email_on_low,
        }
        return severity_map.get(severity.lower(), False)

    def should_notify_ntfy(self, severity: str, event_type: str = "alert") -> bool:
        """Check if ntfy notification should be sent based on preferences."""
        if not self.ntfy_enabled:
            return False

        if event_type == "anomaly":
            return self.ntfy_on_anomaly
        elif event_type == "quarantine":
            return self.ntfy_on_quarantine

        severity_map = {
            "critical": self.ntfy_on_critical,
            "high": self.ntfy_on_high,
            "medium": self.ntfy_on_medium,
            "low": self.ntfy_on_low,
        }
        return severity_map.get(severity.lower(), False)
