"""Retention policy model for data lifecycle management."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class RetentionPolicy(Base, TimestampMixin):
    """Retention policy for automatic data cleanup.

    Defines how long data should be kept before automatic deletion.

    Attributes:
        id: Unique identifier (UUID).
        table_name: Name of the table this policy applies to.
        display_name: Human-readable name for the policy.
        description: Description of what data this policy covers.
        retention_days: Number of days to retain data (0 = keep forever).
        enabled: Whether this policy is active.
        last_run: When the cleanup was last executed.
        deleted_count: Number of records deleted in last run.
    """

    __tablename__ = "retention_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    table_name: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
    )
    display_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text(),
        nullable=True,
    )
    retention_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=90,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    last_run: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    deleted_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    def __repr__(self) -> str:
        return f"<RetentionPolicy {self.table_name}: {self.retention_days}d>"
