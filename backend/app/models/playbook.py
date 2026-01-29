"""Playbook models for automated response actions."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import ENUM, JSON
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.models.base import Base


class PlaybookTriggerType(str, Enum):
    """Types of triggers that can activate a playbook."""

    ANOMALY_DETECTED = "anomaly_detected"
    ALERT_CREATED = "alert_created"
    DEVICE_NEW = "device_new"
    DEVICE_STATUS_CHANGE = "device_status_change"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    SCHEDULE = "schedule"
    MANUAL = "manual"


class PlaybookActionType(str, Enum):
    """Types of actions a playbook can perform."""

    QUARANTINE_DEVICE = "quarantine_device"
    RELEASE_DEVICE = "release_device"
    BLOCK_DOMAIN = "block_domain"
    UNBLOCK_DOMAIN = "unblock_domain"
    SEND_NOTIFICATION = "send_notification"
    CREATE_ALERT = "create_alert"
    RUN_LLM_ANALYSIS = "run_llm_analysis"
    EXECUTE_WEBHOOK = "execute_webhook"
    LOG_EVENT = "log_event"
    TAG_DEVICE = "tag_device"


class PlaybookStatus(str, Enum):
    """Status of a playbook."""

    ACTIVE = "active"
    DISABLED = "disabled"
    DRAFT = "draft"


class ExecutionStatus(str, Enum):
    """Status of a playbook execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Playbook(Base):
    """Model for response playbooks."""

    __tablename__ = "playbooks"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[PlaybookStatus] = mapped_column(
        ENUM(
            PlaybookStatus,
            name="playbookstatus",
            create_type=False,
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=PlaybookStatus.DRAFT,
    )

    # Trigger configuration
    trigger_type: Mapped[PlaybookTriggerType] = mapped_column(
        ENUM(
            PlaybookTriggerType,
            name="playbooktriggertype",
            create_type=False,
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    trigger_conditions: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    # Actions to perform (ordered list)
    actions: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    # Execution settings
    cooldown_minutes: Mapped[int] = mapped_column(
        nullable=False,
        default=60,
    )
    max_executions_per_hour: Mapped[int] = mapped_column(
        nullable=False,
        default=10,
    )
    require_approval: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
    )
    created_by: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    executions: Mapped[list["PlaybookExecution"]] = relationship(
        "PlaybookExecution",
        back_populates="playbook",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_playbooks_status", "status"),
        Index("ix_playbooks_trigger_type", "trigger_type"),
    )


class PlaybookExecution(Base):
    """Model for tracking playbook executions."""

    __tablename__ = "playbook_executions"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    playbook_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("playbooks.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[ExecutionStatus] = mapped_column(
        ENUM(
            ExecutionStatus,
            name="executionstatus",
            create_type=False,
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        default=ExecutionStatus.PENDING,
    )

    # Trigger information
    trigger_event: Mapped[dict[str, Any]] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )
    trigger_device_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Execution details
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    action_results: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Who triggered it (null for automatic)
    triggered_by: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
    )

    # Relationships
    playbook: Mapped["Playbook"] = relationship(
        "Playbook",
        back_populates="executions",
    )

    __table_args__ = (
        Index("ix_playbook_executions_playbook_id", "playbook_id"),
        Index("ix_playbook_executions_status", "status"),
        Index("ix_playbook_executions_created_at", "created_at"),
    )
