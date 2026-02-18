"""Investigation models for autonomous security investigations."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.anomaly import AnomalyDetection
    from app.models.device import Device
    from app.models.user import User


class InvestigationStatus(str, Enum):
    """Status of an investigation."""

    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class InvestigationStepType(str, Enum):
    """Types of investigation steps."""

    GATHER_CONTEXT = "gather_context"
    CORRELATE_EVENTS = "correlate_events"
    CHECK_THREAT_INTEL = "check_threat_intel"
    ANALYZE_BASELINE = "analyze_baseline"
    GENERATE_HYPOTHESIS = "generate_hypothesis"
    RECOMMEND_ACTIONS = "recommend_actions"


class InvestigationStepStatus(str, Enum):
    """Status of an investigation step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class InvestigationActionStatus(str, Enum):
    """Status of an investigation action."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class InvestigationActionRiskLevel(str, Enum):
    """Risk level of an investigation action."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvestigationTriggerSource(str, Enum):
    """Source that triggered an investigation."""

    PLAYBOOK = "playbook"
    MANUAL = "manual"
    AUTO = "auto"


class Investigation(Base, TimestampMixin):
    """Investigation model for autonomous security investigations.

    Attributes:
        id: Unique identifier (UUID).
        alert_id: Associated alert (if applicable).
        anomaly_id: Associated anomaly (if applicable).
        device_id: Associated device (if applicable).
        status: Current investigation status.
        trigger_source: What triggered the investigation.
        priority: Investigation priority (1-5, 5 being highest).
        started_at: When investigation started running.
        completed_at: When investigation completed.
        summary: LLM-generated investigation summary.
        recommendations: JSON object with recommendations.
        requires_approval: Whether actions require human approval.
        approved_by: User who approved the investigation.
    """

    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    anomaly_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("anomaly_detections.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[InvestigationStatus] = mapped_column(
        SQLEnum(
            InvestigationStatus,
            name="investigationstatus",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=InvestigationStatus.PENDING,
        nullable=False,
        index=True,
    )
    trigger_source: Mapped[InvestigationTriggerSource] = mapped_column(
        SQLEnum(
            InvestigationTriggerSource,
            name="investigationtriggersource",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(
        Integer,
        default=3,
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    recommendations: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    requires_approval: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    alert: Mapped[Alert | None] = relationship(
        "Alert",
        foreign_keys=[alert_id],
    )
    anomaly: Mapped[AnomalyDetection | None] = relationship(
        "AnomalyDetection",
        foreign_keys=[anomaly_id],
    )
    device: Mapped[Device | None] = relationship(
        "Device",
        foreign_keys=[device_id],
    )
    approved_by_user: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[approved_by],
    )
    steps: Mapped[list[InvestigationStep]] = relationship(
        "InvestigationStep",
        back_populates="investigation",
        cascade="all, delete-orphan",
        order_by="InvestigationStep.step_number",
    )
    actions: Mapped[list[InvestigationAction]] = relationship(
        "InvestigationAction",
        back_populates="investigation",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_investigations_status_priority", "status", "priority"),
        Index("ix_investigations_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Investigation {self.id} ({self.status.value})>"


class InvestigationStep(Base, TimestampMixin):
    """Investigation step model tracking chain-of-thought reasoning.

    Attributes:
        id: Unique identifier (UUID).
        investigation_id: Parent investigation.
        step_number: Order of this step (1-indexed).
        step_type: Type of investigation step.
        status: Current step status.
        reasoning: Chain-of-thought reasoning (visible to users).
        findings: JSON object with findings/data.
        confidence_score: Confidence in findings (0.0-1.0).
        duration_ms: How long the step took.
        llm_model_used: Which LLM model was used.
    """

    __tablename__ = "investigation_steps"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    step_type: Mapped[InvestigationStepType] = mapped_column(
        SQLEnum(
            InvestigationStepType,
            name="investigationsteptype",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    status: Mapped[InvestigationStepStatus] = mapped_column(
        SQLEnum(
            InvestigationStepStatus,
            name="investigationstepstatus",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=InvestigationStepStatus.PENDING,
        nullable=False,
    )
    reasoning: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    findings: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )
    confidence_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    llm_model_used: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    investigation: Mapped[Investigation] = relationship(
        "Investigation",
        back_populates="steps",
    )

    __table_args__ = (
        Index("ix_investigation_steps_investigation_step", "investigation_id", "step_number"),
    )

    def __repr__(self) -> str:
        return f"<InvestigationStep {self.step_number}: {self.step_type.value}>"


class InvestigationAction(Base, TimestampMixin):
    """Investigation action model for recommended/executed actions.

    Attributes:
        id: Unique identifier (UUID).
        investigation_id: Parent investigation.
        action_type: Type of action (quarantine, block_domain, create_rule, etc.).
        action_params: Parameters for the action.
        risk_level: Risk level of the action.
        justification: LLM-generated justification for the action.
        status: Current action status.
        approved_by: User who approved the action.
        approved_at: When the action was approved.
        executed_at: When the action was executed.
        execution_result: Result of action execution.
    """

    __tablename__ = "investigation_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )
    action_params: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    risk_level: Mapped[InvestigationActionRiskLevel] = mapped_column(
        SQLEnum(
            InvestigationActionRiskLevel,
            name="investigationactionrisklevel",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    justification: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[InvestigationActionStatus] = mapped_column(
        SQLEnum(
            InvestigationActionStatus,
            name="investigationactionstatus",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=InvestigationActionStatus.PENDING,
        nullable=False,
        index=True,
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    rejected_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    rejected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    rejection_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    execution_result: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    # Relationships
    investigation: Mapped[Investigation] = relationship(
        "Investigation",
        back_populates="actions",
    )
    approved_by_user: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[approved_by],
    )
    rejected_by_user: Mapped[User | None] = relationship(
        "User",
        foreign_keys=[rejected_by],
    )

    def __repr__(self) -> str:
        return f"<InvestigationAction {self.action_type} ({self.status.value})>"
