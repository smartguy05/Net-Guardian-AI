"""Semantic analysis models for intelligent log pattern detection."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class LLMProvider(str, Enum):
    """LLM provider type."""

    CLAUDE = "claude"
    OLLAMA = "ollama"


class AnalysisRunStatus(str, Enum):
    """Status of an analysis run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SuggestedRuleStatus(str, Enum):
    """Status of a suggested rule."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    IMPLEMENTED = "implemented"


class SuggestedRuleType(str, Enum):
    """Type of suggested rule."""

    PATTERN_MATCH = "pattern_match"
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"


class LogPattern(Base, TimestampMixin):
    """Stores normalized log patterns learned from events.

    Attributes:
        id: Unique identifier (UUID).
        source_id: Reference to the LogSource that produces this pattern.
        normalized_pattern: Template with placeholders (e.g., "User <USER> logged in from <IP>").
        pattern_hash: SHA-256 hash of normalized pattern for quick lookup.
        first_seen: When this pattern was first observed.
        last_seen: When this pattern was last observed.
        occurrence_count: Total number of times this pattern has been seen.
        is_ignored: Manual flag to ignore this pattern in analysis.
    """

    __tablename__ = "log_patterns"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    source_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("log_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    normalized_pattern: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    pattern_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    occurrence_count: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    is_ignored: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    __table_args__ = (
        # Unique constraint on source + hash
        Index("ix_log_patterns_source_hash", "source_id", "pattern_hash", unique=True),
    )

    def __repr__(self) -> str:
        return f"<LogPattern {self.id} ({self.occurrence_count} occurrences)>"


class SemanticAnalysisConfig(Base, TimestampMixin):
    """Per-source configuration for semantic analysis.

    Attributes:
        id: Unique identifier (UUID).
        source_id: Reference to the LogSource (unique).
        enabled: Whether semantic analysis is enabled for this source.
        llm_provider: LLM provider to use (claude or ollama).
        ollama_model: Model to use if provider is ollama.
        rarity_threshold: Patterns seen < N times are considered irregular.
        batch_size: Maximum logs per LLM batch.
        batch_interval_minutes: How often to run batch analysis.
        last_run_at: Timestamp of last analysis run.
    """

    __tablename__ = "semantic_analysis_configs"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    source_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("log_sources.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    llm_provider: Mapped[LLMProvider] = mapped_column(
        SQLEnum(
            LLMProvider,
            name="llmprovider",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=LLMProvider.CLAUDE,
        nullable=False,
    )
    ollama_model: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    rarity_threshold: Mapped[int] = mapped_column(
        Integer,
        default=3,
        nullable=False,
    )
    batch_size: Mapped[int] = mapped_column(
        Integer,
        default=50,
        nullable=False,
    )
    batch_interval_minutes: Mapped[int] = mapped_column(
        Integer,
        default=60,
        nullable=False,
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<SemanticAnalysisConfig for {self.source_id}>"


class IrregularLog(Base, TimestampMixin):
    """Detected irregular log events.

    Attributes:
        id: Unique identifier (UUID).
        event_id: Reference to the RawEvent.
        event_timestamp: Timestamp of the event (needed for hypertable FK).
        source_id: Reference to the LogSource.
        pattern_id: Reference to the LogPattern (if matched).
        reason: Why this log was flagged as irregular.
        llm_reviewed: Whether this log has been analyzed by LLM.
        llm_response: Full LLM response for this log.
        severity_score: Severity score from LLM (0.0-1.0).
        reviewed_by_user: Whether a human has reviewed this.
        reviewed_at: When the human review occurred.
    """

    __tablename__ = "irregular_logs"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    event_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    source_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("log_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    pattern_id: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("log_patterns.id", ondelete="SET NULL"),
        nullable=True,
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    llm_reviewed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    llm_response: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    severity_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    reviewed_by_user: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    pattern: Mapped[Optional["LogPattern"]] = relationship(
        "LogPattern",
        lazy="joined",
    )

    __table_args__ = (
        Index("ix_irregular_logs_source_created", "source_id", "created_at"),
        Index("ix_irregular_logs_severity", "severity_score"),
    )

    def __repr__(self) -> str:
        return f"<IrregularLog {self.id} (severity={self.severity_score})>"


class SemanticAnalysisRun(Base, TimestampMixin):
    """Audit trail for batch analysis runs.

    Attributes:
        id: Unique identifier (UUID).
        source_id: Reference to the LogSource.
        started_at: When the analysis started.
        completed_at: When the analysis completed.
        status: Status of the run (running, completed, failed).
        events_scanned: Number of events scanned in this run.
        irregulars_found: Number of irregular events found.
        llm_provider: LLM provider used for this run.
        llm_response_summary: Summary of LLM findings.
        error_message: Error message if the run failed.
    """

    __tablename__ = "semantic_analysis_runs"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    source_id: Mapped[str] = mapped_column(
        String(100),
        ForeignKey("log_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    status: Mapped[AnalysisRunStatus] = mapped_column(
        SQLEnum(
            AnalysisRunStatus,
            name="analysisrunstatus",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=AnalysisRunStatus.RUNNING,
        nullable=False,
    )
    events_scanned: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    irregulars_found: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    llm_provider: Mapped[LLMProvider] = mapped_column(
        SQLEnum(
            LLMProvider,
            name="llmprovider",
            values_callable=lambda x: [e.value for e in x],
            create_type=False,  # Already created above
        ),
        nullable=False,
    )
    llm_response_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    __table_args__ = (
        Index("ix_semantic_analysis_runs_source_started", "source_id", "started_at"),
    )

    def __repr__(self) -> str:
        return f"<SemanticAnalysisRun {self.id} ({self.status.value})>"


class SuggestedRule(Base, TimestampMixin):
    """LLM-generated detection rule suggestions.

    Attributes:
        id: Unique identifier (UUID).
        source_id: Reference to the LogSource (null = global).
        analysis_run_id: Reference to the SemanticAnalysisRun that generated this.
        irregular_log_id: Reference to the IrregularLog that triggered this suggestion.
        name: Short descriptive rule name.
        description: What the rule detects.
        reason: Why this rule was suggested (from LLM analysis).
        benefit: How this rule improves security posture.
        rule_type: Type of rule (pattern_match, threshold, sequence).
        rule_config: Rule parameters (JSON).
        status: Current status of the rule.
        enabled: Whether the rule is enabled (only if approved).
        rule_hash: Hash for deduplication.
        reviewed_by: User who reviewed this rule.
        reviewed_at: When the rule was reviewed.
        rejection_reason: Reason for rejection (if rejected).
    """

    __tablename__ = "suggested_rules"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    source_id: Mapped[str | None] = mapped_column(
        String(100),
        ForeignKey("log_sources.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("semantic_analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    irregular_log_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("irregular_logs.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Rule definition
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    benefit: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    rule_type: Mapped[SuggestedRuleType] = mapped_column(
        SQLEnum(
            SuggestedRuleType,
            name="suggestedruletype",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    rule_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )

    # Status tracking
    status: Mapped[SuggestedRuleStatus] = mapped_column(
        SQLEnum(
            SuggestedRuleStatus,
            name="suggestedrulestatus",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=SuggestedRuleStatus.PENDING,
        nullable=False,
        index=True,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Deduplication
    rule_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    # Audit
    reviewed_by: Mapped[UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    rejection_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    analysis_run: Mapped["SemanticAnalysisRun"] = relationship(
        "SemanticAnalysisRun",
        lazy="joined",
    )
    irregular_log: Mapped["IrregularLog"] = relationship(
        "IrregularLog",
        lazy="joined",
    )

    def __repr__(self) -> str:
        return f"<SuggestedRule {self.name} ({self.status.value})>"


class SuggestedRuleHistory(Base):
    """History of suggested rules for deduplication.

    Prevents suggesting the same rule again after approval or rejection.

    Attributes:
        id: Unique identifier (UUID).
        rule_hash: Hash of the rule configuration.
        original_rule_id: Reference to the original SuggestedRule.
        status: Final status of the rule (approved/rejected).
        created_at: When this history entry was created.
    """

    __tablename__ = "suggested_rule_history"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    rule_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    original_rule_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("suggested_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[SuggestedRuleStatus] = mapped_column(
        SQLEnum(
            SuggestedRuleStatus,
            name="suggestedrulestatus",
            values_callable=lambda x: [e.value for e in x],
            create_type=False,  # Already created above
        ),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default="now()",
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<SuggestedRuleHistory {self.rule_hash} ({self.status.value})>"
