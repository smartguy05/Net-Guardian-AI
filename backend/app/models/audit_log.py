"""Audit log model for tracking administrative actions."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, Enum as SQLEnum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class AuditAction(Enum):
    """Types of auditable actions."""

    # Device actions
    DEVICE_QUARANTINE = "device_quarantine"
    DEVICE_RELEASE = "device_release"
    DEVICE_UPDATE = "device_update"

    # Alert actions
    ALERT_ACKNOWLEDGE = "alert_acknowledge"
    ALERT_RESOLVE = "alert_resolve"
    ALERT_ANALYZE = "alert_analyze"

    # Anomaly actions
    ANOMALY_REVIEW = "anomaly_review"
    ANOMALY_CONFIRM = "anomaly_confirm"
    ANOMALY_FALSE_POSITIVE = "anomaly_false_positive"

    # User actions
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DEACTIVATE = "user_deactivate"
    USER_PASSWORD_RESET = "user_password_reset"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"

    # Source actions
    SOURCE_CREATE = "source_create"
    SOURCE_UPDATE = "source_update"
    SOURCE_DELETE = "source_delete"
    SOURCE_ENABLE = "source_enable"
    SOURCE_DISABLE = "source_disable"

    # Integration actions
    INTEGRATION_BLOCK = "integration_block"
    INTEGRATION_UNBLOCK = "integration_unblock"
    INTEGRATION_TEST = "integration_test"

    # Playbook actions
    PLAYBOOK_EXECUTE = "playbook_execute"
    PLAYBOOK_CREATE = "playbook_create"
    PLAYBOOK_UPDATE = "playbook_update"
    PLAYBOOK_DELETE = "playbook_delete"


class AuditLog(Base):
    """Audit log for tracking all administrative and security actions.

    This provides a complete audit trail of who did what and when,
    which is essential for security monitoring and compliance.
    """

    __tablename__ = "audit_logs"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    action: Mapped[AuditAction] = mapped_column(
        SQLEnum(AuditAction, name="auditaction", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )

    # Who performed the action
    user_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    username: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
    )

    # Target of the action
    target_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )  # device, user, alert, anomaly, source, etc.

    target_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    target_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # Action details
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    details: Mapped[Dict[str, Any]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    # Result
    success: Mapped[bool] = mapped_column(
        default=True,
        nullable=False,
    )

    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Request context
    ip_address: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True,
    )

    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    # Relationship to user (optional, for when user still exists)
    user = relationship("User", foreign_keys=[user_id])

    def __repr__(self) -> str:
        return f"<AuditLog {self.action.value} by {self.username} at {self.timestamp}>"

    @classmethod
    def create(
        cls,
        action: AuditAction,
        target_type: str,
        description: str,
        user_id: Optional[UUID] = None,
        username: Optional[str] = None,
        target_id: Optional[str] = None,
        target_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> "AuditLog":
        """Create a new audit log entry."""
        return cls(
            action=action,
            target_type=target_type,
            description=description,
            user_id=user_id,
            username=username,
            target_id=target_id,
            target_name=target_name,
            details=details or {},
            success=success,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
        )
