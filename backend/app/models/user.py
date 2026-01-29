"""User model for authentication and authorization."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.security import UserRole
from app.models.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """User account model.

    Attributes:
        id: Unique identifier (UUID).
        username: Unique username (lowercase).
        email: Unique email address.
        password_hash: Bcrypt hashed password.
        role: User role (admin, operator, viewer).
        is_active: Whether the account is active.
        must_change_password: Whether user must change password on next login.
        last_login: Timestamp of last successful login.
        created_by: UUID of admin who created this account.
        totp_enabled: Whether 2FA is enabled.
        totp_secret: Encrypted TOTP secret (base32).
        backup_codes: List of remaining backup codes for 2FA recovery.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole, name="userrole", values_callable=lambda x: [e.value for e in x]),
        default=UserRole.VIEWER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    must_change_password: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Two-Factor Authentication fields
    totp_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    totp_secret: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )
    backup_codes: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(16)),
        nullable=True,
    )

    # External authentication (Authentik SSO)
    external_id: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        nullable=True,
        index=True,
    )
    external_provider: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    is_external: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<User {self.username} ({self.role.value})>"
