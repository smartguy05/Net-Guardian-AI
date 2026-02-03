"""Security pattern models for configurable attack pattern detection."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.alert import AlertSeverity
from app.models.base import Base, TimestampMixin


class PatternCategory(str, Enum):
    """Category of security pattern."""

    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XSS = "xss"
    DESERIALIZATION = "deserialization"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    LOG_INJECTION = "log_injection"
    LDAP_INJECTION = "ldap_injection"
    XXE = "xxe"
    CUSTOM = "custom"


class PatternType(str, Enum):
    """Type of pattern matching."""

    REGEX = "regex"  # Regular expression pattern
    LITERAL = "literal"  # Exact string match
    KEYWORD = "keyword"  # Keyword/substring match


class PatternSource(str, Enum):
    """Source of the security pattern."""

    BUILTIN = "builtin"  # Built-in default patterns
    USER = "user"  # User-created patterns
    FEED = "feed"  # Imported from external feed


class SecurityPattern(Base, TimestampMixin):
    """Security pattern for detecting attacks in application logs.

    Attributes:
        id: Unique identifier.
        name: Human-readable pattern name.
        description: Description of what this pattern detects.
        category: Category of attack pattern.
        pattern_type: Type of pattern matching (regex, literal, keyword).
        pattern: The actual pattern/regex to match.
        severity: Severity level when pattern matches.
        enabled: Whether the pattern is active.
        tags: Tags for categorization and filtering.
        extra_data: Additional metadata and context.
        source: Where this pattern came from (builtin, user, feed).
        feed_id: Reference to feed if imported from external source.
        examples: Example strings that should match this pattern.
        references: URLs to documentation about this attack type.
        hit_count: Number of times this pattern was matched.
        last_hit_at: When this pattern was last matched.
    """

    __tablename__ = "security_patterns"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    category: Mapped[PatternCategory] = mapped_column(
        SQLEnum(
            PatternCategory,
            name="patterncategory",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        index=True,
    )
    pattern_type: Mapped[PatternType] = mapped_column(
        SQLEnum(
            PatternType,
            name="patterntype",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    pattern: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(
            AlertSeverity,
            name="alertseverity",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=AlertSeverity.MEDIUM,
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
    )
    tags: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )
    extra_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    source: Mapped[PatternSource] = mapped_column(
        SQLEnum(
            PatternSource,
            name="patternsource",
            values_callable=lambda x: [e.value for e in x],
        ),
        default=PatternSource.USER,
        nullable=False,
        index=True,
    )
    feed_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("security_pattern_feeds.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    examples: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )
    references: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )
    hit_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    last_hit_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    feed: Mapped["SecurityPatternFeed | None"] = relationship(
        "SecurityPatternFeed",
        back_populates="patterns",
    )

    def __repr__(self) -> str:
        return f"<SecurityPattern {self.name} ({self.category.value})>"


class SecurityPatternFeed(Base, TimestampMixin):
    """External feed for importing security patterns.

    Attributes:
        id: Unique identifier.
        name: Human-readable feed name.
        description: Feed description.
        url: URL to fetch patterns from.
        enabled: Whether the feed is actively being fetched.
        update_interval_hours: How often to fetch updates.
        auth_type: Authentication type (none, basic, bearer, api_key).
        auth_config: Authentication configuration (credentials, headers).
        field_mapping: Mapping of feed fields to SecurityPattern fields.
        last_fetch_at: When the feed was last successfully fetched.
        last_fetch_status: Status of last fetch (success, error).
        last_fetch_message: Message from last fetch (error details, etc.).
        pattern_count: Number of patterns from this feed.
    """

    __tablename__ = "security_pattern_feeds"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    url: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    update_interval_hours: Mapped[int] = mapped_column(
        Integer,
        default=24,
        nullable=False,
    )
    auth_type: Mapped[str] = mapped_column(
        String(32),
        default="none",
        nullable=False,
    )
    auth_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    field_mapping: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    last_fetch_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_fetch_status: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )
    last_fetch_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    pattern_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    # Relationships
    patterns: Mapped[list["SecurityPattern"]] = relationship(
        "SecurityPattern",
        back_populates="feed",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<SecurityPatternFeed {self.name}>"
