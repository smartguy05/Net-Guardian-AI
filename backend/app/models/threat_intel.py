"""Threat intelligence models for feed and indicator management."""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class FeedType(str, Enum):
    """Type of threat intelligence feed."""

    CSV = "csv"
    JSON = "json"
    STIX = "stix"
    URL_LIST = "url_list"
    IP_LIST = "ip_list"


class IndicatorType(str, Enum):
    """Type of threat indicator."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CIDR = "cidr"


class ThreatIntelFeed(Base, TimestampMixin):
    """Threat intelligence feed configuration.

    Attributes:
        id: Unique identifier.
        name: Human-readable feed name.
        description: Feed description.
        feed_type: Type of feed (CSV, JSON, STIX, etc.).
        url: URL to fetch the feed from.
        enabled: Whether the feed is actively being fetched.
        update_interval_hours: How often to fetch updates.
        auth_type: Authentication type (none, basic, bearer, api_key).
        auth_config: Authentication configuration (headers, credentials).
        field_mapping: Mapping of feed fields to indicator fields.
        last_fetch_at: When the feed was last successfully fetched.
        last_fetch_status: Status of last fetch (success, error, etc.).
        last_fetch_message: Message from last fetch (error details, etc.).
        indicator_count: Number of active indicators from this feed.
    """

    __tablename__ = "threat_intel_feeds"

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
    feed_type: Mapped[FeedType] = mapped_column(
        SQLEnum(FeedType, name="feedtype", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
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
    indicator_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    # Relationships
    indicators: Mapped[list["ThreatIndicator"]] = relationship(
        "ThreatIndicator",
        back_populates="feed",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelFeed {self.name} ({self.feed_type.value})>"


class ThreatIndicator(Base, TimestampMixin):
    """Individual threat indicator from a feed.

    Attributes:
        id: Unique identifier.
        feed_id: Reference to the source feed.
        indicator_type: Type of indicator (IP, domain, URL, hash, etc.).
        value: The actual indicator value.
        confidence: Confidence score (0-100).
        severity: Severity level (info, low, medium, high, critical).
        tags: Tags associated with the indicator.
        description: Description of the threat.
        source_ref: Reference ID from the source feed.
        first_seen_at: When the indicator was first observed.
        last_seen_at: When the indicator was last observed.
        expires_at: When the indicator should be considered stale.
        extra_data: Additional metadata from the feed.
        hit_count: Number of times this indicator was matched.
        last_hit_at: When this indicator was last matched.
    """

    __tablename__ = "threat_indicators"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    feed_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("threat_intel_feeds.id", ondelete="CASCADE"),
        nullable=False,
    )
    indicator_type: Mapped[IndicatorType] = mapped_column(
        SQLEnum(
            IndicatorType, name="indicatortype", values_callable=lambda x: [e.value for e in x]
        ),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(
        String(2048),
        nullable=False,
        index=True,
    )
    confidence: Mapped[int] = mapped_column(
        Integer,
        default=50,
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        default="medium",
        nullable=False,
    )
    tags: Mapped[list[str]] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    source_ref: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    extra_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
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
    feed: Mapped["ThreatIntelFeed"] = relationship(
        "ThreatIntelFeed",
        back_populates="indicators",
    )

    def __repr__(self) -> str:
        return f"<ThreatIndicator {self.indicator_type.value}:{self.value[:50]}>"
