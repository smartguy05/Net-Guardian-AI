"""Gamification models for security achievements and leaderboards."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User


class AchievementRarity(StrEnum):
    """Rarity of an achievement."""

    COMMON = "common"
    UNCOMMON = "uncommon"
    RARE = "rare"
    LEGENDARY = "legendary"


class AchievementCategory(StrEnum):
    """Category of an achievement."""

    ALERTS = "alerts"
    ANOMALIES = "anomalies"
    DEVICES = "devices"
    INVESTIGATIONS = "investigations"
    STREAKS = "streaks"
    MILESTONES = "milestones"
    SPECIAL = "special"


class ChallengeType(StrEnum):
    """Type of challenge."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class ChallengeStatus(StrEnum):
    """Status of a challenge."""

    ACTIVE = "active"
    EXPIRED = "expired"
    COMPLETED = "completed"


class Achievement(Base, TimestampMixin):
    """Achievement definition model.

    Attributes:
        id: Unique identifier (string, e.g., "first_alert_resolved").
        name: Display name of the achievement.
        description: Detailed description.
        category: Achievement category.
        rarity: Achievement rarity level.
        icon: Icon name or URL.
        points: Points awarded when unlocked.
        requirements: JSON object with unlock requirements.
        hidden: Whether achievement is secret until unlocked.
        enabled: Whether achievement can be earned.
    """

    __tablename__ = "achievements"

    id: Mapped[str] = mapped_column(
        String(50),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    category: Mapped[AchievementCategory] = mapped_column(
        SQLEnum(
            AchievementCategory,
            name="achievementcategory",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        index=True,
    )
    rarity: Mapped[AchievementRarity] = mapped_column(
        SQLEnum(
            AchievementRarity,
            name="achievementrarity",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
    )
    icon: Mapped[str] = mapped_column(
        String(100),
        default="trophy",
        nullable=False,
    )
    points: Mapped[int] = mapped_column(
        Integer,
        default=10,
        nullable=False,
    )
    requirements: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    hidden: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    user_achievements: Mapped[list[UserAchievement]] = relationship(
        "UserAchievement",
        back_populates="achievement",
    )

    def __repr__(self) -> str:
        return f"<Achievement {self.id}: {self.name}>"


class UserAchievement(Base, TimestampMixin):
    """User achievement unlock record.

    Attributes:
        id: Unique identifier (UUID).
        user_id: User who earned the achievement.
        achievement_id: Achievement that was earned.
        earned_at: When the achievement was unlocked.
        context: JSON object with context about how it was earned.
    """

    __tablename__ = "user_achievements"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    achievement_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("achievements.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    earned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    context: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
    )

    # Relationships
    user: Mapped[User] = relationship(
        "User",
        foreign_keys=[user_id],
    )
    achievement: Mapped[Achievement] = relationship(
        "Achievement",
        back_populates="user_achievements",
    )

    __table_args__ = (
        Index("ix_user_achievements_user_achievement", "user_id", "achievement_id", unique=True),
    )

    def __repr__(self) -> str:
        return f"<UserAchievement {self.user_id}: {self.achievement_id}>"


class UserStats(Base, TimestampMixin):
    """User gamification stats.

    Attributes:
        user_id: User this record belongs to.
        total_points: Total points earned all-time.
        current_level: Current level.
        current_xp: XP towards next level.
        xp_to_next_level: XP required for next level.
        alerts_resolved: Total alerts resolved.
        anomalies_confirmed: Total anomalies confirmed.
        false_positives_marked: Total false positives marked.
        devices_quarantined: Total devices quarantined.
        investigations_completed: Total investigations completed.
        current_streak_days: Current daily activity streak.
        longest_streak_days: Longest streak ever.
        last_activity_at: Last activity timestamp.
        leaderboard_opt_in: Whether user appears on leaderboard.
    """

    __tablename__ = "user_stats"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    total_points: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    current_level: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    current_xp: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    xp_to_next_level: Mapped[int] = mapped_column(
        Integer,
        default=100,
        nullable=False,
    )

    # Counters
    alerts_resolved: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    critical_alerts_resolved: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    anomalies_confirmed: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    false_positives_marked: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    devices_quarantined: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    investigations_completed: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    # Streaks
    current_streak_days: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    longest_streak_days: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    last_activity_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
    )
    last_activity_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Preferences
    leaderboard_opt_in: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    user: Mapped[User] = relationship(
        "User",
        foreign_keys=[user_id],
    )

    __table_args__ = (
        Index("ix_user_stats_total_points", "total_points"),
        Index("ix_user_stats_current_level", "current_level"),
    )

    def __repr__(self) -> str:
        return f"<UserStats {self.user_id}: Level {self.current_level}>"


class Challenge(Base, TimestampMixin):
    """Challenge definition model.

    Attributes:
        id: Unique identifier (UUID).
        name: Display name of the challenge.
        description: Detailed description.
        challenge_type: Type of challenge (daily, weekly, monthly).
        start_date: When the challenge starts.
        end_date: When the challenge ends.
        requirements: JSON object with completion requirements.
        reward_points: Points awarded on completion.
        reward_achievement_id: Achievement awarded on completion (optional).
        enabled: Whether challenge is active.
    """

    __tablename__ = "challenges"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    challenge_type: Mapped[ChallengeType] = mapped_column(
        SQLEnum(
            ChallengeType,
            name="challengetype",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        index=True,
    )
    start_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        index=True,
    )
    end_date: Mapped[date] = mapped_column(
        Date,
        nullable=False,
        index=True,
    )
    requirements: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    reward_points: Mapped[int] = mapped_column(
        Integer,
        default=50,
        nullable=False,
    )
    reward_achievement_id: Mapped[str | None] = mapped_column(
        String(50),
        ForeignKey("achievements.id", ondelete="SET NULL"),
        nullable=True,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    user_challenges: Mapped[list[UserChallenge]] = relationship(
        "UserChallenge",
        back_populates="challenge",
    )
    reward_achievement: Mapped[Achievement | None] = relationship(
        "Achievement",
        foreign_keys=[reward_achievement_id],
    )

    __table_args__ = (
        Index("ix_challenges_active", "start_date", "end_date", "enabled"),
    )

    def __repr__(self) -> str:
        return f"<Challenge {self.name} ({self.challenge_type.value})>"


class UserChallenge(Base, TimestampMixin):
    """User challenge progress record.

    Attributes:
        id: Unique identifier (UUID).
        user_id: User participating in the challenge.
        challenge_id: Challenge being tracked.
        progress: JSON object with current progress.
        completed: Whether challenge is completed.
        completed_at: When challenge was completed.
    """

    __tablename__ = "user_challenges"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    progress: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    completed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    user: Mapped[User] = relationship(
        "User",
        foreign_keys=[user_id],
    )
    challenge: Mapped[Challenge] = relationship(
        "Challenge",
        back_populates="user_challenges",
    )

    __table_args__ = (
        Index("ix_user_challenges_user_challenge", "user_id", "challenge_id", unique=True),
    )

    def __repr__(self) -> str:
        return f"<UserChallenge {self.user_id}: {self.challenge_id}>"
