"""Gamification service for managing achievements, points, and leaderboards."""

from datetime import UTC, date, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import structlog
from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.data.achievements import (
    ACHIEVEMENTS,
    POINT_VALUES,
    get_level_for_xp,
    get_title_for_level,
    get_xp_for_level,
)
from app.db.session import AsyncSessionLocal
from app.models.alert import AlertSeverity
from app.models.gamification import (
    Achievement,
    AchievementCategory,
    AchievementRarity,
    Challenge,
    UserAchievement,
    UserChallenge,
    UserStats,
)

logger = structlog.get_logger()


class GamificationService:
    """Service for managing gamification features."""

    def __init__(self, session: AsyncSession | None = None):
        """Initialize the gamification service.

        Args:
            session: Optional database session.
        """
        self._session = session

    async def _get_session(self) -> AsyncSession:
        """Get a database session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    async def _close_session(self, session: AsyncSession) -> None:
        """Close session if it was created internally."""
        if session != self._session:
            await session.close()

    # ==================== USER STATS ====================

    async def get_or_create_stats(self, user_id: UUID) -> UserStats:
        """Get or create user stats record.

        Args:
            user_id: User's UUID.

        Returns:
            UserStats object.
        """
        session = await self._get_session()
        try:
            result = await session.execute(select(UserStats).where(UserStats.user_id == user_id))
            stats = result.scalar_one_or_none()

            if not stats:
                stats = UserStats(
                    user_id=user_id,
                    total_points=0,
                    current_level=1,
                    current_xp=0,
                    xp_to_next_level=100,
                )
                session.add(stats)
                await session.commit()
                await session.refresh(stats)
                logger.info("user_stats_created", user_id=str(user_id))

            return stats
        finally:
            await self._close_session(session)

    async def get_user_stats(self, user_id: UUID) -> dict[str, Any]:
        """Get user stats with level info.

        Args:
            user_id: User's UUID.

        Returns:
            Dict with stats and level information.
        """
        stats = await self.get_or_create_stats(user_id)

        get_level_for_xp(stats.current_xp + (stats.current_level - 1) * 100)

        return {
            "user_id": str(stats.user_id),
            "total_points": stats.total_points,
            "level": stats.current_level,
            "title": get_title_for_level(stats.current_level),
            "current_xp": stats.current_xp,
            "xp_to_next_level": stats.xp_to_next_level,
            "xp_progress_percent": (
                (stats.current_xp / stats.xp_to_next_level * 100)
                if stats.xp_to_next_level > 0
                else 100
            ),
            "counters": {
                "alerts_resolved": stats.alerts_resolved,
                "critical_alerts_resolved": stats.critical_alerts_resolved,
                "anomalies_confirmed": stats.anomalies_confirmed,
                "false_positives_marked": stats.false_positives_marked,
                "devices_quarantined": stats.devices_quarantined,
                "investigations_completed": stats.investigations_completed,
            },
            "streak": {
                "current": stats.current_streak_days,
                "longest": stats.longest_streak_days,
            },
            "leaderboard_opt_in": stats.leaderboard_opt_in,
            "last_activity": stats.last_activity_at.isoformat() if stats.last_activity_at else None,
        }

    # ==================== POINTS & LEVELS ====================

    async def award_points(
        self,
        user_id: UUID,
        points: int,
        reason: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Award points to a user and check for level up.

        Args:
            user_id: User's UUID.
            points: Points to award.
            reason: Reason for award.
            context: Additional context.

        Returns:
            Dict with points awarded and level up info.
        """
        if not settings.gamification_enabled:
            return {"points_awarded": 0, "level_up": False}

        # Apply multiplier
        points = int(points * settings.gamification_points_multiplier)

        session = await self._get_session()
        try:
            stats = await self.get_or_create_stats(user_id)

            old_level = stats.current_level

            # Add points
            stats.total_points += points
            stats.current_xp += points

            # Check for level up
            level_up = False
            new_level = old_level

            while stats.current_xp >= stats.xp_to_next_level:
                stats.current_xp -= stats.xp_to_next_level
                stats.current_level += 1
                new_level = stats.current_level

                # Calculate XP for next level (increases each level)
                next_level_xp = get_xp_for_level(stats.current_level + 1)
                current_level_xp = get_xp_for_level(stats.current_level)
                stats.xp_to_next_level = next_level_xp - current_level_xp

                level_up = True

            # Update activity
            stats.last_activity_at = datetime.now(UTC)
            stats.last_activity_date = date.today()

            session.add(stats)
            await session.commit()

            result: dict[str, Any] = {
                "points_awarded": points,
                "total_points": stats.total_points,
                "level_up": level_up,
                "old_level": old_level,
                "new_level": new_level,
                "current_xp": stats.current_xp,
                "xp_to_next_level": stats.xp_to_next_level,
            }

            if level_up:
                result["new_title"] = get_title_for_level(new_level)
                logger.info(
                    "user_level_up",
                    user_id=str(user_id),
                    old_level=old_level,
                    new_level=new_level,
                )

            logger.debug(
                "points_awarded",
                user_id=str(user_id),
                points=points,
                reason=reason,
            )

            return result

        finally:
            await self._close_session(session)

    def get_points_for_action(self, action: str, severity: str | None = None) -> int:
        """Get point value for an action.

        Args:
            action: Action type.
            severity: Optional severity for alerts.

        Returns:
            Point value.
        """
        if severity:
            key = f"alert_resolve_{severity.lower()}"
            return POINT_VALUES.get(key, POINT_VALUES.get(action, 10))
        return POINT_VALUES.get(action, 10)

    # ==================== COUNTERS ====================

    async def increment_counter(
        self,
        user_id: UUID,
        counter: str,
        amount: int = 1,
    ) -> int:
        """Increment a counter for a user.

        Args:
            user_id: User's UUID.
            counter: Counter name (e.g., 'alerts_resolved').
            amount: Amount to increment.

        Returns:
            New counter value.
        """
        session = await self._get_session()
        try:
            stats = await self.get_or_create_stats(user_id)

            current_value = getattr(stats, counter, 0)
            new_value = current_value + amount
            setattr(stats, counter, new_value)

            session.add(stats)
            await session.commit()

            return new_value

        finally:
            await self._close_session(session)

    # ==================== STREAKS ====================

    async def update_streak(self, user_id: UUID) -> dict[str, Any]:
        """Update user's activity streak.

        Args:
            user_id: User's UUID.

        Returns:
            Dict with streak info.
        """
        session = await self._get_session()
        try:
            stats = await self.get_or_create_stats(user_id)

            today = date.today()
            yesterday = today - timedelta(days=1)

            old_streak = stats.current_streak_days

            if stats.last_activity_date == today:
                # Already active today, no change
                pass
            elif stats.last_activity_date == yesterday:
                # Consecutive day, increment streak
                stats.current_streak_days += 1
                if stats.current_streak_days > stats.longest_streak_days:
                    stats.longest_streak_days = stats.current_streak_days
            else:
                # Streak broken, reset to 1
                stats.current_streak_days = 1

            stats.last_activity_date = today
            stats.last_activity_at = datetime.now(UTC)

            session.add(stats)
            await session.commit()

            streak_increased = stats.current_streak_days > old_streak

            return {
                "current_streak": stats.current_streak_days,
                "longest_streak": stats.longest_streak_days,
                "streak_increased": streak_increased,
            }

        finally:
            await self._close_session(session)

    # ==================== ACHIEVEMENTS ====================

    async def sync_achievements(self) -> int:
        """Sync achievement definitions to database.

        Returns:
            Number of achievements synced.
        """
        session = await self._get_session()
        try:
            count = 0
            for achievement_id, data in ACHIEVEMENTS.items():
                result = await session.execute(
                    select(Achievement).where(Achievement.id == achievement_id)
                )
                existing = result.scalar_one_or_none()

                if existing:
                    # Update existing
                    existing.name = cast(str, data["name"])
                    existing.description = cast(str, data["description"])
                    existing.category = cast(AchievementCategory, data["category"])
                    existing.rarity = cast(AchievementRarity, data["rarity"])
                    existing.icon = cast(str, data.get("icon", "trophy"))
                    existing.points = cast(int, data.get("points", 10))
                    existing.requirements = cast(dict[str, Any], data.get("requirements", {}))
                    existing.hidden = cast(bool, data.get("hidden", False))
                else:
                    # Create new
                    achievement = Achievement(
                        id=achievement_id,
                        name=cast(str, data["name"]),
                        description=cast(str, data["description"]),
                        category=cast(AchievementCategory, data["category"]),
                        rarity=cast(AchievementRarity, data["rarity"]),
                        icon=cast(str, data.get("icon", "trophy")),
                        points=cast(int, data.get("points", 10)),
                        requirements=cast(dict[str, Any], data.get("requirements", {})),
                        hidden=cast(bool, data.get("hidden", False)),
                    )
                    session.add(achievement)

                count += 1

            await session.commit()
            logger.info("achievements_synced", count=count)
            return count

        finally:
            await self._close_session(session)

    async def get_all_achievements(
        self,
        user_id: UUID | None = None,
        category: AchievementCategory | None = None,
        include_hidden: bool = False,
    ) -> list[dict[str, Any]]:
        """Get all achievements with optional user unlock status.

        Args:
            user_id: Optional user to check unlock status.
            category: Optional category filter.
            include_hidden: Whether to include hidden achievements.

        Returns:
            List of achievement dicts.
        """
        session = await self._get_session()
        try:
            query = select(Achievement).where(Achievement.enabled == True)  # noqa: E712

            if category:
                query = query.where(Achievement.category == category)

            result = await session.execute(query)
            achievements = result.scalars().all()

            # Get user unlocks if user specified
            user_unlocks = {}
            if user_id:
                unlock_result = await session.execute(
                    select(UserAchievement).where(UserAchievement.user_id == user_id)
                )
                for ua in unlock_result.scalars().all():
                    user_unlocks[ua.achievement_id] = ua

            output = []
            for a in achievements:
                is_unlocked = a.id in user_unlocks

                # Skip hidden achievements that aren't unlocked
                if a.hidden and not is_unlocked and not include_hidden:
                    continue

                achievement_data: dict[str, Any] = {
                    "id": a.id,
                    "name": a.name if not a.hidden or is_unlocked else "???",
                    "description": a.description
                    if not a.hidden or is_unlocked
                    else "Hidden achievement",
                    "category": a.category.value,
                    "rarity": a.rarity.value,
                    "icon": a.icon,
                    "points": a.points,
                    "hidden": a.hidden,
                    "unlocked": is_unlocked,
                }

                if is_unlocked:
                    ua = user_unlocks[a.id]
                    achievement_data["earned_at"] = ua.earned_at.isoformat()
                    achievement_data["context"] = ua.context

                output.append(achievement_data)

            return output

        finally:
            await self._close_session(session)

    async def get_recent_achievements(
        self,
        user_id: UUID,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Get recently unlocked achievements for a user.

        Args:
            user_id: User's UUID.
            limit: Max achievements to return.

        Returns:
            List of achievement dicts.
        """
        session = await self._get_session()
        try:
            result = await session.execute(
                select(UserAchievement)
                .where(UserAchievement.user_id == user_id)
                .order_by(desc(UserAchievement.earned_at))
                .limit(limit)
            )

            output = []
            for ua in result.scalars().all():
                achievement_result = await session.execute(
                    select(Achievement).where(Achievement.id == ua.achievement_id)
                )
                achievement = achievement_result.scalar_one_or_none()

                if achievement:
                    output.append(
                        {
                            "id": achievement.id,
                            "name": achievement.name,
                            "description": achievement.description,
                            "category": achievement.category.value,
                            "rarity": achievement.rarity.value,
                            "icon": achievement.icon,
                            "points": achievement.points,
                            "earned_at": ua.earned_at.isoformat(),
                        }
                    )

            return output

        finally:
            await self._close_session(session)

    async def check_achievements(
        self,
        user_id: UUID,
        event_type: str,
        context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Check and unlock achievements based on event.

        Args:
            user_id: User's UUID.
            event_type: Type of event that occurred.
            context: Event context.

        Returns:
            List of newly unlocked achievements.
        """
        if not settings.gamification_enabled:
            return []

        session = await self._get_session()
        try:
            stats = await self.get_or_create_stats(user_id)
            context = context or {}

            # Get user's current achievements
            result = await session.execute(
                select(UserAchievement.achievement_id).where(UserAchievement.user_id == user_id)
            )
            unlocked_ids = {row[0] for row in result.all()}

            # Check each achievement
            newly_unlocked = []

            for achievement_id, data in ACHIEVEMENTS.items():
                if achievement_id in unlocked_ids:
                    continue

                requirements = cast(dict[str, Any], data.get("requirements", {}))

                # Check counter-based requirements
                if self._check_requirements(stats, requirements, context):
                    # Unlock achievement
                    ua = UserAchievement(
                        user_id=user_id,
                        achievement_id=achievement_id,
                        earned_at=datetime.now(UTC),
                        context=context,
                    )
                    session.add(ua)

                    achievement_points = cast(int, data.get("points", 10))
                    newly_unlocked.append(
                        {
                            "id": achievement_id,
                            "name": data["name"],
                            "description": data["description"],
                            "category": cast(AchievementCategory, data["category"]).value,
                            "rarity": cast(AchievementRarity, data["rarity"]).value,
                            "icon": data.get("icon", "trophy"),
                            "points": achievement_points,
                        }
                    )

                    # Award achievement points
                    stats.total_points += achievement_points
                    stats.current_xp += achievement_points

                    logger.info(
                        "achievement_unlocked",
                        user_id=str(user_id),
                        achievement=achievement_id,
                    )

            if newly_unlocked:
                session.add(stats)
                await session.commit()

            return newly_unlocked

        finally:
            await self._close_session(session)

    def _check_requirements(
        self,
        stats: UserStats,
        requirements: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        """Check if requirements are met.

        Args:
            stats: User's stats.
            requirements: Achievement requirements.
            context: Event context.

        Returns:
            True if all requirements met.
        """
        for key, value in requirements.items():
            # Counter-based requirements
            if key == "alerts_resolved":
                if stats.alerts_resolved < value:
                    return False
            elif key == "critical_alerts_resolved":
                if stats.critical_alerts_resolved < value:
                    return False
            elif key == "anomalies_confirmed":
                if stats.anomalies_confirmed < value:
                    return False
            elif key == "false_positives_marked":
                if stats.false_positives_marked < value:
                    return False
            elif key == "devices_quarantined":
                if stats.devices_quarantined < value:
                    return False
            elif key == "investigations_completed":
                if stats.investigations_completed < value:
                    return False
            elif key == "streak_days":
                if stats.current_streak_days < value:
                    return False
            elif key == "level":
                if stats.current_level < value:
                    return False
            elif key == "total_points":
                if stats.total_points < value:
                    return False
            # Context-based requirements (special achievements)
            elif key in context:
                if not context.get(key):
                    return False

        return True

    async def unlock_achievement(
        self,
        user_id: UUID,
        achievement_id: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Manually unlock an achievement.

        Args:
            user_id: User's UUID.
            achievement_id: Achievement to unlock.
            context: Unlock context.

        Returns:
            Achievement data or None if already unlocked.
        """
        session = await self._get_session()
        try:
            # Check if already unlocked
            result = await session.execute(
                select(UserAchievement).where(
                    and_(
                        UserAchievement.user_id == user_id,
                        UserAchievement.achievement_id == achievement_id,
                    )
                )
            )
            if result.scalar_one_or_none():
                return None

            # Get achievement
            achievement_data = ACHIEVEMENTS.get(achievement_id)
            if not achievement_data:
                return None

            # Create unlock
            ua = UserAchievement(
                user_id=user_id,
                achievement_id=achievement_id,
                earned_at=datetime.now(UTC),
                context=context,
            )
            session.add(ua)

            # Award points
            stats = await self.get_or_create_stats(user_id)
            points = cast(int, achievement_data.get("points", 10))
            stats.total_points += points
            stats.current_xp += points
            session.add(stats)

            await session.commit()

            logger.info(
                "achievement_manually_unlocked",
                user_id=str(user_id),
                achievement=achievement_id,
            )

            return {
                "id": achievement_id,
                "name": achievement_data["name"],
                "description": achievement_data["description"],
                "category": cast(AchievementCategory, achievement_data["category"]).value,
                "rarity": cast(AchievementRarity, achievement_data["rarity"]).value,
                "icon": achievement_data.get("icon", "trophy"),
                "points": points,
            }

        finally:
            await self._close_session(session)

    # ==================== LEADERBOARD ====================

    async def get_leaderboard(
        self,
        period: str = "all_time",
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get leaderboard.

        Args:
            period: Time period ('all_time', 'weekly', 'monthly').
            limit: Max entries.

        Returns:
            List of leaderboard entries.
        """
        if not settings.gamification_leaderboard_enabled:
            return []

        session = await self._get_session()
        try:
            # For now, just use total points for all periods
            # A more advanced implementation would track weekly/monthly points separately
            result = await session.execute(
                select(UserStats)
                .where(UserStats.leaderboard_opt_in == True)  # noqa: E712
                .order_by(desc(UserStats.total_points))
                .limit(limit)
            )

            output = []
            rank = 1
            for stats in result.scalars().all():
                output.append(
                    {
                        "rank": rank,
                        "user_id": str(stats.user_id),
                        "total_points": stats.total_points,
                        "level": stats.current_level,
                        "title": get_title_for_level(stats.current_level),
                        "alerts_resolved": stats.alerts_resolved,
                        "current_streak": stats.current_streak_days,
                    }
                )
                rank += 1

            return output

        finally:
            await self._close_session(session)

    async def toggle_leaderboard_opt_in(self, user_id: UUID) -> bool:
        """Toggle user's leaderboard visibility.

        Args:
            user_id: User's UUID.

        Returns:
            New opt-in status.
        """
        session = await self._get_session()
        try:
            stats = await self.get_or_create_stats(user_id)
            stats.leaderboard_opt_in = not stats.leaderboard_opt_in
            session.add(stats)
            await session.commit()
            return stats.leaderboard_opt_in

        finally:
            await self._close_session(session)

    # ==================== CHALLENGES ====================

    async def get_active_challenges(
        self,
        user_id: UUID | None = None,
    ) -> list[dict[str, Any]]:
        """Get active challenges with optional user progress.

        Args:
            user_id: Optional user for progress.

        Returns:
            List of challenge dicts.
        """
        session = await self._get_session()
        try:
            today = date.today()

            result = await session.execute(
                select(Challenge).where(
                    and_(
                        Challenge.enabled == True,  # noqa: E712
                        Challenge.start_date <= today,
                        Challenge.end_date >= today,
                    )
                )
            )

            # Get user progress if specified
            user_progress = {}
            if user_id:
                progress_result = await session.execute(
                    select(UserChallenge).where(UserChallenge.user_id == user_id)
                )
                for uc in progress_result.scalars().all():
                    user_progress[uc.challenge_id] = uc

            output = []
            for challenge in result.scalars().all():
                challenge_data = {
                    "id": str(challenge.id),
                    "name": challenge.name,
                    "description": challenge.description,
                    "challenge_type": challenge.challenge_type.value,
                    "start_date": challenge.start_date.isoformat(),
                    "end_date": challenge.end_date.isoformat(),
                    "requirements": challenge.requirements,
                    "reward_points": challenge.reward_points,
                    "reward_achievement_id": challenge.reward_achievement_id,
                }

                if challenge.id in user_progress:
                    uc = user_progress[challenge.id]
                    challenge_data["progress"] = uc.progress
                    challenge_data["completed"] = uc.completed
                    if uc.completed_at:
                        challenge_data["completed_at"] = uc.completed_at.isoformat()

                output.append(challenge_data)

            return output

        finally:
            await self._close_session(session)

    async def update_challenge_progress(
        self,
        user_id: UUID,
        challenge_id: UUID,
        progress: dict[str, Any],
    ) -> dict[str, Any]:
        """Update user's progress on a challenge.

        Args:
            user_id: User's UUID.
            challenge_id: Challenge UUID.
            progress: Progress data.

        Returns:
            Updated challenge progress.
        """
        session = await self._get_session()
        try:
            # Get or create user challenge
            result = await session.execute(
                select(UserChallenge).where(
                    and_(
                        UserChallenge.user_id == user_id,
                        UserChallenge.challenge_id == challenge_id,
                    )
                )
            )
            uc = result.scalar_one_or_none()

            if not uc:
                uc = UserChallenge(
                    user_id=user_id,
                    challenge_id=challenge_id,
                    progress={},
                )

            # Update progress
            uc.progress.update(progress)
            session.add(uc)

            # Check if challenge completed
            challenge_result = await session.execute(
                select(Challenge).where(Challenge.id == challenge_id)
            )
            challenge = challenge_result.scalar_one_or_none()

            completed = False
            if challenge and not uc.completed:
                completed = self._check_challenge_complete(challenge.requirements, uc.progress)
                if completed:
                    uc.completed = True
                    uc.completed_at = datetime.now(UTC)

                    # Award points
                    await self.award_points(
                        user_id,
                        challenge.reward_points,
                        f"challenge_complete:{challenge.name}",
                    )

                    # Award achievement if specified
                    if challenge.reward_achievement_id:
                        await self.unlock_achievement(
                            user_id,
                            challenge.reward_achievement_id,
                            {"challenge_id": str(challenge_id)},
                        )

            await session.commit()

            return {
                "challenge_id": str(challenge_id),
                "progress": uc.progress,
                "completed": uc.completed,
                "just_completed": completed,
            }

        finally:
            await self._close_session(session)

    def _check_challenge_complete(
        self,
        requirements: dict[str, Any],
        progress: dict[str, Any],
    ) -> bool:
        """Check if challenge requirements are met.

        Args:
            requirements: Challenge requirements.
            progress: User's progress.

        Returns:
            True if complete.
        """
        for key, target in requirements.items():
            current = progress.get(key, 0)
            if isinstance(target, (int, float)) and isinstance(current, (int, float)):
                if current < target:
                    return False
            elif current != target:
                return False
        return True


# ==================== EVENT HANDLERS ====================


async def on_alert_resolved(
    user_id: UUID,
    severity: AlertSeverity,
    response_time_seconds: int | None = None,
) -> dict[str, Any]:
    """Handle alert resolution for gamification.

    Args:
        user_id: User who resolved the alert.
        severity: Alert severity.
        response_time_seconds: How long it took to resolve.

    Returns:
        Gamification result.
    """
    service = get_gamification_service()

    # Update streak
    await service.update_streak(user_id)

    # Increment counters
    await service.increment_counter(user_id, "alerts_resolved")
    if severity == AlertSeverity.CRITICAL:
        await service.increment_counter(user_id, "critical_alerts_resolved")

    # Award points
    points = service.get_points_for_action("alert_resolve", severity.value)
    point_result = await service.award_points(
        user_id,
        points,
        f"alert_resolved:{severity.value}",
    )

    # Check achievements
    context = {
        "severity": severity.value,
        "response_time_seconds": response_time_seconds,
    }

    # Check for special achievements
    now = datetime.now(UTC)
    if 2 <= now.hour < 5:
        context["night_alert"] = True
    if now.hour < 6:
        context["early_response"] = True
    if response_time_seconds and response_time_seconds < 60 and severity == AlertSeverity.CRITICAL:
        context["fast_critical_response"] = True
    if now.weekday() >= 5:  # Saturday or Sunday
        context["weekend_resolution"] = True

    achievements = await service.check_achievements(user_id, "alert_resolved", context)

    return {
        "points": point_result,
        "achievements": achievements,
    }


async def on_anomaly_action(
    user_id: UUID,
    action: str,  # "confirm" or "false_positive"
) -> dict[str, Any]:
    """Handle anomaly action for gamification.

    Args:
        user_id: User who acted.
        action: Action taken.

    Returns:
        Gamification result.
    """
    service = get_gamification_service()

    await service.update_streak(user_id)

    if action == "confirm":
        await service.increment_counter(user_id, "anomalies_confirmed")
        points = service.get_points_for_action("anomaly_confirm")
    else:
        await service.increment_counter(user_id, "false_positives_marked")
        points = service.get_points_for_action("anomaly_false_positive")

    point_result = await service.award_points(user_id, points, f"anomaly_{action}")
    achievements = await service.check_achievements(user_id, f"anomaly_{action}")

    return {
        "points": point_result,
        "achievements": achievements,
    }


async def on_device_quarantined(user_id: UUID) -> dict[str, Any]:
    """Handle device quarantine for gamification.

    Args:
        user_id: User who quarantined.

    Returns:
        Gamification result.
    """
    service = get_gamification_service()

    await service.update_streak(user_id)
    await service.increment_counter(user_id, "devices_quarantined")

    points = service.get_points_for_action("device_quarantine")
    point_result = await service.award_points(user_id, points, "device_quarantine")
    achievements = await service.check_achievements(user_id, "device_quarantine")

    return {
        "points": point_result,
        "achievements": achievements,
    }


async def on_investigation_completed(user_id: UUID) -> dict[str, Any]:
    """Handle investigation completion for gamification.

    Args:
        user_id: User who completed investigation.

    Returns:
        Gamification result.
    """
    service = get_gamification_service()

    await service.update_streak(user_id)
    await service.increment_counter(user_id, "investigations_completed")

    points = service.get_points_for_action("investigation_complete")
    point_result = await service.award_points(user_id, points, "investigation_complete")
    achievements = await service.check_achievements(user_id, "investigation_complete")

    return {
        "points": point_result,
        "achievements": achievements,
    }


# Global service instance
_gamification_service: GamificationService | None = None


def get_gamification_service() -> GamificationService:
    """Get the global gamification service instance."""
    global _gamification_service
    if _gamification_service is None:
        _gamification_service = GamificationService()
    return _gamification_service
