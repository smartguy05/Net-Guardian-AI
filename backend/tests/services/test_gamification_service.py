"""Tests for the gamification service."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.data.achievements import (
    ACHIEVEMENTS,
    LEVELS,
    POINT_VALUES,
    get_level_for_xp,
    get_title_for_level,
    get_xp_for_level,
)
from app.models.gamification import (
    Achievement,
    AchievementCategory,
    AchievementRarity,
    UserAchievement,
    UserStats,
)
from app.services.gamification_service import GamificationService


class TestAchievementData:
    """Tests for achievement definitions."""

    def test_achievements_have_required_fields(self):
        """Test that all achievements have required fields."""
        required_fields = ["name", "description", "category", "rarity", "icon", "points", "requirements"]
        for ach_id, ach in ACHIEVEMENTS.items():
            for field in required_fields:
                assert field in ach, f"Achievement {ach_id} missing {field}"

    def test_achievements_have_valid_categories(self):
        """Test that achievements use valid categories."""
        for ach_id, ach in ACHIEVEMENTS.items():
            assert isinstance(
                ach["category"], AchievementCategory
            ), f"Achievement {ach_id} has invalid category"

    def test_achievements_have_valid_rarities(self):
        """Test that achievements use valid rarities."""
        for ach_id, ach in ACHIEVEMENTS.items():
            assert isinstance(
                ach["rarity"], AchievementRarity
            ), f"Achievement {ach_id} has invalid rarity"

    def test_achievements_have_positive_points(self):
        """Test that achievements have positive point values."""
        for ach_id, ach in ACHIEVEMENTS.items():
            assert ach["points"] > 0, f"Achievement {ach_id} has non-positive points"

    def test_achievements_have_nonempty_requirements(self):
        """Test that achievements have at least one requirement."""
        for ach_id, ach in ACHIEVEMENTS.items():
            assert len(ach["requirements"]) > 0, f"Achievement {ach_id} has no requirements"


class TestLevelSystem:
    """Tests for level progression."""

    def test_levels_are_ordered(self):
        """Test that levels are in ascending order."""
        prev_level = 0
        prev_xp = 0
        for lvl in LEVELS:
            assert lvl["level"] > prev_level, "Levels not in ascending order"
            assert lvl["xp"] >= prev_xp, "XP requirements not in ascending order"
            prev_level = lvl["level"]
            prev_xp = lvl["xp"]

    def test_level_1_starts_at_0_xp(self):
        """Test that level 1 requires 0 XP."""
        assert LEVELS[0]["level"] == 1
        assert LEVELS[0]["xp"] == 0

    def test_all_levels_have_titles(self):
        """Test that all levels have titles."""
        for lvl in LEVELS:
            assert "title" in lvl
            assert len(lvl["title"]) > 0


class TestGetLevelForXp:
    """Tests for get_level_for_xp function."""

    def test_zero_xp_is_level_1(self):
        """Test that 0 XP gives level 1."""
        result = get_level_for_xp(0)
        assert result["level"] == 1
        assert result["title"] == "Novice Guardian"

    def test_100_xp_is_level_2(self):
        """Test that 100 XP gives level 2."""
        result = get_level_for_xp(100)
        assert result["level"] == 2

    def test_250_xp_is_level_3(self):
        """Test that 250 XP gives level 3."""
        result = get_level_for_xp(250)
        assert result["level"] == 3

    def test_xp_to_next_level_calculation(self):
        """Test XP to next level calculation."""
        result = get_level_for_xp(0)
        # Level 1 to 2 requires 100 XP
        assert result["xp_to_next_level"] == 100

    def test_high_xp_reaches_max_level(self):
        """Test that very high XP reaches the highest level."""
        result = get_level_for_xp(1000000)
        assert result["level"] == 50


class TestGetXpForLevel:
    """Tests for get_xp_for_level function."""

    def test_level_1_needs_0_xp(self):
        """Test level 1 requires 0 XP."""
        assert get_xp_for_level(1) == 0

    def test_level_5_needs_700_xp(self):
        """Test level 5 requires 700 XP."""
        assert get_xp_for_level(5) == 700

    def test_level_10_needs_3200_xp(self):
        """Test level 10 requires 3200 XP."""
        assert get_xp_for_level(10) == 3200

    def test_extrapolation_for_high_level(self):
        """Test extrapolation for levels above defined."""
        # Level 50 is max defined at 600000 XP
        # Level 51 should extrapolate to 600000 + 100000 = 700000
        result = get_xp_for_level(51)
        assert result == 700000


class TestGetTitleForLevel:
    """Tests for get_title_for_level function."""

    def test_level_1_title(self):
        """Test level 1 title."""
        assert get_title_for_level(1) == "Novice Guardian"

    def test_level_5_title(self):
        """Test level 5 title (Alert Watcher)."""
        assert get_title_for_level(5) == "Alert Watcher"

    def test_level_10_title(self):
        """Test level 10 title (Threat Hunter)."""
        assert get_title_for_level(10) == "Threat Hunter"

    def test_level_20_title(self):
        """Test level 20 title (Cyber Defender)."""
        assert get_title_for_level(20) == "Cyber Defender"

    def test_level_30_title(self):
        """Test level 30 title (Master Sentinel)."""
        assert get_title_for_level(30) == "Master Sentinel"


class TestPointValues:
    """Tests for point value definitions."""

    def test_alert_resolution_points_increase_with_severity(self):
        """Test that higher severity alerts give more points."""
        assert POINT_VALUES["alert_resolve_info"] < POINT_VALUES["alert_resolve_low"]
        assert POINT_VALUES["alert_resolve_low"] < POINT_VALUES["alert_resolve_medium"]
        assert POINT_VALUES["alert_resolve_medium"] < POINT_VALUES["alert_resolve_high"]
        assert POINT_VALUES["alert_resolve_high"] < POINT_VALUES["alert_resolve_critical"]

    def test_critical_alert_gives_100_points(self):
        """Test critical alert resolution gives 100 points."""
        assert POINT_VALUES["alert_resolve_critical"] == 100

    def test_anomaly_confirm_gives_25_points(self):
        """Test anomaly confirmation gives 25 points."""
        assert POINT_VALUES["anomaly_confirm"] == 25

    def test_device_quarantine_gives_30_points(self):
        """Test device quarantine gives 30 points."""
        assert POINT_VALUES["device_quarantine"] == 30


class TestGamificationService:
    """Tests for GamificationService class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        session.close = AsyncMock()
        return session

    @pytest.fixture
    def service(self, mock_session):
        """Create a service with mock session."""
        return GamificationService(mock_session)

    @pytest.mark.asyncio
    async def test_get_or_create_stats_creates_new(self, service, mock_session):
        """Test creating new user stats."""
        user_id = uuid4()

        # Mock no existing stats
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        # Mock refresh to set attributes
        async def set_stats_attrs(obj):
            obj.user_id = user_id
            obj.total_points = 0
            obj.current_level = 1
            obj.current_xp = 0
            obj.xp_to_next_level = 100
            obj.alerts_resolved = 0
            obj.critical_alerts_resolved = 0
            obj.anomalies_confirmed = 0
            obj.false_positives_marked = 0
            obj.devices_quarantined = 0
            obj.investigations_completed = 0
            obj.current_streak_days = 0
            obj.longest_streak_days = 0
            obj.last_activity_at = None
            obj.leaderboard_opt_in = False

        mock_session.refresh = AsyncMock(side_effect=set_stats_attrs)

        stats = await service.get_or_create_stats(user_id)

        assert stats.user_id == user_id
        assert stats.total_points == 0
        assert stats.current_level == 1
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_or_create_stats_returns_existing(self, service, mock_session):
        """Test returning existing user stats."""
        user_id = uuid4()

        # Create mock existing stats
        existing_stats = MagicMock(spec=UserStats)
        existing_stats.user_id = user_id
        existing_stats.total_points = 500
        existing_stats.current_level = 5

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_stats
        mock_session.execute = AsyncMock(return_value=mock_result)

        stats = await service.get_or_create_stats(user_id)

        assert stats.total_points == 500
        assert stats.current_level == 5
        mock_session.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_user_stats_returns_formatted_dict(self, service, mock_session):
        """Test get_user_stats returns properly formatted dict."""
        user_id = uuid4()

        # Create mock stats
        existing_stats = MagicMock(spec=UserStats)
        existing_stats.user_id = user_id
        existing_stats.total_points = 1000
        existing_stats.current_level = 5
        existing_stats.current_xp = 50
        existing_stats.xp_to_next_level = 300
        existing_stats.alerts_resolved = 20
        existing_stats.critical_alerts_resolved = 5
        existing_stats.anomalies_confirmed = 10
        existing_stats.false_positives_marked = 15
        existing_stats.devices_quarantined = 3
        existing_stats.investigations_completed = 2
        existing_stats.current_streak_days = 7
        existing_stats.longest_streak_days = 14
        existing_stats.last_activity_at = datetime.now(UTC)
        existing_stats.leaderboard_opt_in = True

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_stats
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await service.get_user_stats(user_id)

        assert result["user_id"] == str(user_id)
        assert result["total_points"] == 1000
        assert result["level"] == 5
        assert result["title"] == "Alert Watcher"
        assert "counters" in result
        assert result["counters"]["alerts_resolved"] == 20
        assert "streak" in result
        assert result["streak"]["current"] == 7
        assert result["leaderboard_opt_in"] is True


class TestAchievementChecking:
    """Tests for achievement checking logic."""

    def test_first_blood_requires_1_alert(self):
        """Test first_blood achievement requires 1 alert resolved."""
        ach = ACHIEVEMENTS["first_blood"]
        assert ach["requirements"]["alerts_resolved"] == 1

    def test_alert_hunter_requires_100_alerts(self):
        """Test alert_hunter achievement requires 100 alerts."""
        ach = ACHIEVEMENTS["alert_hunter"]
        assert ach["requirements"]["alerts_resolved"] == 100

    def test_critical_responder_requires_10_critical(self):
        """Test critical_responder requires 10 critical alerts."""
        ach = ACHIEVEMENTS["critical_responder"]
        assert ach["requirements"]["critical_alerts_resolved"] == 10

    def test_week_warrior_requires_7_day_streak(self):
        """Test week_warrior requires 7 day streak."""
        ach = ACHIEVEMENTS["week_warrior"]
        assert ach["requirements"]["streak_days"] == 7

    def test_night_owl_is_hidden(self):
        """Test night_owl achievement is hidden."""
        ach = ACHIEVEMENTS["night_owl"]
        assert ach["hidden"] is True

    def test_speed_demon_is_legendary(self):
        """Test speed_demon achievement is legendary rarity."""
        ach = ACHIEVEMENTS["speed_demon"]
        assert ach["rarity"] == AchievementRarity.LEGENDARY


class TestAchievementCategories:
    """Tests for achievement category distribution."""

    def test_has_alert_achievements(self):
        """Test there are alert-category achievements."""
        alert_achs = [
            a for a in ACHIEVEMENTS.values() if a["category"] == AchievementCategory.ALERTS
        ]
        assert len(alert_achs) >= 4

    def test_has_anomaly_achievements(self):
        """Test there are anomaly-category achievements."""
        anomaly_achs = [
            a for a in ACHIEVEMENTS.values() if a["category"] == AchievementCategory.ANOMALIES
        ]
        assert len(anomaly_achs) >= 2

    def test_has_device_achievements(self):
        """Test there are device-category achievements."""
        device_achs = [
            a for a in ACHIEVEMENTS.values() if a["category"] == AchievementCategory.DEVICES
        ]
        assert len(device_achs) >= 2

    def test_has_streak_achievements(self):
        """Test there are streak-category achievements."""
        streak_achs = [
            a for a in ACHIEVEMENTS.values() if a["category"] == AchievementCategory.STREAKS
        ]
        assert len(streak_achs) >= 4

    def test_has_milestone_achievements(self):
        """Test there are milestone-category achievements."""
        milestone_achs = [
            a for a in ACHIEVEMENTS.values() if a["category"] == AchievementCategory.MILESTONES
        ]
        assert len(milestone_achs) >= 4

    def test_has_special_achievements(self):
        """Test there are special-category achievements."""
        special_achs = [
            a for a in ACHIEVEMENTS.values() if a["category"] == AchievementCategory.SPECIAL
        ]
        assert len(special_achs) >= 5
