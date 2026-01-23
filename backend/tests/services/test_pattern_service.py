"""Tests for the pattern service."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.pattern_service import (
    PatternService,
    PatternStats,
    PatternFilters,
    get_pattern_service,
)


class TestPatternServiceInit:
    """Tests for PatternService initialization."""

    def test_creates_instance_without_session(self):
        """Should create instance without a session."""
        service = PatternService()
        assert service is not None
        assert service._session is None

    def test_creates_instance_with_session(self):
        """Should create instance with provided session."""
        mock_session = MagicMock()
        service = PatternService(session=mock_session)
        assert service._session is mock_session


class TestPatternFilters:
    """Tests for PatternFilters dataclass."""

    def test_default_values(self):
        """Should have correct default values."""
        filters = PatternFilters()

        assert filters.source_id is None
        assert filters.is_ignored is None
        assert filters.rare_only is False
        assert filters.rarity_threshold == 3
        assert filters.search is None
        assert filters.limit == 100
        assert filters.offset == 0

    def test_custom_values(self):
        """Should accept custom values."""
        filters = PatternFilters(
            source_id="test-source",
            is_ignored=True,
            rare_only=True,
            rarity_threshold=5,
            search="error",
            limit=50,
            offset=10,
        )

        assert filters.source_id == "test-source"
        assert filters.is_ignored is True
        assert filters.rare_only is True
        assert filters.rarity_threshold == 5
        assert filters.search == "error"
        assert filters.limit == 50
        assert filters.offset == 10


class TestPatternStats:
    """Tests for PatternStats dataclass."""

    def test_creates_stats_object(self):
        """Should create stats object with all fields."""
        stats = PatternStats(
            total_patterns=100,
            ignored_patterns=5,
            rare_patterns=20,
            total_occurrences=5000,
            avg_occurrences=50.0,
        )

        assert stats.total_patterns == 100
        assert stats.ignored_patterns == 5
        assert stats.rare_patterns == 20
        assert stats.total_occurrences == 5000
        assert stats.avg_occurrences == 50.0


class TestIsPatternRare:
    """Tests for is_pattern_rare method."""

    @pytest.mark.asyncio
    async def test_pattern_is_rare_below_threshold(self):
        """Pattern with count below threshold should be rare."""
        service = PatternService()

        mock_pattern = MagicMock()
        mock_pattern.occurrence_count = 2

        result = await service.is_pattern_rare(mock_pattern, default_threshold=3)
        assert result is True

    @pytest.mark.asyncio
    async def test_pattern_not_rare_at_threshold(self):
        """Pattern with count at threshold should not be rare."""
        service = PatternService()

        mock_pattern = MagicMock()
        mock_pattern.occurrence_count = 3

        result = await service.is_pattern_rare(mock_pattern, default_threshold=3)
        assert result is False

    @pytest.mark.asyncio
    async def test_pattern_not_rare_above_threshold(self):
        """Pattern with count above threshold should not be rare."""
        service = PatternService()

        mock_pattern = MagicMock()
        mock_pattern.occurrence_count = 10

        result = await service.is_pattern_rare(mock_pattern, default_threshold=3)
        assert result is False

    @pytest.mark.asyncio
    async def test_uses_config_threshold(self):
        """Should use threshold from config if provided."""
        service = PatternService()

        mock_pattern = MagicMock()
        mock_pattern.occurrence_count = 4

        mock_config = MagicMock()
        mock_config.rarity_threshold = 5

        result = await service.is_pattern_rare(mock_pattern, config=mock_config)
        assert result is True  # 4 < 5

    @pytest.mark.asyncio
    async def test_config_threshold_overrides_default(self):
        """Config threshold should override default."""
        service = PatternService()

        mock_pattern = MagicMock()
        mock_pattern.occurrence_count = 4

        mock_config = MagicMock()
        mock_config.rarity_threshold = 3

        result = await service.is_pattern_rare(
            mock_pattern, config=mock_config, default_threshold=10
        )
        assert result is False  # Uses config threshold 3, not default 10


class TestGetPatternService:
    """Tests for get_pattern_service factory function."""

    def test_returns_pattern_service_without_session(self):
        """Should return PatternService without session."""
        service = get_pattern_service()
        assert isinstance(service, PatternService)
        assert service._session is None

    def test_returns_pattern_service_with_session(self):
        """Should return PatternService with session."""
        mock_session = MagicMock()
        service = get_pattern_service(session=mock_session)
        assert isinstance(service, PatternService)
        assert service._session is mock_session


class TestRecordPatternMocked:
    """Tests for record_pattern with mocked database."""

    @pytest.mark.asyncio
    async def test_normalizes_message_before_recording(self):
        """Should normalize message before recording pattern."""
        with patch("app.services.pattern_service.PatternNormalizer") as MockNormalizer:
            MockNormalizer.normalize.return_value = ("<IP> connected", "hash123")

            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_pattern = MagicMock()
            mock_result.scalar_one.return_value = mock_pattern
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            service = PatternService(session=mock_session)

            await service.record_pattern(
                source_id="test-source",
                message="192.168.1.1 connected",
            )

            MockNormalizer.normalize.assert_called_once_with("192.168.1.1 connected")


class TestPatternServiceIntegration:
    """Integration-like tests with mocked session."""

    @pytest.mark.asyncio
    async def test_get_session_returns_provided_session(self):
        """Should return the provided session."""
        mock_session = MagicMock()
        service = PatternService(session=mock_session)

        result = await service._get_session()
        assert result is mock_session

    @pytest.mark.asyncio
    async def test_get_session_creates_new_when_none(self):
        """Should create new session when none provided."""
        with patch("app.services.pattern_service.AsyncSessionLocal") as MockSession:
            mock_new_session = MagicMock()
            MockSession.return_value = mock_new_session

            service = PatternService()
            result = await service._get_session()

            assert result is mock_new_session


class TestPatternFiltersQueryBuilding:
    """Tests for query building with filters."""

    def test_filters_with_all_options(self):
        """Should create filters with all options set."""
        filters = PatternFilters(
            source_id="source-123",
            is_ignored=False,
            rare_only=True,
            rarity_threshold=5,
            search="ERROR",
            limit=25,
            offset=50,
        )

        assert filters.source_id == "source-123"
        assert filters.is_ignored is False
        assert filters.rare_only is True
        assert filters.rarity_threshold == 5
        assert filters.search == "ERROR"
        assert filters.limit == 25
        assert filters.offset == 50

    def test_filters_with_none_values(self):
        """Should handle None values correctly."""
        filters = PatternFilters(
            source_id=None,
            is_ignored=None,
            search=None,
        )

        assert filters.source_id is None
        assert filters.is_ignored is None
        assert filters.search is None


class TestPatternStatsCalculation:
    """Tests for pattern stats calculations."""

    def test_stats_with_zero_patterns(self):
        """Should handle zero patterns."""
        stats = PatternStats(
            total_patterns=0,
            ignored_patterns=0,
            rare_patterns=0,
            total_occurrences=0,
            avg_occurrences=0.0,
        )

        assert stats.total_patterns == 0
        assert stats.avg_occurrences == 0.0

    def test_stats_with_large_numbers(self):
        """Should handle large numbers."""
        stats = PatternStats(
            total_patterns=1000000,
            ignored_patterns=50000,
            rare_patterns=200000,
            total_occurrences=50000000,
            avg_occurrences=50.0,
        )

        assert stats.total_patterns == 1000000
        assert stats.total_occurrences == 50000000

    def test_stats_avg_calculation(self):
        """Stats should represent proper average."""
        # If we have 100 patterns with 5000 total occurrences, avg should be 50
        stats = PatternStats(
            total_patterns=100,
            ignored_patterns=0,
            rare_patterns=10,
            total_occurrences=5000,
            avg_occurrences=50.0,
        )

        expected_avg = stats.total_occurrences / stats.total_patterns
        assert stats.avg_occurrences == expected_avg


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.mark.asyncio
    async def test_is_pattern_rare_with_zero_count(self):
        """Pattern with zero occurrences should be rare."""
        service = PatternService()

        mock_pattern = MagicMock()
        mock_pattern.occurrence_count = 0

        result = await service.is_pattern_rare(mock_pattern, default_threshold=1)
        assert result is True

    @pytest.mark.asyncio
    async def test_is_pattern_rare_with_one_count(self):
        """Pattern seen exactly once should be rare with threshold > 1."""
        service = PatternService()

        mock_pattern = MagicMock()
        mock_pattern.occurrence_count = 1

        result = await service.is_pattern_rare(mock_pattern, default_threshold=3)
        assert result is True

    def test_filters_with_empty_search(self):
        """Empty search string should be treated as no search."""
        filters = PatternFilters(search="")

        # Empty string is falsy in Python
        assert not filters.search

    def test_filters_with_whitespace_search(self):
        """Whitespace search should be preserved."""
        filters = PatternFilters(search="   ")

        assert filters.search == "   "
