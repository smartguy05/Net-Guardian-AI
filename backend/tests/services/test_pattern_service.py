"""Tests for the pattern service.

Tests cover:
- Pattern recording
- Pattern retrieval (by hash, by ID)
- Pattern statistics
- Mark pattern ignored
- Get patterns with filters
- Pattern count
- Pattern deletion
- Edge cases
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.pattern_service import (
    PatternFilters,
    PatternService,
    PatternStats,
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


class TestRecordPattern:
    """Tests for record_pattern method."""

    @pytest.mark.asyncio
    async def test_normalizes_message_before_recording(self):
        """Should normalize message before recording pattern."""
        with patch("app.services.pattern_service.PatternNormalizer") as MockNormalizer:
            MockNormalizer.normalize.return_value = ("<IP> connected", "hash123")

            mock_session = AsyncMock()
            mock_pattern = MagicMock()
            mock_pattern.id = uuid4()
            mock_pattern.source_id = "test-source"
            mock_pattern.normalized_pattern = "<IP> connected"
            mock_pattern.pattern_hash = "hash123"
            mock_pattern.occurrence_count = 1

            mock_result = MagicMock()
            mock_result.scalar_one.return_value = mock_pattern
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            service = PatternService(session=mock_session)

            pattern = await service.record_pattern(
                source_id="test-source",
                message="192.168.1.1 connected",
            )

            MockNormalizer.normalize.assert_called_once_with("192.168.1.1 connected")
            assert pattern == mock_pattern

    @pytest.mark.asyncio
    async def test_record_pattern_with_custom_timestamp(self):
        """Should use provided timestamp."""
        with patch("app.services.pattern_service.PatternNormalizer") as MockNormalizer:
            MockNormalizer.normalize.return_value = ("pattern", "hash")

            mock_session = AsyncMock()
            mock_pattern = MagicMock()
            mock_result = MagicMock()
            mock_result.scalar_one.return_value = mock_pattern
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            service = PatternService(session=mock_session)

            custom_time = datetime(2024, 6, 15, 12, 0, 0)
            await service.record_pattern(
                source_id="test-source",
                message="test message",
                timestamp=custom_time,
            )

            # Verify execute was called (timestamp is in the statement)
            mock_session.execute.assert_called_once()


class TestGetPatternByHash:
    """Tests for get_pattern_by_hash method."""

    @pytest.mark.asyncio
    async def test_returns_pattern_when_found(self):
        """Should return pattern when found."""
        mock_session = AsyncMock()
        mock_pattern = MagicMock()
        mock_pattern.id = uuid4()
        mock_pattern.source_id = "test-source"
        mock_pattern.pattern_hash = "hash123"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_pattern
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)

        result = await service.get_pattern_by_hash("test-source", "hash123")

        assert result == mock_pattern

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self):
        """Should return None when pattern not found."""
        mock_session = AsyncMock()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)

        result = await service.get_pattern_by_hash("test-source", "nonexistent")

        assert result is None


class TestGetPatternById:
    """Tests for get_pattern_by_id method."""

    @pytest.mark.asyncio
    async def test_returns_pattern_when_found(self):
        """Should return pattern when found."""
        mock_session = AsyncMock()
        pattern_id = uuid4()
        mock_pattern = MagicMock()
        mock_pattern.id = pattern_id

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_pattern
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)

        result = await service.get_pattern_by_id(pattern_id)

        assert result == mock_pattern

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self):
        """Should return None when pattern not found."""
        mock_session = AsyncMock()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)

        result = await service.get_pattern_by_id(uuid4())

        assert result is None


class TestGetPatternStats:
    """Tests for get_pattern_stats method."""

    @pytest.mark.asyncio
    async def test_returns_stats_for_source(self):
        """Should return stats for a source."""
        mock_session = AsyncMock()

        # Create a mock row with named attributes
        mock_row = MagicMock()
        mock_row.total = 100
        mock_row.ignored = 5
        mock_row.rare = 20
        mock_row.total_occurrences = 5000
        mock_row.avg_occurrences = 50.0

        mock_result = MagicMock()
        mock_result.one.return_value = mock_row
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)

        stats = await service.get_pattern_stats("test-source")

        assert stats.total_patterns == 100
        assert stats.ignored_patterns == 5
        assert stats.rare_patterns == 20
        assert stats.total_occurrences == 5000
        assert stats.avg_occurrences == 50.0

    @pytest.mark.asyncio
    async def test_uses_custom_rarity_threshold(self):
        """Should use custom rarity threshold in query."""
        mock_session = AsyncMock()

        mock_row = MagicMock()
        mock_row.total = 50
        mock_row.ignored = 0
        mock_row.rare = 30
        mock_row.total_occurrences = 1000
        mock_row.avg_occurrences = 20.0

        mock_result = MagicMock()
        mock_result.one.return_value = mock_row
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)

        stats = await service.get_pattern_stats("test-source", rarity_threshold=10)

        # Verify query was executed
        mock_session.execute.assert_called_once()


class TestMarkPatternIgnored:
    """Tests for mark_pattern_ignored method."""

    @pytest.mark.asyncio
    async def test_marks_pattern_as_ignored(self):
        """Should mark pattern as ignored."""
        mock_session = AsyncMock()
        pattern_id = uuid4()
        mock_pattern = MagicMock()
        mock_pattern.id = pattern_id
        mock_pattern.is_ignored = True

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_pattern
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        service = PatternService(session=mock_session)

        result = await service.mark_pattern_ignored(pattern_id, ignored=True)

        assert result == mock_pattern
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_marks_pattern_as_not_ignored(self):
        """Should mark pattern as not ignored."""
        mock_session = AsyncMock()
        pattern_id = uuid4()
        mock_pattern = MagicMock()
        mock_pattern.id = pattern_id
        mock_pattern.is_ignored = False

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_pattern
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        service = PatternService(session=mock_session)

        result = await service.mark_pattern_ignored(pattern_id, ignored=False)

        assert result == mock_pattern
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self):
        """Should return None when pattern not found."""
        mock_session = AsyncMock()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()

        service = PatternService(session=mock_session)

        result = await service.mark_pattern_ignored(uuid4(), ignored=True)

        assert result is None


class TestGetPatternsForSource:
    """Tests for get_patterns_for_source method."""

    @pytest.mark.asyncio
    async def test_returns_patterns_with_basic_filters(self):
        """Should return patterns matching basic filters."""
        mock_session = AsyncMock()
        mock_patterns = [MagicMock(), MagicMock(), MagicMock()]

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_patterns
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)
        filters = PatternFilters(source_id="test-source")

        result = await service.get_patterns_for_source(filters)

        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_filters_by_is_ignored(self):
        """Should filter by is_ignored flag."""
        mock_session = AsyncMock()
        mock_patterns = [MagicMock()]

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_patterns
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)
        filters = PatternFilters(source_id="test-source", is_ignored=False)

        result = await service.get_patterns_for_source(filters)

        # Query was executed with filter
        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_filters_by_rare_only(self):
        """Should filter to rare patterns only."""
        mock_session = AsyncMock()
        mock_patterns = [MagicMock()]

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_patterns
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)
        filters = PatternFilters(source_id="test-source", rare_only=True, rarity_threshold=5)

        result = await service.get_patterns_for_source(filters)

        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_filters_by_search(self):
        """Should filter by search string."""
        mock_session = AsyncMock()
        mock_patterns = [MagicMock()]

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_patterns
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)
        filters = PatternFilters(source_id="test-source", search="ERROR")

        result = await service.get_patterns_for_source(filters)

        mock_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_applies_limit_and_offset(self):
        """Should apply limit and offset."""
        mock_session = AsyncMock()
        mock_patterns = [MagicMock(), MagicMock()]

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_patterns
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)
        filters = PatternFilters(limit=2, offset=10)

        result = await service.get_patterns_for_source(filters)

        assert len(result) == 2
        mock_session.execute.assert_called_once()


class TestGetPatternCount:
    """Tests for get_pattern_count method."""

    @pytest.mark.asyncio
    async def test_returns_count(self):
        """Should return count of matching patterns."""
        mock_session = AsyncMock()

        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 42
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)
        filters = PatternFilters(source_id="test-source")

        count = await service.get_pattern_count(filters)

        assert count == 42

    @pytest.mark.asyncio
    async def test_count_with_filters(self):
        """Should apply filters to count query."""
        mock_session = AsyncMock()

        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 10
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)
        filters = PatternFilters(
            source_id="test-source",
            is_ignored=False,
            rare_only=True,
        )

        count = await service.get_pattern_count(filters)

        assert count == 10
        mock_session.execute.assert_called_once()


class TestDeletePattern:
    """Tests for delete_pattern method."""

    @pytest.mark.asyncio
    async def test_deletes_existing_pattern(self):
        """Should delete existing pattern and return True."""
        mock_session = AsyncMock()
        pattern_id = uuid4()
        mock_pattern = MagicMock()
        mock_pattern.id = pattern_id

        mock_session.delete = AsyncMock()
        mock_session.commit = AsyncMock()

        service = PatternService(session=mock_session)

        # Mock get_pattern_by_id to return the pattern
        with patch.object(service, "get_pattern_by_id", return_value=mock_pattern):
            result = await service.delete_pattern(pattern_id)

        assert result is True
        mock_session.delete.assert_called_once_with(mock_pattern)
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_not_found(self):
        """Should return False when pattern not found."""
        mock_session = AsyncMock()

        # Mock get_pattern_by_id to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        service = PatternService(session=mock_session)

        result = await service.delete_pattern(uuid4())

        assert result is False


class TestSessionManagement:
    """Tests for session management."""

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
        assert not filters.search

    def test_filters_with_whitespace_search(self):
        """Whitespace search should be preserved."""
        filters = PatternFilters(search="   ")
        assert filters.search == "   "

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
