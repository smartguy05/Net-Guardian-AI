"""Tests for the semantic analysis service."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.semantic_analysis_service import (
    SemanticAnalysisService,
    SemanticStats,
    IrregularLogFilters,
    get_semantic_analysis_service,
)
from app.models.semantic_analysis import LLMProvider, AnalysisRunStatus


class TestSemanticAnalysisServiceInit:
    """Tests for SemanticAnalysisService initialization."""

    def test_creates_instance_without_session(self):
        """Should create instance without a session."""
        service = SemanticAnalysisService()
        assert service is not None
        assert service._session is None

    def test_creates_instance_with_session(self):
        """Should create instance with provided session."""
        mock_session = MagicMock()
        service = SemanticAnalysisService(session=mock_session)
        assert service._session is mock_session

    def test_creates_pattern_service(self):
        """Should create a pattern service internally."""
        service = SemanticAnalysisService()
        assert service._pattern_service is not None


class TestIrregularLogFilters:
    """Tests for IrregularLogFilters dataclass."""

    def test_default_values(self):
        """Should have correct default values."""
        filters = IrregularLogFilters()

        assert filters.source_id is None
        assert filters.llm_reviewed is None
        assert filters.reviewed_by_user is None
        assert filters.min_severity is None
        assert filters.start_date is None
        assert filters.end_date is None
        assert filters.limit == 100
        assert filters.offset == 0

    def test_custom_values(self):
        """Should accept custom values."""
        now = datetime.utcnow()
        filters = IrregularLogFilters(
            source_id="test-source",
            llm_reviewed=True,
            reviewed_by_user=False,
            min_severity=0.7,
            start_date=now - timedelta(days=7),
            end_date=now,
            limit=50,
            offset=10,
        )

        assert filters.source_id == "test-source"
        assert filters.llm_reviewed is True
        assert filters.reviewed_by_user is False
        assert filters.min_severity == 0.7
        assert filters.limit == 50
        assert filters.offset == 10


class TestSemanticStats:
    """Tests for SemanticStats dataclass."""

    def test_creates_stats(self):
        """Should create stats with all fields."""
        now = datetime.utcnow()
        stats = SemanticStats(
            total_patterns=100,
            total_irregular_logs=25,
            pending_review=10,
            high_severity_count=5,
            last_run_at=now,
            last_run_status="completed",
        )

        assert stats.total_patterns == 100
        assert stats.total_irregular_logs == 25
        assert stats.pending_review == 10
        assert stats.high_severity_count == 5
        assert stats.last_run_at == now
        assert stats.last_run_status == "completed"

    def test_stats_with_none_run_info(self):
        """Should handle None for optional run fields."""
        stats = SemanticStats(
            total_patterns=50,
            total_irregular_logs=0,
            pending_review=0,
            high_severity_count=0,
            last_run_at=None,
            last_run_status=None,
        )

        assert stats.last_run_at is None
        assert stats.last_run_status is None


class TestGetSemanticAnalysisService:
    """Tests for get_semantic_analysis_service factory function."""

    def test_returns_service_without_session(self):
        """Should return service without session."""
        service = get_semantic_analysis_service()
        assert isinstance(service, SemanticAnalysisService)
        assert service._session is None

    def test_returns_service_with_session(self):
        """Should return service with session."""
        mock_session = MagicMock()
        service = get_semantic_analysis_service(session=mock_session)
        assert isinstance(service, SemanticAnalysisService)
        assert service._session is mock_session


class TestProcessEventMocked:
    """Tests for process_event with mocked dependencies."""

    @pytest.mark.asyncio
    async def test_returns_none_when_no_config(self):
        """Should return None when no config exists for source."""
        mock_session = AsyncMock()
        service = SemanticAnalysisService(session=mock_session)

        with patch.object(service, "get_config", return_value=None):
            mock_event = MagicMock()
            mock_event.source_id = "unknown-source"

            result = await service.process_event(mock_event)

            assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_when_config_disabled(self):
        """Should return None when config is disabled."""
        mock_session = AsyncMock()
        service = SemanticAnalysisService(session=mock_session)

        mock_config = MagicMock()
        mock_config.enabled = False

        with patch.object(service, "get_config", return_value=mock_config):
            mock_event = MagicMock()
            mock_event.source_id = "test-source"

            result = await service.process_event(mock_event)

            assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_for_ignored_pattern(self):
        """Should return None for ignored patterns."""
        mock_session = AsyncMock()
        service = SemanticAnalysisService(session=mock_session)

        mock_config = MagicMock()
        mock_config.enabled = True

        mock_pattern = MagicMock()
        mock_pattern.is_ignored = True

        with patch.object(service, "get_config", return_value=mock_config):
            with patch.object(
                service._pattern_service, "record_pattern", return_value=mock_pattern
            ):
                mock_event = MagicMock()
                mock_event.source_id = "test-source"
                mock_event.raw_message = "Test message"
                mock_event.timestamp = datetime.utcnow()

                result = await service.process_event(mock_event)

                assert result is None


class TestRunAnalysisMocked:
    """Tests for run_analysis with mocked dependencies."""

    @pytest.mark.asyncio
    async def test_raises_error_when_no_config(self):
        """Should raise error when no config exists."""
        mock_session = AsyncMock()
        service = SemanticAnalysisService(session=mock_session)

        with patch.object(service, "get_config", return_value=None):
            with pytest.raises(ValueError, match="No config found"):
                await service.run_analysis("nonexistent-source")

    @pytest.mark.asyncio
    async def test_raises_error_when_disabled(self):
        """Should raise error when semantic analysis is disabled."""
        mock_session = AsyncMock()
        service = SemanticAnalysisService(session=mock_session)

        mock_config = MagicMock()
        mock_config.enabled = False

        with patch.object(service, "get_config", return_value=mock_config):
            with pytest.raises(ValueError, match="disabled"):
                await service.run_analysis("test-source")

    @pytest.mark.asyncio
    async def test_raises_error_when_too_soon(self):
        """Should raise error when interval hasn't passed."""
        mock_session = AsyncMock()
        service = SemanticAnalysisService(session=mock_session)

        mock_config = MagicMock()
        mock_config.enabled = True
        mock_config.last_run_at = datetime.utcnow()  # Just ran
        mock_config.batch_interval_minutes = 60

        with patch.object(service, "get_config", return_value=mock_config):
            with pytest.raises(ValueError, match="Too soon"):
                await service.run_analysis("test-source", force=False)

    @pytest.mark.asyncio
    async def test_force_bypasses_interval_check(self):
        """Should bypass interval check when force=True."""
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.commit = AsyncMock()
        mock_session.refresh = AsyncMock()
        mock_session.execute = AsyncMock()

        service = SemanticAnalysisService(session=mock_session)

        mock_config = MagicMock()
        mock_config.enabled = True
        mock_config.last_run_at = datetime.utcnow()  # Just ran
        mock_config.batch_interval_minutes = 60
        mock_config.batch_size = 50
        mock_config.llm_provider = LLMProvider.CLAUDE
        mock_config.ollama_model = None

        # Mock the session.execute to return empty results
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        with patch.object(service, "get_config", return_value=mock_config):
            # This should not raise an error because force=True
            run = await service.run_analysis("test-source", force=True)

            # Verify run was created (even if no logs to analyze)
            mock_session.add.assert_called()


class TestGetSession:
    """Tests for _get_session method."""

    @pytest.mark.asyncio
    async def test_returns_provided_session(self):
        """Should return the provided session."""
        mock_session = MagicMock()
        service = SemanticAnalysisService(session=mock_session)

        result = await service._get_session()
        assert result is mock_session

    @pytest.mark.asyncio
    async def test_creates_new_session_when_none(self):
        """Should create new session when none provided."""
        with patch(
            "app.services.semantic_analysis_service.AsyncSessionLocal"
        ) as MockSession:
            mock_new_session = MagicMock()
            MockSession.return_value = mock_new_session

            service = SemanticAnalysisService()
            result = await service._get_session()

            assert result is mock_new_session


class TestIrregularLogFiltersQueryBuilding:
    """Tests for query building with irregular log filters."""

    def test_filters_with_all_options(self):
        """Should create filters with all options set."""
        start = datetime.utcnow() - timedelta(days=7)
        end = datetime.utcnow()

        filters = IrregularLogFilters(
            source_id="source-123",
            llm_reviewed=True,
            reviewed_by_user=False,
            min_severity=0.8,
            start_date=start,
            end_date=end,
            limit=25,
            offset=50,
        )

        assert filters.source_id == "source-123"
        assert filters.llm_reviewed is True
        assert filters.reviewed_by_user is False
        assert filters.min_severity == 0.8
        assert filters.start_date == start
        assert filters.end_date == end

    def test_filters_with_severity_boundary(self):
        """Should handle severity boundary values."""
        filters_low = IrregularLogFilters(min_severity=0.0)
        filters_high = IrregularLogFilters(min_severity=1.0)

        assert filters_low.min_severity == 0.0
        assert filters_high.min_severity == 1.0


class TestSemanticStatsCalculation:
    """Tests for semantic stats."""

    def test_stats_with_zero_values(self):
        """Should handle zero values."""
        stats = SemanticStats(
            total_patterns=0,
            total_irregular_logs=0,
            pending_review=0,
            high_severity_count=0,
            last_run_at=None,
            last_run_status=None,
        )

        assert stats.total_patterns == 0
        assert stats.total_irregular_logs == 0

    def test_stats_with_large_numbers(self):
        """Should handle large numbers."""
        stats = SemanticStats(
            total_patterns=1000000,
            total_irregular_logs=50000,
            pending_review=10000,
            high_severity_count=5000,
            last_run_at=datetime.utcnow(),
            last_run_status="completed",
        )

        assert stats.total_patterns == 1000000
        assert stats.total_irregular_logs == 50000


class TestMarkReviewedMocked:
    """Tests for mark_reviewed with mocked session."""

    @pytest.mark.asyncio
    async def test_mark_reviewed_updates_record(self):
        """Should update the irregular log record."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_irregular = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_irregular
        mock_session.execute.return_value = mock_result
        mock_session.commit = AsyncMock()

        service = SemanticAnalysisService(session=mock_session)

        result = await service.mark_reviewed(uuid4())

        assert mock_session.execute.called
        assert mock_session.commit.called


class TestLLMProviderEnum:
    """Tests for LLMProvider enum usage."""

    def test_claude_provider_value(self):
        """Should have correct Claude provider value."""
        assert LLMProvider.CLAUDE.value == "claude"

    def test_ollama_provider_value(self):
        """Should have correct Ollama provider value."""
        assert LLMProvider.OLLAMA.value == "ollama"


class TestAnalysisRunStatusEnum:
    """Tests for AnalysisRunStatus enum."""

    def test_running_status(self):
        """Should have running status."""
        assert AnalysisRunStatus.RUNNING.value == "running"

    def test_completed_status(self):
        """Should have completed status."""
        assert AnalysisRunStatus.COMPLETED.value == "completed"

    def test_failed_status(self):
        """Should have failed status."""
        assert AnalysisRunStatus.FAILED.value == "failed"


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.mark.asyncio
    async def test_process_event_with_empty_message(self):
        """Should handle event with empty message."""
        mock_session = AsyncMock()
        service = SemanticAnalysisService(session=mock_session)

        mock_config = MagicMock()
        mock_config.enabled = True

        mock_pattern = MagicMock()
        mock_pattern.is_ignored = False
        mock_pattern.occurrence_count = 1

        with patch.object(service, "get_config", return_value=mock_config):
            with patch.object(
                service._pattern_service, "record_pattern", return_value=mock_pattern
            ):
                with patch.object(
                    service._pattern_service, "is_pattern_rare", return_value=True
                ):
                    mock_event = MagicMock()
                    mock_event.id = uuid4()
                    mock_event.source_id = "test-source"
                    mock_event.raw_message = ""  # Empty message
                    mock_event.timestamp = datetime.utcnow()

                    mock_session.add = MagicMock()
                    mock_session.commit = AsyncMock()
                    mock_session.refresh = AsyncMock()

                    # Should not crash
                    await service.process_event(mock_event)

    def test_filters_with_date_range(self):
        """Should handle date range filtering."""
        start = datetime(2025, 1, 1)
        end = datetime(2025, 1, 31)

        filters = IrregularLogFilters(
            start_date=start,
            end_date=end,
        )

        assert filters.start_date == start
        assert filters.end_date == end
        assert filters.end_date > filters.start_date
