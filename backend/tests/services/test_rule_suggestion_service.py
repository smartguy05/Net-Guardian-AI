"""Tests for the rule suggestion service."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.rule_suggestion_service import (
    RuleSuggestionService,
    RuleFilters,
    HistoryFilters,
    get_rule_suggestion_service,
)
from app.services.llm_providers.base import SuggestedRuleData
from app.models.semantic_analysis import (
    SuggestedRuleStatus,
    SuggestedRuleType,
)


class TestRuleSuggestionServiceInit:
    """Tests for RuleSuggestionService initialization."""

    def test_creates_instance_without_session(self):
        """Should create instance without a session."""
        service = RuleSuggestionService()
        assert service is not None
        assert service._session is None

    def test_creates_instance_with_session(self):
        """Should create instance with provided session."""
        mock_session = MagicMock()
        service = RuleSuggestionService(session=mock_session)
        assert service._session is mock_session


class TestRuleFilters:
    """Tests for RuleFilters dataclass."""

    def test_default_values(self):
        """Should have correct default values."""
        filters = RuleFilters()

        assert filters.source_id is None
        assert filters.status is None
        assert filters.rule_type is None
        assert filters.search is None
        assert filters.limit == 100
        assert filters.offset == 0

    def test_custom_values(self):
        """Should accept custom values."""
        filters = RuleFilters(
            source_id="test-source",
            status=SuggestedRuleStatus.PENDING,
            rule_type=SuggestedRuleType.PATTERN_MATCH,
            search="login",
            limit=50,
            offset=10,
        )

        assert filters.source_id == "test-source"
        assert filters.status == SuggestedRuleStatus.PENDING
        assert filters.rule_type == SuggestedRuleType.PATTERN_MATCH
        assert filters.search == "login"


class TestHistoryFilters:
    """Tests for HistoryFilters dataclass."""

    def test_default_values(self):
        """Should have correct default values."""
        filters = HistoryFilters()

        assert filters.status is None
        assert filters.limit == 100
        assert filters.offset == 0

    def test_custom_values(self):
        """Should accept custom values."""
        filters = HistoryFilters(
            status=SuggestedRuleStatus.APPROVED,
            limit=25,
            offset=50,
        )

        assert filters.status == SuggestedRuleStatus.APPROVED
        assert filters.limit == 25
        assert filters.offset == 50


class TestComputeRuleHash:
    """Tests for compute_rule_hash method."""

    def test_generates_consistent_hash(self):
        """Should generate the same hash for the same config."""
        service = RuleSuggestionService()
        config = {"pattern": ".*error.*", "fields": ["message"]}

        hash1 = service.compute_rule_hash(config)
        hash2 = service.compute_rule_hash(config)

        assert hash1 == hash2

    def test_same_hash_for_different_key_order(self):
        """Should generate same hash regardless of key order."""
        service = RuleSuggestionService()
        config1 = {"pattern": ".*error.*", "fields": ["message"]}
        config2 = {"fields": ["message"], "pattern": ".*error.*"}

        hash1 = service.compute_rule_hash(config1)
        hash2 = service.compute_rule_hash(config2)

        assert hash1 == hash2

    def test_different_hash_for_different_config(self):
        """Should generate different hash for different config."""
        service = RuleSuggestionService()
        config1 = {"pattern": ".*error.*"}
        config2 = {"pattern": ".*warning.*"}

        hash1 = service.compute_rule_hash(config1)
        hash2 = service.compute_rule_hash(config2)

        assert hash1 != hash2

    def test_handles_empty_config(self):
        """Should handle empty config."""
        service = RuleSuggestionService()
        config = {}

        hash_val = service.compute_rule_hash(config)

        assert hash_val is not None
        assert len(hash_val) == 64  # SHA-256 hex

    def test_handles_nested_config(self):
        """Should handle nested config."""
        service = RuleSuggestionService()
        config = {
            "pattern": ".*",
            "nested": {"key": "value", "list": [1, 2, 3]},
        }

        hash_val = service.compute_rule_hash(config)

        assert hash_val is not None


class TestGetRuleSuggestionService:
    """Tests for get_rule_suggestion_service factory function."""

    def test_returns_service_without_session(self):
        """Should return service without session."""
        service = get_rule_suggestion_service()
        assert isinstance(service, RuleSuggestionService)
        assert service._session is None

    def test_returns_service_with_session(self):
        """Should return service with session."""
        mock_session = MagicMock()
        service = get_rule_suggestion_service(session=mock_session)
        assert isinstance(service, RuleSuggestionService)
        assert service._session is mock_session


class TestIsDuplicateMocked:
    """Tests for is_duplicate with mocked session."""

    @pytest.mark.asyncio
    async def test_returns_true_when_hash_exists(self):
        """Should return True when hash exists in history."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = MagicMock()  # Exists
        mock_session.execute.return_value = mock_result

        service = RuleSuggestionService(session=mock_session)

        result = await service.is_duplicate("existing-hash")

        assert result is True

    @pytest.mark.asyncio
    async def test_returns_false_when_hash_not_exists(self):
        """Should return False when hash doesn't exist."""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None  # Not exists
        mock_session.execute.return_value = mock_result

        service = RuleSuggestionService(session=mock_session)

        result = await service.is_duplicate("new-hash")

        assert result is False


class TestMapRuleConfigToConditions:
    """Tests for _map_rule_config_to_conditions method."""

    def test_pattern_match_single_field(self):
        """Should map pattern match with single field."""
        service = RuleSuggestionService()
        config = {
            "pattern": ".*error.*",
            "fields": ["message"],
        }

        result = service._map_rule_config_to_conditions(
            SuggestedRuleType.PATTERN_MATCH, config
        )

        assert result["logic"] == "and"
        assert len(result["conditions"]) == 1
        assert result["conditions"][0]["field"] == "message"
        assert result["conditions"][0]["operator"] == "regex"
        assert result["conditions"][0]["value"] == ".*error.*"

    def test_pattern_match_multiple_fields(self):
        """Should map pattern match with multiple fields."""
        service = RuleSuggestionService()
        config = {
            "pattern": ".*login.*",
            "fields": ["message", "raw_message"],
        }

        result = service._map_rule_config_to_conditions(
            SuggestedRuleType.PATTERN_MATCH, config
        )

        assert result["logic"] == "or"
        assert len(result["conditions"]) == 2

    def test_threshold_rule(self):
        """Should map threshold rule."""
        service = RuleSuggestionService()
        config = {
            "field": "error_count",
            "threshold": 5,
            "time_window": 300,
        }

        result = service._map_rule_config_to_conditions(
            SuggestedRuleType.THRESHOLD, config
        )

        assert result["logic"] == "and"
        assert result["conditions"][0]["operator"] == "gte"
        assert result["conditions"][0]["value"] == 5
        assert result["time_window_minutes"] == 300

    def test_sequence_rule(self):
        """Should map sequence rule."""
        service = RuleSuggestionService()
        config = {
            "sequence": [{"event": "login"}, {"event": "escalation"}],
            "time_window": 600,
        }

        result = service._map_rule_config_to_conditions(
            SuggestedRuleType.SEQUENCE, config
        )

        assert result["logic"] == "sequence"
        assert result["time_window_minutes"] == 600

    def test_pattern_match_default_field(self):
        """Should use default field when not specified."""
        service = RuleSuggestionService()
        config = {"pattern": ".*test.*"}  # No fields specified

        result = service._map_rule_config_to_conditions(
            SuggestedRuleType.PATTERN_MATCH, config
        )

        assert result["conditions"][0]["field"] == "raw_message"

    def test_threshold_default_values(self):
        """Should use default values for threshold rule."""
        service = RuleSuggestionService()
        config = {}  # Empty config

        result = service._map_rule_config_to_conditions(
            SuggestedRuleType.THRESHOLD, config
        )

        assert result["conditions"][0]["field"] == "count"
        assert result["conditions"][0]["value"] == 10
        assert result["time_window_minutes"] == 60


class TestSuggestedRuleData:
    """Tests for SuggestedRuleData from LLM providers."""

    def test_creates_rule_data(self):
        """Should create rule data from LLM response."""
        rule_data = SuggestedRuleData(
            log_index=0,
            name="Failed Login Alert",
            description="Alerts on multiple failed logins",
            reason="Pattern of failed authentication detected",
            benefit="Early detection of brute force attacks",
            rule_type="pattern_match",
            rule_config={"pattern": ".*failed.*login.*"},
        )

        assert rule_data.log_index == 0
        assert rule_data.name == "Failed Login Alert"
        assert rule_data.rule_type == "pattern_match"


class TestApproveRuleMocked:
    """Tests for approve_rule with mocked dependencies."""

    @pytest.mark.asyncio
    async def test_raises_error_for_non_pending_rule(self):
        """Should raise error when rule is not pending."""
        mock_session = AsyncMock()
        service = RuleSuggestionService(session=mock_session)

        mock_rule = MagicMock()
        mock_rule.status = SuggestedRuleStatus.APPROVED  # Already approved

        with patch.object(service, "get_rule_by_id", return_value=mock_rule):
            with pytest.raises(ValueError, match="not pending"):
                await service.approve_rule(uuid4(), uuid4())

    @pytest.mark.asyncio
    async def test_returns_none_when_rule_not_found(self):
        """Should return None when rule doesn't exist."""
        mock_session = AsyncMock()
        service = RuleSuggestionService(session=mock_session)

        with patch.object(service, "get_rule_by_id", return_value=None):
            result = await service.approve_rule(uuid4(), uuid4())

            assert result is None


class TestRejectRuleMocked:
    """Tests for reject_rule with mocked dependencies."""

    @pytest.mark.asyncio
    async def test_raises_error_for_non_pending_rule(self):
        """Should raise error when rule is not pending."""
        mock_session = AsyncMock()
        service = RuleSuggestionService(session=mock_session)

        mock_rule = MagicMock()
        mock_rule.status = SuggestedRuleStatus.REJECTED  # Already rejected

        with patch.object(service, "get_rule_by_id", return_value=mock_rule):
            with pytest.raises(ValueError, match="not pending"):
                await service.reject_rule(uuid4(), uuid4(), "Reason")

    @pytest.mark.asyncio
    async def test_returns_none_when_rule_not_found(self):
        """Should return None when rule doesn't exist."""
        mock_session = AsyncMock()
        service = RuleSuggestionService(session=mock_session)

        with patch.object(service, "get_rule_by_id", return_value=None):
            result = await service.reject_rule(uuid4(), uuid4(), "Reason")

            assert result is None


class TestSuggestedRuleStatus:
    """Tests for SuggestedRuleStatus enum."""

    def test_pending_status(self):
        """Should have pending status."""
        assert SuggestedRuleStatus.PENDING.value == "pending"

    def test_approved_status(self):
        """Should have approved status."""
        assert SuggestedRuleStatus.APPROVED.value == "approved"

    def test_implemented_status(self):
        """Should have implemented status."""
        assert SuggestedRuleStatus.IMPLEMENTED.value == "implemented"

    def test_rejected_status(self):
        """Should have rejected status."""
        assert SuggestedRuleStatus.REJECTED.value == "rejected"


class TestSuggestedRuleType:
    """Tests for SuggestedRuleType enum."""

    def test_pattern_match_type(self):
        """Should have pattern_match type."""
        assert SuggestedRuleType.PATTERN_MATCH.value == "pattern_match"

    def test_threshold_type(self):
        """Should have threshold type."""
        assert SuggestedRuleType.THRESHOLD.value == "threshold"

    def test_sequence_type(self):
        """Should have sequence type."""
        assert SuggestedRuleType.SEQUENCE.value == "sequence"


class TestGetSession:
    """Tests for _get_session method."""

    @pytest.mark.asyncio
    async def test_returns_provided_session(self):
        """Should return the provided session."""
        mock_session = MagicMock()
        service = RuleSuggestionService(session=mock_session)

        result = await service._get_session()
        assert result is mock_session

    @pytest.mark.asyncio
    async def test_creates_new_session_when_none(self):
        """Should create new session when none provided."""
        with patch(
            "app.services.rule_suggestion_service.AsyncSessionLocal"
        ) as MockSession:
            mock_new_session = MagicMock()
            MockSession.return_value = mock_new_session

            service = RuleSuggestionService()
            result = await service._get_session()

            assert result is mock_new_session


class TestEdgeCases:
    """Tests for edge cases."""

    def test_compute_hash_with_special_characters(self):
        """Should handle special characters in config."""
        service = RuleSuggestionService()
        config = {
            "pattern": r".*\d+\.\d+\.\d+\.\d+.*",
            "special": "quote'test\"value",
        }

        hash_val = service.compute_rule_hash(config)

        assert hash_val is not None

    def test_compute_hash_with_unicode(self):
        """Should handle unicode in config."""
        service = RuleSuggestionService()
        config = {
            "pattern": ".*\u4e2d\u6587.*",
            "description": "\u6d4b\u8bd5",
        }

        hash_val = service.compute_rule_hash(config)

        assert hash_val is not None

    def test_filters_with_all_rule_types(self):
        """Should accept all rule types in filters."""
        for rule_type in SuggestedRuleType:
            filters = RuleFilters(rule_type=rule_type)
            assert filters.rule_type == rule_type

    def test_filters_with_all_statuses(self):
        """Should accept all statuses in filters."""
        for status in SuggestedRuleStatus:
            filters = RuleFilters(status=status)
            assert filters.status == status
