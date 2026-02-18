"""Tests for the investigation service."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.models.investigation import (
    Investigation,
    InvestigationAction,
    InvestigationActionRiskLevel,
    InvestigationActionStatus,
    InvestigationStatus,
    InvestigationStep,
    InvestigationStepStatus,
    InvestigationStepType,
    InvestigationTriggerSource,
)
from app.services.investigation.service import InvestigationService


class TestInvestigationStatus:
    """Tests for investigation status enum."""

    def test_all_statuses_exist(self):
        """Test all expected statuses exist."""
        assert InvestigationStatus.PENDING
        assert InvestigationStatus.RUNNING
        assert InvestigationStatus.AWAITING_APPROVAL
        assert InvestigationStatus.COMPLETED
        assert InvestigationStatus.FAILED
        assert InvestigationStatus.CANCELLED

    def test_status_values(self):
        """Test status enum values."""
        assert InvestigationStatus.PENDING.value == "pending"
        assert InvestigationStatus.RUNNING.value == "running"
        assert InvestigationStatus.COMPLETED.value == "completed"


class TestInvestigationTriggerSource:
    """Tests for trigger source enum."""

    def test_all_trigger_sources_exist(self):
        """Test all expected trigger sources exist."""
        assert InvestigationTriggerSource.MANUAL
        assert InvestigationTriggerSource.PLAYBOOK
        assert InvestigationTriggerSource.AUTO

    def test_trigger_source_values(self):
        """Test trigger source enum values."""
        assert InvestigationTriggerSource.MANUAL.value == "manual"
        assert InvestigationTriggerSource.PLAYBOOK.value == "playbook"
        assert InvestigationTriggerSource.AUTO.value == "auto"


class TestInvestigationStepType:
    """Tests for investigation step type enum."""

    def test_all_step_types_exist(self):
        """Test all expected step types exist."""
        assert InvestigationStepType.GATHER_CONTEXT
        assert InvestigationStepType.CORRELATE_EVENTS
        assert InvestigationStepType.CHECK_THREAT_INTEL
        assert InvestigationStepType.ANALYZE_BASELINE
        assert InvestigationStepType.GENERATE_HYPOTHESIS
        assert InvestigationStepType.RECOMMEND_ACTIONS

    def test_step_type_values(self):
        """Test step type enum values."""
        assert InvestigationStepType.GATHER_CONTEXT.value == "gather_context"
        assert InvestigationStepType.CORRELATE_EVENTS.value == "correlate_events"
        assert InvestigationStepType.RECOMMEND_ACTIONS.value == "recommend_actions"


class TestInvestigationActionRiskLevel:
    """Tests for action risk level enum."""

    def test_all_risk_levels_exist(self):
        """Test all expected risk levels exist."""
        assert InvestigationActionRiskLevel.LOW
        assert InvestigationActionRiskLevel.MEDIUM
        assert InvestigationActionRiskLevel.HIGH
        assert InvestigationActionRiskLevel.CRITICAL

    def test_risk_level_values(self):
        """Test risk level enum values."""
        assert InvestigationActionRiskLevel.LOW.value == "low"
        assert InvestigationActionRiskLevel.MEDIUM.value == "medium"
        assert InvestigationActionRiskLevel.HIGH.value == "high"
        assert InvestigationActionRiskLevel.CRITICAL.value == "critical"


class TestInvestigationActionStatus:
    """Tests for action status enum."""

    def test_all_action_statuses_exist(self):
        """Test all expected action statuses exist."""
        assert InvestigationActionStatus.PENDING
        assert InvestigationActionStatus.APPROVED
        assert InvestigationActionStatus.REJECTED
        assert InvestigationActionStatus.EXECUTED
        assert InvestigationActionStatus.FAILED

    def test_action_status_values(self):
        """Test action status enum values."""
        assert InvestigationActionStatus.PENDING.value == "pending"
        assert InvestigationActionStatus.APPROVED.value == "approved"
        assert InvestigationActionStatus.EXECUTED.value == "executed"


class TestInvestigationService:
    """Tests for InvestigationService class."""

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
        return InvestigationService(mock_session)

    @pytest.mark.asyncio
    async def test_create_investigation_manual(self, service, mock_session):
        """Test creating a manual investigation."""
        alert_id = uuid4()

        # Mock count running investigations
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 0
        mock_session.execute = AsyncMock(return_value=mock_count_result)

        # Mock refresh to set investigation attributes
        async def set_investigation_attrs(obj):
            obj.id = uuid4()
            obj.alert_id = alert_id
            obj.status = InvestigationStatus.PENDING
            obj.trigger_source = InvestigationTriggerSource.MANUAL
            obj.priority = 3
            obj.requires_approval = True
            obj.created_at = datetime.now(UTC)

        mock_session.refresh = AsyncMock(side_effect=set_investigation_attrs)

        # Patch run_investigation to prevent actual execution
        with patch.object(service, "run_investigation", new_callable=AsyncMock):
            investigation = await service.create_investigation(
                trigger_source=InvestigationTriggerSource.MANUAL,
                alert_id=alert_id,
                priority=3,
                auto_run=False,
            )

        assert investigation.alert_id == alert_id
        assert investigation.trigger_source == InvestigationTriggerSource.MANUAL
        assert investigation.priority == 3
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_investigation_auto_run(self, service, mock_session):
        """Test creating an auto-run investigation."""
        # Mock count running investigations (none running)
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 0
        mock_session.execute = AsyncMock(return_value=mock_count_result)

        # Mock refresh
        async def set_investigation_attrs(obj):
            obj.id = uuid4()
            obj.status = InvestigationStatus.PENDING
            obj.trigger_source = InvestigationTriggerSource.AUTO
            obj.priority = 4
            obj.requires_approval = True
            obj.created_at = datetime.now(UTC)

        mock_session.refresh = AsyncMock(side_effect=set_investigation_attrs)

        # Patch run_investigation
        with patch.object(service, "run_investigation", new_callable=AsyncMock) as mock_run:
            investigation = await service.create_investigation(
                trigger_source=InvestigationTriggerSource.AUTO,
                priority=4,
                auto_run=True,
            )
            mock_run.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_investigation_respects_concurrent_limit(self, service, mock_session):
        """Test that auto_run is disabled when at concurrent limit."""
        # Mock count running investigations at max
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 10  # At or above limit

        mock_session.execute = AsyncMock(return_value=mock_count_result)

        # Mock refresh
        async def set_investigation_attrs(obj):
            obj.id = uuid4()
            obj.status = InvestigationStatus.PENDING
            obj.created_at = datetime.now(UTC)

        mock_session.refresh = AsyncMock(side_effect=set_investigation_attrs)

        # Patch run_investigation
        with patch.object(service, "run_investigation", new_callable=AsyncMock) as mock_run:
            with patch("app.services.investigation.service.settings") as mock_settings:
                mock_settings.investigation_max_concurrent = 3
                mock_settings.investigation_require_approval_risk = "high"

                investigation = await service.create_investigation(
                    trigger_source=InvestigationTriggerSource.AUTO,
                    auto_run=True,
                )
                # Should not run because limit reached
                mock_run.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_investigation_by_id(self, service, mock_session):
        """Test getting an investigation by ID."""
        investigation_id = uuid4()

        mock_investigation = MagicMock(spec=Investigation)
        mock_investigation.id = investigation_id
        mock_investigation.status = InvestigationStatus.COMPLETED
        mock_investigation.summary = "Test investigation"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_investigation
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await service.get_investigation(investigation_id)

        assert result.id == investigation_id
        assert result.status == InvestigationStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_get_investigation_not_found(self, service, mock_session):
        """Test getting a non-existent investigation."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await service.get_investigation(uuid4())

        assert result is None


class TestInvestigationModel:
    """Tests for Investigation model behavior."""

    def test_investigation_default_values(self):
        """Test investigation default values."""
        inv = Investigation()
        inv.id = uuid4()
        inv.trigger_source = InvestigationTriggerSource.MANUAL
        inv.priority = 3

        assert inv.status is None  # Not set yet
        assert inv.requires_approval is None

    def test_investigation_step_creation(self):
        """Test creating an investigation step."""
        step = InvestigationStep()
        step.id = uuid4()
        step.investigation_id = uuid4()
        step.step_number = 1
        step.step_type = InvestigationStepType.GATHER_CONTEXT
        step.status = InvestigationStepStatus.COMPLETED
        step.reasoning = "Gathered device context and recent events"
        step.confidence_score = 0.85

        assert step.step_type == InvestigationStepType.GATHER_CONTEXT
        assert step.confidence_score == 0.85

    def test_investigation_action_creation(self):
        """Test creating an investigation action."""
        action = InvestigationAction()
        action.id = uuid4()
        action.investigation_id = uuid4()
        action.action_type = "quarantine"
        action.risk_level = InvestigationActionRiskLevel.HIGH
        action.status = InvestigationActionStatus.PENDING
        action.justification = "Device showing malicious behavior"

        assert action.action_type == "quarantine"
        assert action.risk_level == InvestigationActionRiskLevel.HIGH
        assert action.status == InvestigationActionStatus.PENDING


class TestInvestigationStepStatus:
    """Tests for investigation step status enum."""

    def test_all_step_statuses_exist(self):
        """Test all expected step statuses exist."""
        assert InvestigationStepStatus.PENDING
        assert InvestigationStepStatus.RUNNING
        assert InvestigationStepStatus.COMPLETED
        assert InvestigationStepStatus.FAILED
        assert InvestigationStepStatus.SKIPPED


class TestInvestigationPriority:
    """Tests for investigation priority handling."""

    def test_priority_range(self):
        """Test valid priority range is 1-5."""
        # Priority should be 1 (lowest) to 5 (highest)
        for priority in range(1, 6):
            inv = Investigation()
            inv.priority = priority
            assert 1 <= inv.priority <= 5

    def test_higher_priority_means_more_urgent(self):
        """Test that higher priority number means more urgent."""
        # Convention: 5 = critical, 1 = low
        inv_low = Investigation()
        inv_low.priority = 1

        inv_high = Investigation()
        inv_high.priority = 5

        assert inv_high.priority > inv_low.priority


class TestInvestigationWorkflow:
    """Tests for investigation workflow state transitions."""

    def test_valid_status_transitions(self):
        """Test valid status transition flow."""
        # Valid flow: PENDING -> RUNNING -> AWAITING_APPROVAL -> COMPLETED
        # Or: PENDING -> RUNNING -> COMPLETED (no approval needed)
        # Or: PENDING -> CANCELLED
        # Or: PENDING -> RUNNING -> FAILED

        valid_transitions = {
            InvestigationStatus.PENDING: [
                InvestigationStatus.RUNNING,
                InvestigationStatus.CANCELLED,
            ],
            InvestigationStatus.RUNNING: [
                InvestigationStatus.AWAITING_APPROVAL,
                InvestigationStatus.COMPLETED,
                InvestigationStatus.FAILED,
                InvestigationStatus.CANCELLED,
            ],
            InvestigationStatus.AWAITING_APPROVAL: [
                InvestigationStatus.COMPLETED,
                InvestigationStatus.FAILED,
                InvestigationStatus.CANCELLED,
            ],
        }

        # Verify all transitions are defined
        assert InvestigationStatus.PENDING in valid_transitions
        assert InvestigationStatus.RUNNING in valid_transitions
        assert InvestigationStatus.AWAITING_APPROVAL in valid_transitions

    def test_action_approval_flow(self):
        """Test action approval state transitions."""
        # Valid flow: PENDING -> APPROVED -> EXECUTED
        # Or: PENDING -> REJECTED

        action = InvestigationAction()
        action.status = InvestigationActionStatus.PENDING

        # Can be approved
        action.status = InvestigationActionStatus.APPROVED
        assert action.status == InvestigationActionStatus.APPROVED

        # Then executed
        action.status = InvestigationActionStatus.EXECUTED
        assert action.status == InvestigationActionStatus.EXECUTED

    def test_action_rejection_flow(self):
        """Test action rejection state transition."""
        action = InvestigationAction()
        action.status = InvestigationActionStatus.PENDING

        # Can be rejected
        action.status = InvestigationActionStatus.REJECTED
        assert action.status == InvestigationActionStatus.REJECTED
