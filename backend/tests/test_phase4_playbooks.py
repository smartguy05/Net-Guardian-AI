"""Tests for Phase 4 playbook engine."""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.models.playbook import (
    ExecutionStatus,
    Playbook,
    PlaybookActionType,
    PlaybookStatus,
    PlaybookTriggerType,
)
from app.services.playbook_engine import PlaybookEngine


class TestPlaybookEngine:
    """Tests for the playbook engine."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        session.close = AsyncMock()
        session.rollback = AsyncMock()
        return session

    @pytest.fixture
    def mock_quarantine_service(self):
        """Create a mock quarantine service."""
        service = MagicMock()
        service.quarantine_device = AsyncMock()
        service.release_device = AsyncMock()
        return service

    @pytest.fixture
    def mock_audit_service(self):
        """Create a mock audit service."""
        service = MagicMock()
        service.log = AsyncMock()
        service.log_device_quarantine = AsyncMock()
        service.log_device_release = AsyncMock()
        return service

    @pytest.fixture
    def playbook_engine(self, mock_session, mock_quarantine_service, mock_audit_service):
        """Create a playbook engine instance."""
        return PlaybookEngine(
            session=mock_session,
            quarantine_service=mock_quarantine_service,
            audit_service=mock_audit_service,
        )

    @pytest.fixture
    def sample_playbook(self):
        """Create a sample playbook."""
        playbook = MagicMock(spec=Playbook)
        playbook.id = uuid4()
        playbook.name = "Test Playbook"
        playbook.status = PlaybookStatus.ACTIVE
        playbook.trigger_type = PlaybookTriggerType.ANOMALY_DETECTED
        playbook.trigger_conditions = {"min_severity": "high"}
        playbook.actions = [
            {
                "type": PlaybookActionType.QUARANTINE_DEVICE.value,
                "params": {"reason": "Automated response"},
                "stop_on_failure": True,
            }
        ]
        playbook.cooldown_minutes = 60
        playbook.max_executions_per_hour = 10
        return playbook

    @pytest.mark.asyncio
    async def test_check_trigger_conditions_passes_for_matching_severity(
        self, playbook_engine, sample_playbook
    ):
        """Test trigger conditions pass for matching severity."""
        event_data = {"severity": "high"}

        result = await playbook_engine._check_trigger_conditions(
            sample_playbook, event_data, None
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_check_trigger_conditions_fails_for_low_severity(
        self, playbook_engine, sample_playbook
    ):
        """Test trigger conditions fail for low severity."""
        event_data = {"severity": "low"}

        result = await playbook_engine._check_trigger_conditions(
            sample_playbook, event_data, None
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_execute_action_quarantine_calls_service(
        self, playbook_engine, mock_quarantine_service
    ):
        """Test quarantine action calls quarantine service."""
        device_id = uuid4()
        mock_quarantine_service.quarantine_device.return_value = MagicMock(
            success=True,
            message="Device quarantined",
            device_name="Test Device",
            integration_results=[],
            errors=[],
        )

        action = {
            "type": PlaybookActionType.QUARANTINE_DEVICE.value,
            "params": {"reason": "Test quarantine"},
        }

        result = await playbook_engine._execute_action(
            action, {"description": "Test"}, device_id, None
        )

        mock_quarantine_service.quarantine_device.assert_called_once()
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_action_release_calls_service(
        self, playbook_engine, mock_quarantine_service
    ):
        """Test release action calls quarantine service."""
        device_id = uuid4()
        mock_quarantine_service.release_device.return_value = MagicMock(
            success=True,
            message="Device released",
            device_name="Test Device",
        )

        action = {
            "type": PlaybookActionType.RELEASE_DEVICE.value,
            "params": {"reason": "Test release"},
        }

        result = await playbook_engine._execute_action(
            action, {"description": "Test"}, device_id, None
        )

        mock_quarantine_service.release_device.assert_called_once()
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_execute_action_unknown_type_returns_error(self, playbook_engine):
        """Test unknown action type returns error."""
        action = {
            "type": "unknown_action",
            "params": {},
        }

        result = await playbook_engine._execute_action(
            action, {}, None, None
        )

        assert result["success"] is False
        assert "unknown action type" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_action_tag_device_adds_tags(self, playbook_engine, mock_session):
        """Test tag device action adds tags."""
        device_id = uuid4()

        # Mock the device query
        mock_device = MagicMock()
        mock_device.profile_tags = ["existing"]
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_session.execute.return_value = mock_result

        result = await playbook_engine._action_tag_device(
            device_id,
            {"add_tags": ["new_tag"], "remove_tags": []},
        )

        assert result["success"] is True
        assert "new_tag" in result["tags_added"]

    @pytest.mark.asyncio
    async def test_action_tag_device_removes_tags(self, playbook_engine, mock_session):
        """Test tag device action removes tags."""
        device_id = uuid4()

        # Mock the device query
        mock_device = MagicMock()
        mock_device.profile_tags = ["existing", "to_remove"]
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_session.execute.return_value = mock_result

        result = await playbook_engine._action_tag_device(
            device_id,
            {"add_tags": [], "remove_tags": ["to_remove"]},
        )

        assert result["success"] is True
        assert "to_remove" in result["tags_removed"]

    @pytest.mark.asyncio
    async def test_action_log_event(self, playbook_engine):
        """Test log event action creates log."""
        result = await playbook_engine._action_log_event(
            {"level": "info", "message": "Test message"},
            {"description": "Test event"},
            None,
        )

        assert result["success"] is True
        assert result["level"] == "info"

    @pytest.mark.asyncio
    async def test_action_send_notification(self, playbook_engine):
        """Test send notification action."""
        result = await playbook_engine._action_send_notification(
            {"type": "log", "message": "Test notification"},
            {"description": "Test event"},
            None,
        )

        assert result["success"] is True
        assert result["notification_type"] == "log"


class TestPlaybookTriggerType:
    """Tests for PlaybookTriggerType enum."""

    def test_all_trigger_types_have_values(self):
        """Test that all trigger types have string values."""
        for trigger in PlaybookTriggerType:
            assert isinstance(trigger.value, str)
            assert len(trigger.value) > 0

    def test_expected_triggers_exist(self):
        """Test expected trigger types exist."""
        assert PlaybookTriggerType.ANOMALY_DETECTED.value == "anomaly_detected"
        assert PlaybookTriggerType.ALERT_CREATED.value == "alert_created"
        assert PlaybookTriggerType.DEVICE_NEW.value == "device_new"
        assert PlaybookTriggerType.MANUAL.value == "manual"


class TestPlaybookActionType:
    """Tests for PlaybookActionType enum."""

    def test_all_action_types_have_values(self):
        """Test that all action types have string values."""
        for action in PlaybookActionType:
            assert isinstance(action.value, str)
            assert len(action.value) > 0

    def test_expected_actions_exist(self):
        """Test expected action types exist."""
        assert PlaybookActionType.QUARANTINE_DEVICE.value == "quarantine_device"
        assert PlaybookActionType.RELEASE_DEVICE.value == "release_device"
        assert PlaybookActionType.CREATE_ALERT.value == "create_alert"
        assert PlaybookActionType.SEND_NOTIFICATION.value == "send_notification"
        assert PlaybookActionType.TAG_DEVICE.value == "tag_device"


class TestPlaybookStatus:
    """Tests for PlaybookStatus enum."""

    def test_status_values(self):
        """Test playbook status values."""
        assert PlaybookStatus.ACTIVE.value == "active"
        assert PlaybookStatus.DISABLED.value == "disabled"
        assert PlaybookStatus.DRAFT.value == "draft"


class TestExecutionStatus:
    """Tests for ExecutionStatus enum."""

    def test_status_values(self):
        """Test execution status values."""
        assert ExecutionStatus.PENDING.value == "pending"
        assert ExecutionStatus.RUNNING.value == "running"
        assert ExecutionStatus.COMPLETED.value == "completed"
        assert ExecutionStatus.FAILED.value == "failed"
        assert ExecutionStatus.CANCELLED.value == "cancelled"
