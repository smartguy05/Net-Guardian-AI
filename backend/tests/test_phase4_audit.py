"""Tests for Phase 4 audit service."""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from app.models.audit_log import AuditAction, AuditLog
from app.services.audit_service import AuditService


class TestAuditService:
    """Tests for the audit service."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock database session."""
        session = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        session.close = AsyncMock()
        return session

    @pytest.fixture
    def mock_user(self):
        """Create a mock user."""
        user = MagicMock()
        user.id = uuid4()
        user.username = "testuser"
        return user

    @pytest.fixture
    def audit_service(self, mock_session):
        """Create an audit service instance."""
        return AuditService(session=mock_session)

    @pytest.mark.asyncio
    async def test_log_creates_audit_entry(self, audit_service, mock_session, mock_user):
        """Test that log creates an audit entry."""
        await audit_service.log(
            action=AuditAction.DEVICE_QUARANTINE,
            target_type="device",
            description="Test quarantine",
            user=mock_user,
            target_id="device-123",
            target_name="Test Device",
        )

        # Verify that add was called with an AuditLog
        mock_session.add.assert_called_once()
        call_args = mock_session.add.call_args[0][0]
        assert isinstance(call_args, AuditLog)
        assert call_args.action == AuditAction.DEVICE_QUARANTINE
        assert call_args.target_type == "device"
        assert call_args.description == "Test quarantine"
        assert call_args.user_id == mock_user.id
        assert call_args.username == mock_user.username

    @pytest.mark.asyncio
    async def test_log_device_quarantine(self, audit_service, mock_session, mock_user):
        """Test logging a device quarantine action."""
        device_id = uuid4()

        await audit_service.log_device_quarantine(
            device_id=device_id,
            device_name="Test Device",
            mac_address="AA:BB:CC:DD:EE:FF",
            user=mock_user,
            reason="Suspicious activity",
            ip_address="192.168.1.50",
        )

        mock_session.add.assert_called_once()
        call_args = mock_session.add.call_args[0][0]
        assert call_args.action == AuditAction.DEVICE_QUARANTINE
        assert call_args.target_id == str(device_id)
        assert call_args.target_name == "Test Device"
        assert call_args.details["reason"] == "Suspicious activity"
        assert call_args.details["mac_address"] == "AA:BB:CC:DD:EE:FF"

    @pytest.mark.asyncio
    async def test_log_device_release(self, audit_service, mock_session, mock_user):
        """Test logging a device release action."""
        device_id = uuid4()

        await audit_service.log_device_release(
            device_id=device_id,
            device_name="Test Device",
            mac_address="AA:BB:CC:DD:EE:FF",
            user=mock_user,
            reason="False positive",
        )

        mock_session.add.assert_called_once()
        call_args = mock_session.add.call_args[0][0]
        assert call_args.action == AuditAction.DEVICE_RELEASE
        assert call_args.target_id == str(device_id)
        assert call_args.details["reason"] == "False positive"

    @pytest.mark.asyncio
    async def test_log_integration_action(self, audit_service, mock_session, mock_user):
        """Test logging an integration action."""
        await audit_service.log_integration_action(
            action=AuditAction.INTEGRATION_BLOCK,
            integration_type="adguard_home",
            target="AA:BB:CC:DD:EE:FF",
            user=mock_user,
            success=True,
            details={"ip": "192.168.1.100"},
        )

        mock_session.add.assert_called_once()
        call_args = mock_session.add.call_args[0][0]
        assert call_args.action == AuditAction.INTEGRATION_BLOCK
        assert call_args.target_type == "integration"
        assert call_args.details["integration_type"] == "adguard_home"

    @pytest.mark.asyncio
    async def test_log_user_login(self, audit_service, mock_session, mock_user):
        """Test logging a user login action."""
        await audit_service.log_user_login(
            user=mock_user,
            ip_address="192.168.1.50",
            success=True,
        )

        mock_session.add.assert_called_once()
        call_args = mock_session.add.call_args[0][0]
        assert call_args.action == AuditAction.USER_LOGIN
        assert call_args.success is True
        assert call_args.ip_address == "192.168.1.50"

    @pytest.mark.asyncio
    async def test_log_user_login_failure(self, audit_service, mock_session):
        """Test logging a failed user login."""
        await audit_service.log_user_login(
            username="baduser",
            ip_address="192.168.1.50",
            success=False,
            error_message="Invalid password",
        )

        mock_session.add.assert_called_once()
        call_args = mock_session.add.call_args[0][0]
        assert call_args.action == AuditAction.USER_LOGIN
        assert call_args.success is False
        assert call_args.error_message == "Invalid password"

    @pytest.mark.asyncio
    async def test_log_handles_no_user(self, audit_service, mock_session):
        """Test that log handles no user gracefully."""
        await audit_service.log(
            action=AuditAction.DEVICE_QUARANTINE,
            target_type="device",
            description="System quarantine",
            user=None,
        )

        mock_session.add.assert_called_once()
        call_args = mock_session.add.call_args[0][0]
        assert call_args.user_id is None
        assert call_args.username is None


class TestAuditAction:
    """Tests for the AuditAction enum."""

    def test_all_actions_have_values(self):
        """Test that all actions have string values."""
        for action in AuditAction:
            assert isinstance(action.value, str)
            assert len(action.value) > 0

    def test_device_actions_exist(self):
        """Test that device-related actions exist."""
        assert AuditAction.DEVICE_QUARANTINE.value == "device_quarantine"
        assert AuditAction.DEVICE_RELEASE.value == "device_release"
        assert AuditAction.DEVICE_UPDATE.value == "device_update"

    def test_user_actions_exist(self):
        """Test that user-related actions exist."""
        assert AuditAction.USER_LOGIN.value == "user_login"
        assert AuditAction.USER_LOGOUT.value == "user_logout"
        assert AuditAction.USER_CREATE.value == "user_create"

    def test_integration_actions_exist(self):
        """Test that integration-related actions exist."""
        assert AuditAction.INTEGRATION_BLOCK.value == "integration_block"
        assert AuditAction.INTEGRATION_UNBLOCK.value == "integration_unblock"
        assert AuditAction.INTEGRATION_TEST.value == "integration_test"

    def test_playbook_actions_exist(self):
        """Test that playbook-related actions exist."""
        assert AuditAction.PLAYBOOK_EXECUTE.value == "playbook_execute"
        assert AuditAction.PLAYBOOK_CREATE.value == "playbook_create"
        assert AuditAction.PLAYBOOK_UPDATE.value == "playbook_update"
