"""Tests for the Quarantine Service.

Tests cover:
- Quarantine device operations
- Release device operations
- Integration with AdGuard and routers
- Audit logging
- Error handling
- Get quarantined devices
- Sync quarantine status
"""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.models.device import Device, DeviceStatus
from app.models.user import User, UserRole
from app.services.integrations.base import ActionType, IntegrationResult, IntegrationType
from app.services.quarantine_service import QuarantineResult, QuarantineService


@pytest.fixture
def mock_session():
    """Create a mock async session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def mock_adguard():
    """Create a mock AdGuard service."""
    adguard = MagicMock()
    adguard.is_enabled = True
    adguard.block_device = AsyncMock()
    adguard.unblock_device = AsyncMock()
    adguard.is_device_blocked = AsyncMock()
    return adguard


@pytest.fixture
def mock_router():
    """Create a mock router service."""
    router = MagicMock()
    router.is_enabled = True
    router.integration_type = IntegrationType.UNIFI
    router.block_device = AsyncMock()
    router.unblock_device = AsyncMock()
    router.is_device_blocked = AsyncMock()
    return router


@pytest.fixture
def mock_audit():
    """Create a mock audit service."""
    audit = MagicMock()
    audit.log_device_quarantine = AsyncMock()
    audit.log_device_release = AsyncMock()
    audit.log_integration_action = AsyncMock()
    return audit


@pytest.fixture
def sample_device():
    """Create a sample device."""
    device = MagicMock(spec=Device)
    device.id = uuid4()
    device.hostname = "test-device"
    device.mac_address = "AA:BB:CC:DD:EE:FF"
    device.ip_addresses = ["192.168.1.100"]
    device.status = DeviceStatus.ACTIVE
    return device


@pytest.fixture
def sample_user():
    """Create a sample user."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "admin"
    user.role = UserRole.ADMIN
    return user


@pytest.fixture
def quarantine_service(mock_session, mock_adguard, mock_router, mock_audit):
    """Create a QuarantineService instance with mocks."""
    return QuarantineService(
        session=mock_session,
        adguard_service=mock_adguard,
        router_service=mock_router,
        audit_service=mock_audit,
    )


class TestQuarantineResult:
    """Tests for QuarantineResult dataclass."""

    def test_to_dict(self):
        """Should convert result to dictionary."""
        result = QuarantineResult(
            success=True,
            device_id=uuid4(),
            device_name="test-device",
            mac_address="AA:BB:CC:DD:EE:FF",
            message="Device quarantined",
            integration_results=[{"adguard": True}],
            errors=[],
        )

        result_dict = result.to_dict()

        assert result_dict["success"] is True
        assert result_dict["device_name"] == "test-device"
        assert result_dict["mac_address"] == "AA:BB:CC:DD:EE:FF"
        assert result_dict["message"] == "Device quarantined"

    def test_to_dict_with_errors(self):
        """Should include errors in dictionary."""
        result = QuarantineResult(
            success=False,
            device_id=uuid4(),
            device_name="test",
            mac_address="AA:BB:CC:DD:EE:FF",
            message="Failed",
            integration_results=[],
            errors=["Error 1", "Error 2"],
        )

        result_dict = result.to_dict()

        assert result_dict["success"] is False
        assert len(result_dict["errors"]) == 2


class TestQuarantineServiceInit:
    """Tests for QuarantineService initialization."""

    def test_init_with_mocks(self, mock_session, mock_adguard, mock_router, mock_audit):
        """Should initialize with provided services."""
        service = QuarantineService(
            session=mock_session,
            adguard_service=mock_adguard,
            router_service=mock_router,
            audit_service=mock_audit,
        )

        assert service._session == mock_session
        assert service._adguard == mock_adguard
        assert service._router == mock_router
        assert service._audit == mock_audit

    def test_init_without_router(self, mock_session, mock_adguard, mock_audit):
        """Should initialize without router service."""
        service = QuarantineService(
            session=mock_session,
            adguard_service=mock_adguard,
            router_service=None,
            audit_service=mock_audit,
        )

        assert service._router is None


class TestQuarantineDeviceOperation:
    """Tests for quarantine_device method."""

    @pytest.mark.asyncio
    async def test_quarantine_device_success(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device, sample_user
    ):
        """Should successfully quarantine a device."""
        # Setup mocks
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        adguard_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device blocked in AdGuard",
        )
        mock_adguard.block_device.return_value = adguard_result

        router_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device blocked in router",
        )
        mock_router.block_device.return_value = router_result

        # Execute
        result = await quarantine_service.quarantine_device(
            device_id=sample_device.id,
            user=sample_user,
            reason="Suspicious activity",
        )

        # Verify
        assert result.success is True
        assert sample_device.status == DeviceStatus.QUARANTINED
        mock_adguard.block_device.assert_called_once()
        mock_router.block_device.assert_called_once()
        mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_quarantine_device_not_found(self, quarantine_service, mock_session, sample_user):
        """Should return failure for non-existent device."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await quarantine_service.quarantine_device(
            device_id=uuid4(),
            user=sample_user,
        )

        assert result.success is False
        assert "not found" in result.message.lower()

    @pytest.mark.asyncio
    async def test_quarantine_already_quarantined(
        self, quarantine_service, mock_session, sample_device, sample_user
    ):
        """Should return failure for already quarantined device."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        result = await quarantine_service.quarantine_device(
            device_id=sample_device.id,
            user=sample_user,
        )

        assert result.success is False
        assert "already quarantined" in result.message.lower()

    @pytest.mark.asyncio
    async def test_quarantine_adguard_failure(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device, sample_user
    ):
        """Should succeed with warning when AdGuard fails."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        adguard_result = IntegrationResult(
            success=False,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Failed to block device",
            error="Connection refused",
        )
        mock_adguard.block_device.return_value = adguard_result

        router_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device blocked in router",
        )
        mock_router.block_device.return_value = router_result

        result = await quarantine_service.quarantine_device(
            device_id=sample_device.id,
            user=sample_user,
        )

        # Should still succeed (DB updated) but with warning
        assert result.success is True
        assert len(result.errors) > 0
        assert "warning" in result.message.lower()

    @pytest.mark.asyncio
    async def test_quarantine_without_ip(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device, sample_user
    ):
        """Should quarantine device without IP addresses."""
        sample_device.ip_addresses = []

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        adguard_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device blocked in AdGuard",
        )
        mock_adguard.block_device.return_value = adguard_result

        router_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device blocked in router",
        )
        mock_router.block_device.return_value = router_result

        result = await quarantine_service.quarantine_device(
            device_id=sample_device.id,
            user=sample_user,
        )

        # Should pass None as ip_address
        mock_adguard.block_device.assert_called_once_with(
            mac_address=sample_device.mac_address,
            ip_address=None,
            reason=None,
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_quarantine_exception_handling(
        self, quarantine_service, mock_session, sample_device, sample_user
    ):
        """Should handle exceptions gracefully."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result
        mock_session.commit.side_effect = Exception("Database error")

        result = await quarantine_service.quarantine_device(
            device_id=sample_device.id,
            user=sample_user,
        )

        assert result.success is False
        assert "Database error" in result.errors[0]
        mock_session.rollback.assert_called_once()

    @pytest.mark.asyncio
    async def test_quarantine_adguard_disabled(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device, sample_user
    ):
        """Should skip AdGuard when disabled."""
        mock_adguard.is_enabled = False

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        router_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device blocked in router",
        )
        mock_router.block_device.return_value = router_result

        result = await quarantine_service.quarantine_device(
            device_id=sample_device.id,
            user=sample_user,
        )

        assert result.success is True
        mock_adguard.block_device.assert_not_called()


class TestReleaseDeviceOperation:
    """Tests for release_device method."""

    @pytest.mark.asyncio
    async def test_release_device_success(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device, sample_user
    ):
        """Should successfully release a device."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        adguard_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.UNBLOCK,
            target=sample_device.mac_address,
            message="Device unblocked in AdGuard",
        )
        mock_adguard.unblock_device.return_value = adguard_result

        router_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.UNBLOCK,
            target=sample_device.mac_address,
            message="Device unblocked in router",
        )
        mock_router.unblock_device.return_value = router_result

        result = await quarantine_service.release_device(
            device_id=sample_device.id,
            user=sample_user,
            reason="Investigation complete",
        )

        assert result.success is True
        assert sample_device.status == DeviceStatus.ACTIVE
        mock_adguard.unblock_device.assert_called_once()
        mock_router.unblock_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_release_device_not_found(self, quarantine_service, mock_session, sample_user):
        """Should return failure for non-existent device."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result

        result = await quarantine_service.release_device(
            device_id=uuid4(),
            user=sample_user,
        )

        assert result.success is False
        assert "not found" in result.message.lower()

    @pytest.mark.asyncio
    async def test_release_device_not_quarantined(
        self, quarantine_service, mock_session, sample_device, sample_user
    ):
        """Should return failure for non-quarantined device."""
        sample_device.status = DeviceStatus.ACTIVE

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        result = await quarantine_service.release_device(
            device_id=sample_device.id,
            user=sample_user,
        )

        assert result.success is False
        assert "not quarantined" in result.message.lower()

    @pytest.mark.asyncio
    async def test_release_device_integration_failure(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device, sample_user
    ):
        """Should succeed with warning when integration fails."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        adguard_result = IntegrationResult(
            success=False,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.UNBLOCK,
            target=sample_device.mac_address,
            message="Failed to unblock device",
            error="Device not found in AdGuard",
        )
        mock_adguard.unblock_device.return_value = adguard_result

        router_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.UNBLOCK,
            target=sample_device.mac_address,
            message="Device unblocked in router",
        )
        mock_router.unblock_device.return_value = router_result

        result = await quarantine_service.release_device(
            device_id=sample_device.id,
            user=sample_user,
        )

        assert result.success is True
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_release_device_exception(
        self, quarantine_service, mock_session, sample_device, sample_user
    ):
        """Should handle exceptions gracefully."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result
        mock_session.commit.side_effect = Exception("Database error")

        result = await quarantine_service.release_device(
            device_id=sample_device.id,
            user=sample_user,
        )

        assert result.success is False
        mock_session.rollback.assert_called_once()


class TestGetQuarantinedDevices:
    """Tests for get_quarantined_devices method."""

    @pytest.mark.asyncio
    async def test_get_quarantined_devices(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device
    ):
        """Should return list of quarantined devices."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_device]
        mock_session.execute.return_value = mock_result

        mock_adguard.is_device_blocked.return_value = True
        mock_router.is_device_blocked.return_value = True

        devices = await quarantine_service.get_quarantined_devices()

        assert len(devices) == 1
        assert devices[0]["mac_address"] == sample_device.mac_address
        assert devices[0]["adguard_blocked"] is True
        assert devices[0]["router_blocked"] is True

    @pytest.mark.asyncio
    async def test_get_quarantined_devices_empty(self, quarantine_service, mock_session):
        """Should return empty list when no quarantined devices."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result

        devices = await quarantine_service.get_quarantined_devices()

        assert len(devices) == 0

    @pytest.mark.asyncio
    async def test_get_quarantined_devices_without_router(
        self, mock_session, mock_adguard, mock_audit, sample_device
    ):
        """Should handle missing router service."""
        service = QuarantineService(
            session=mock_session,
            adguard_service=mock_adguard,
            router_service=None,
            audit_service=mock_audit,
        )

        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_device]
        mock_session.execute.return_value = mock_result

        mock_adguard.is_device_blocked.return_value = True

        devices = await service.get_quarantined_devices()

        assert len(devices) == 1
        assert devices[0]["router_blocked"] is False
        assert devices[0]["router_type"] is None


class TestSyncQuarantineStatus:
    """Tests for sync_quarantine_status method."""

    @pytest.mark.asyncio
    async def test_sync_status_all_synced(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device
    ):
        """Should report no changes when all synced."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_device]
        mock_session.execute.return_value = mock_result

        # Device is already blocked in both
        mock_adguard.is_device_blocked.return_value = True
        mock_router.is_device_blocked.return_value = True

        summary = await quarantine_service.sync_quarantine_status()

        assert summary["checked"] == 1
        assert summary["synced"] == 0
        assert len(summary["errors"]) == 0

    @pytest.mark.asyncio
    async def test_sync_status_reblock_in_adguard(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device
    ):
        """Should re-block device in AdGuard if not blocked."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_device]
        mock_session.execute.return_value = mock_result

        mock_adguard.is_device_blocked.return_value = False
        mock_router.is_device_blocked.return_value = True

        block_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device re-blocked in AdGuard",
        )
        mock_adguard.block_device.return_value = block_result

        summary = await quarantine_service.sync_quarantine_status()

        assert summary["synced"] == 1
        mock_adguard.block_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_status_reblock_in_router(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device
    ):
        """Should re-block device in router if not blocked."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_device]
        mock_session.execute.return_value = mock_result

        mock_adguard.is_device_blocked.return_value = True
        mock_router.is_device_blocked.return_value = False

        block_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device re-blocked in router",
        )
        mock_router.block_device.return_value = block_result

        summary = await quarantine_service.sync_quarantine_status()

        assert summary["synced"] == 1
        mock_router.block_device.assert_called_once()

    @pytest.mark.asyncio
    async def test_sync_status_with_errors(
        self, quarantine_service, mock_session, mock_adguard, mock_router, sample_device
    ):
        """Should collect errors during sync."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [sample_device]
        mock_session.execute.return_value = mock_result

        mock_adguard.is_device_blocked.return_value = False
        mock_router.is_device_blocked.return_value = True

        block_result = IntegrationResult(
            success=False,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Failed to re-block device",
            error="API error",
        )
        mock_adguard.block_device.return_value = block_result

        summary = await quarantine_service.sync_quarantine_status()

        assert len(summary["errors"]) == 1
        assert "API error" in summary["errors"][0]


class TestAuditLogging:
    """Tests for audit logging in quarantine operations."""

    @pytest.mark.asyncio
    async def test_quarantine_creates_audit_log(
        self, quarantine_service, mock_session, mock_adguard, mock_router, mock_audit, sample_device, sample_user
    ):
        """Should create audit log when quarantining."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        adguard_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device blocked in AdGuard",
        )
        mock_adguard.block_device.return_value = adguard_result

        router_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.BLOCK,
            target=sample_device.mac_address,
            message="Device blocked in router",
        )
        mock_router.block_device.return_value = router_result

        await quarantine_service.quarantine_device(
            device_id=sample_device.id,
            user=sample_user,
            reason="Test reason",
            ip_address="10.0.0.1",
        )

        mock_audit.log_device_quarantine.assert_called_once()
        mock_audit.log_integration_action.assert_called()

    @pytest.mark.asyncio
    async def test_release_creates_audit_log(
        self, quarantine_service, mock_session, mock_adguard, mock_router, mock_audit, sample_device, sample_user
    ):
        """Should create audit log when releasing."""
        sample_device.status = DeviceStatus.QUARANTINED

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result

        adguard_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.ADGUARD_HOME,
            action=ActionType.UNBLOCK,
            target=sample_device.mac_address,
            message="Device unblocked in AdGuard",
        )
        mock_adguard.unblock_device.return_value = adguard_result

        router_result = IntegrationResult(
            success=True,
            integration_type=IntegrationType.UNIFI,
            action=ActionType.UNBLOCK,
            target=sample_device.mac_address,
            message="Device unblocked in router",
        )
        mock_router.unblock_device.return_value = router_result

        await quarantine_service.release_device(
            device_id=sample_device.id,
            user=sample_user,
            reason="Investigation complete",
        )

        mock_audit.log_device_release.assert_called_once()


class TestSessionManagement:
    """Tests for database session management."""

    @pytest.mark.asyncio
    async def test_uses_provided_session(self, mock_session, mock_adguard, mock_audit):
        """Should use provided session."""
        service = QuarantineService(
            session=mock_session,
            adguard_service=mock_adguard,
            audit_service=mock_audit,
        )

        session = await service._get_session()

        assert session == mock_session

    @pytest.mark.asyncio
    async def test_closes_internal_session(self, mock_adguard, mock_audit):
        """Should close internally created session."""
        service = QuarantineService(
            session=None,  # No session provided
            adguard_service=mock_adguard,
            audit_service=mock_audit,
        )

        mock_internal_session = AsyncMock()

        # Should not close if same as provided session
        await service._close_session(service._session)  # No-op

        # Should close different session
        with patch.object(service, "_session", None):
            await service._close_session(mock_internal_session)
            mock_internal_session.close.assert_called_once()


class TestGlobalServiceInstance:
    """Tests for global service instance."""

    def test_get_quarantine_service(self):
        """Should return global service instance."""
        from app.services.quarantine_service import get_quarantine_service

        service = get_quarantine_service()

        assert isinstance(service, QuarantineService)

    def test_get_quarantine_service_singleton(self):
        """Should return same instance."""
        from app.services.quarantine_service import get_quarantine_service

        service1 = get_quarantine_service()
        service2 = get_quarantine_service()

        assert service1 is service2
