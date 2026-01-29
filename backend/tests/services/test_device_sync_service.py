"""Tests for the device sync service."""

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.device_sync_service import DeviceSyncResult, DeviceSyncService


class TestDeviceSyncService:
    """Tests for the DeviceSyncService class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock async session."""
        session = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.close = AsyncMock()
        return session

    @pytest.fixture
    def sync_service(self):
        """Create a sync service instance."""
        return DeviceSyncService()

    @pytest.fixture
    def mock_devices(self):
        """Create mock devices for testing."""
        devices = []

        # Device 1: Has IP that matches AdGuard client
        device1 = MagicMock()
        device1.id = uuid4()
        device1.mac_address = "aa:bb:cc:dd:ee:01"
        device1.ip_addresses = ["192.168.1.100"]
        device1.hostname = None  # No hostname yet
        devices.append(device1)

        # Device 2: Has MAC that matches AdGuard client
        device2 = MagicMock()
        device2.id = uuid4()
        device2.mac_address = "aa:bb:cc:dd:ee:02"
        device2.ip_addresses = ["192.168.1.101"]
        device2.hostname = None
        devices.append(device2)

        # Device 3: No matching AdGuard client
        device3 = MagicMock()
        device3.id = uuid4()
        device3.mac_address = "aa:bb:cc:dd:ee:03"
        device3.ip_addresses = ["192.168.1.102"]
        device3.hostname = None
        devices.append(device3)

        # Device 4: Already has hostname
        device4 = MagicMock()
        device4.id = uuid4()
        device4.mac_address = "aa:bb:cc:dd:ee:04"
        device4.ip_addresses = ["192.168.1.103"]
        device4.hostname = "existing-hostname"
        devices.append(device4)

        return devices

    @pytest.mark.asyncio
    async def test_sync_when_adguard_disabled(self, sync_service, mock_session):
        """Should return empty result when AdGuard is disabled."""
        with patch(
            "app.services.device_sync_service.get_adguard_service"
        ) as mock_get_adguard:
            mock_adguard = MagicMock()
            mock_adguard.is_enabled = False
            mock_get_adguard.return_value = mock_adguard

            result = await sync_service.sync_from_adguard(session=mock_session)

            assert result.total_devices == 0
            assert result.updated_devices == 0
            assert result.source == "adguard"

    @pytest.mark.asyncio
    async def test_sync_with_no_clients(self, sync_service, mock_session):
        """Should return empty result when no AdGuard clients exist."""
        with patch(
            "app.services.device_sync_service.get_adguard_service"
        ) as mock_get_adguard:
            mock_adguard = AsyncMock()
            mock_adguard.is_enabled = True
            mock_adguard.get_device_name_mapping = AsyncMock(return_value={})
            mock_get_adguard.return_value = mock_adguard

            result = await sync_service.sync_from_adguard(session=mock_session)

            assert result.total_devices == 0
            assert result.updated_devices == 0

    @pytest.mark.asyncio
    async def test_sync_matches_by_ip(self, sync_service, mock_session, mock_devices):
        """Should match devices by IP address."""
        # Setup mock AdGuard with IP -> name mapping
        name_mapping = {
            "192.168.1.100": "Living Room TV",
            "192.168.1.103": "Kitchen Tablet",  # Device 4 (has existing hostname)
        }

        # Setup mock session to return devices
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        with patch(
            "app.services.device_sync_service.get_adguard_service"
        ) as mock_get_adguard:
            mock_adguard = AsyncMock()
            mock_adguard.is_enabled = True
            mock_adguard.get_device_name_mapping = AsyncMock(return_value=name_mapping)
            mock_get_adguard.return_value = mock_adguard

            result = await sync_service.sync_from_adguard(
                session=mock_session, overwrite_existing=False
            )

            # Should have updated device1 (IP match, no existing hostname)
            assert result.total_devices == 4
            assert result.updated_devices == 1  # Only device1
            assert result.skipped_devices == 1  # device4 (has hostname)

            # Verify device1 got updated
            assert mock_devices[0].hostname == "Living Room TV"

    @pytest.mark.asyncio
    async def test_sync_matches_by_mac(self, sync_service, mock_session, mock_devices):
        """Should match devices by MAC address."""
        # Setup mock AdGuard with MAC -> name mapping
        name_mapping = {
            "aa:bb:cc:dd:ee:02": "Bedroom Laptop",
        }

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        with patch(
            "app.services.device_sync_service.get_adguard_service"
        ) as mock_get_adguard:
            mock_adguard = AsyncMock()
            mock_adguard.is_enabled = True
            mock_adguard.get_device_name_mapping = AsyncMock(return_value=name_mapping)
            mock_get_adguard.return_value = mock_adguard

            result = await sync_service.sync_from_adguard(session=mock_session)

            assert result.updated_devices == 1
            assert mock_devices[1].hostname == "Bedroom Laptop"

    @pytest.mark.asyncio
    async def test_sync_overwrite_existing(
        self, sync_service, mock_session, mock_devices
    ):
        """Should overwrite existing hostnames when overwrite_existing=True."""
        name_mapping = {
            "192.168.1.103": "New Name for Device 4",  # Device 4 has existing hostname
        }

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        with patch(
            "app.services.device_sync_service.get_adguard_service"
        ) as mock_get_adguard:
            mock_adguard = AsyncMock()
            mock_adguard.is_enabled = True
            mock_adguard.get_device_name_mapping = AsyncMock(return_value=name_mapping)
            mock_get_adguard.return_value = mock_adguard

            result = await sync_service.sync_from_adguard(
                session=mock_session, overwrite_existing=True
            )

            assert result.updated_devices == 1
            assert mock_devices[3].hostname == "New Name for Device 4"

    @pytest.mark.asyncio
    async def test_sync_returns_details(self, sync_service, mock_session, mock_devices):
        """Should return details about updated devices."""
        name_mapping = {
            "192.168.1.100": "Living Room TV",
        }

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices
        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result

        with patch(
            "app.services.device_sync_service.get_adguard_service"
        ) as mock_get_adguard:
            mock_adguard = AsyncMock()
            mock_adguard.is_enabled = True
            mock_adguard.get_device_name_mapping = AsyncMock(return_value=name_mapping)
            mock_get_adguard.return_value = mock_adguard

            result = await sync_service.sync_from_adguard(session=mock_session)

            assert len(result.details) == 1
            detail = result.details[0]
            assert detail["new_hostname"] == "Living Room TV"
            assert detail["old_hostname"] == "(none)"
            assert "ip:192.168.1.100" in detail["matched_by"]


class TestDeviceSyncResult:
    """Tests for the DeviceSyncResult dataclass."""

    def test_dataclass_creation(self):
        """Should create result with all fields."""
        result = DeviceSyncResult(
            total_devices=10,
            updated_devices=3,
            skipped_devices=2,
            source="adguard",
            details=[{"device_id": "123", "new_hostname": "test"}],
        )

        assert result.total_devices == 10
        assert result.updated_devices == 3
        assert result.skipped_devices == 2
        assert result.source == "adguard"
        assert len(result.details) == 1
