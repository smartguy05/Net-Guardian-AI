"""Tests for device management API endpoints.

Tests cover:
- List devices with pagination
- List devices with filters
- Get single device
- Update device
- Quarantine/release device
- Tag management
- Export functionality
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.device import DeviceStatus, DeviceType


class TestListDevices:
    """Tests for the list devices endpoint."""

    @pytest.fixture
    def mock_devices(self):
        """Create mock devices for testing."""
        devices = []
        for i in range(5):
            device = MagicMock()
            device.id = uuid4()
            device.mac_address = f"AA:BB:CC:DD:EE:{i:02X}"
            device.ip_addresses = [f"192.168.1.{100 + i}"]
            device.hostname = f"device-{i}"
            device.manufacturer = "Test Corp"
            device.device_type = DeviceType.PC
            device.profile_tags = ["tag1"] if i % 2 == 0 else []
            device.first_seen = datetime.now(UTC) - timedelta(days=30)
            device.last_seen = datetime.now(UTC) - timedelta(hours=i)
            device.status = DeviceStatus.ACTIVE
            device.baseline_ready = True
            devices.append(device)
        return devices

    @pytest.mark.asyncio
    async def test_list_devices_basic(
        self, mock_devices, mock_db_session, mock_current_user_viewer
    ):
        """Should return paginated list of devices."""
        # Setup mock
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 5

        mock_db_session.execute.side_effect = [mock_count_result, mock_result]

        from app.api.v1.devices import list_devices

        response = await list_devices(
            session=mock_db_session,
            _current_user=mock_current_user_viewer,
            page=1,
            page_size=50,
            tags=None,
        )

        assert response.total == 5
        assert len(response.items) == 5
        assert response.page == 1
        assert response.page_size == 50

    @pytest.mark.asyncio
    async def test_list_devices_with_status_filter(
        self, mock_devices, mock_db_session, mock_current_user_viewer
    ):
        """Should filter devices by status."""
        quarantined_devices = [d for d in mock_devices if d.status == DeviceStatus.QUARANTINED]

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = quarantined_devices

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = len(quarantined_devices)

        mock_db_session.execute.side_effect = [mock_count_result, mock_result]

        from app.api.v1.devices import list_devices

        response = await list_devices(
            session=mock_db_session,
            _current_user=mock_current_user_viewer,
            page=1,
            page_size=50,
            status=DeviceStatus.QUARANTINED,
            tags=None,
        )

        assert response.total == len(quarantined_devices)

    @pytest.mark.asyncio
    async def test_list_devices_with_type_filter(
        self, mock_devices, mock_db_session, mock_current_user_viewer
    ):
        """Should filter devices by type."""
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 5

        mock_db_session.execute.side_effect = [mock_count_result, mock_result]

        from app.api.v1.devices import list_devices

        response = await list_devices(
            session=mock_db_session,
            _current_user=mock_current_user_viewer,
            page=1,
            page_size=50,
            device_type=DeviceType.PC,
            tags=None,
        )

        assert response.total == 5

    @pytest.mark.asyncio
    async def test_list_devices_with_search(
        self, mock_devices, mock_db_session, mock_current_user_viewer
    ):
        """Should search devices by hostname/mac/manufacturer."""
        # Filter to just first device
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_devices[0]]

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 1

        mock_db_session.execute.side_effect = [mock_count_result, mock_result]

        from app.api.v1.devices import list_devices

        response = await list_devices(
            session=mock_db_session,
            _current_user=mock_current_user_viewer,
            page=1,
            page_size=50,
            search="device-0",
            tags=None,
        )

        assert response.total == 1

    @pytest.mark.asyncio
    async def test_list_devices_pagination(
        self, mock_devices, mock_db_session, mock_current_user_viewer
    ):
        """Should return correct page of results."""
        # Page 2 with page_size 2
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices[2:4]

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars

        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 5

        mock_db_session.execute.side_effect = [mock_count_result, mock_result]

        from app.api.v1.devices import list_devices

        response = await list_devices(
            session=mock_db_session,
            _current_user=mock_current_user_viewer,
            page=2,
            page_size=2,
            tags=None,
        )

        assert response.total == 5
        assert response.page == 2
        assert response.page_size == 2


class TestGetDevice:
    """Tests for the get single device endpoint."""

    @pytest.fixture
    def mock_device(self):
        """Create a mock device."""
        device = MagicMock()
        device.id = uuid4()
        device.mac_address = "AA:BB:CC:DD:EE:FF"
        device.ip_addresses = ["192.168.1.100"]
        device.hostname = "test-device"
        device.manufacturer = "Test Corp"
        device.device_type = DeviceType.PC
        device.profile_tags = ["workstation"]
        device.first_seen = datetime.now(UTC) - timedelta(days=30)
        device.last_seen = datetime.now(UTC)
        device.status = DeviceStatus.ACTIVE
        device.baseline_ready = True
        return device

    @pytest.mark.asyncio
    async def test_get_device_found(self, mock_device, mock_db_session, mock_current_user_viewer):
        """Should return device when found."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import get_device

        response = await get_device(
            device_id=mock_device.id,
            session=mock_db_session,
            _current_user=mock_current_user_viewer,
        )

        assert response.id == str(mock_device.id)
        assert response.mac_address == mock_device.mac_address
        assert response.hostname == mock_device.hostname

    @pytest.mark.asyncio
    async def test_get_device_not_found(self, mock_db_session, mock_current_user_viewer):
        """Should return 404 for non-existent device."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import get_device

        with pytest.raises(HTTPException) as exc_info:
            await get_device(
                device_id=uuid4(),
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
            )

        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail.lower()


class TestUpdateDevice:
    """Tests for the update device endpoint."""

    @pytest.fixture
    def mock_device(self):
        """Create a mock device."""
        device = MagicMock()
        device.id = uuid4()
        device.mac_address = "AA:BB:CC:DD:EE:FF"
        device.ip_addresses = ["192.168.1.100"]
        device.hostname = "test-device"
        device.manufacturer = "Test Corp"
        device.device_type = DeviceType.PC
        device.profile_tags = []
        device.first_seen = datetime.now(UTC) - timedelta(days=30)
        device.last_seen = datetime.now(UTC)
        device.status = DeviceStatus.ACTIVE
        device.baseline_ready = True
        return device

    @pytest.mark.asyncio
    async def test_update_device_hostname(
        self, mock_device, mock_db_session, mock_current_user_operator
    ):
        """Should update device hostname."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import DeviceUpdate, update_device

        update_data = DeviceUpdate(hostname="new-hostname")

        response = await update_device(
            device_id=mock_device.id,
            device_data=update_data,
            session=mock_db_session,
            _operator=mock_current_user_operator,
        )

        assert mock_device.hostname == "new-hostname"
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_device_type(
        self, mock_device, mock_db_session, mock_current_user_operator
    ):
        """Should update device type."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import DeviceUpdate, update_device

        update_data = DeviceUpdate(device_type=DeviceType.IOT)

        await update_device(
            device_id=mock_device.id,
            device_data=update_data,
            session=mock_db_session,
            _operator=mock_current_user_operator,
        )

        assert mock_device.device_type == DeviceType.IOT

    @pytest.mark.asyncio
    async def test_update_device_tags(
        self, mock_device, mock_db_session, mock_current_user_operator
    ):
        """Should update device tags."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import DeviceUpdate, update_device

        update_data = DeviceUpdate(profile_tags=["new-tag", "another-tag"])

        await update_device(
            device_id=mock_device.id,
            device_data=update_data,
            session=mock_db_session,
            _operator=mock_current_user_operator,
        )

        assert mock_device.profile_tags == ["new-tag", "another-tag"]

    @pytest.mark.asyncio
    async def test_update_device_not_found(self, mock_db_session, mock_current_user_operator):
        """Should return 404 for non-existent device."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import DeviceUpdate, update_device

        update_data = DeviceUpdate(hostname="new-hostname")

        with pytest.raises(HTTPException) as exc_info:
            await update_device(
                device_id=uuid4(),
                device_data=update_data,
                session=mock_db_session,
                _operator=mock_current_user_operator,
            )

        assert exc_info.value.status_code == 404


class TestQuarantineDevice:
    """Tests for the quarantine device endpoint."""

    @pytest.fixture
    def mock_quarantine_result(self):
        """Create a mock quarantine result."""
        result = MagicMock()
        result.success = True
        result.device_id = uuid4()
        result.device_name = "test-device"
        result.mac_address = "AA:BB:CC:DD:EE:FF"
        result.message = "Device quarantined successfully"
        result.integration_results = []
        result.errors = []
        return result

    @pytest.mark.asyncio
    async def test_quarantine_device_success(
        self, mock_quarantine_result, mock_current_user_operator
    ):
        """Should quarantine device successfully."""
        from fastapi import Request

        from app.api.v1.devices import quarantine_device

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        device_id = uuid4()

        with patch("app.api.v1.devices.get_quarantine_service") as mock_service:
            mock_qs = AsyncMock()
            mock_qs.quarantine_device.return_value = mock_quarantine_result
            mock_service.return_value = mock_qs

            response = await quarantine_device(
                device_id=device_id,
                request=request,
                operator=mock_current_user_operator,
            )

        assert response.success is True
        assert "quarantined" in response.message.lower()

    @pytest.mark.asyncio
    async def test_quarantine_device_not_found(self, mock_current_user_operator):
        """Should return 404 if device not found."""
        from fastapi import Request

        from app.api.v1.devices import quarantine_device

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message = "Device not found"

        with patch("app.api.v1.devices.get_quarantine_service") as mock_service:
            mock_qs = AsyncMock()
            mock_qs.quarantine_device.return_value = mock_result
            mock_service.return_value = mock_qs

            with pytest.raises(HTTPException) as exc_info:
                await quarantine_device(
                    device_id=uuid4(),
                    request=request,
                    operator=mock_current_user_operator,
                )

        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_quarantine_already_quarantined(self, mock_current_user_operator):
        """Should return 400 if device already quarantined."""
        from fastapi import Request

        from app.api.v1.devices import quarantine_device

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message = "Device is already quarantined"

        with patch("app.api.v1.devices.get_quarantine_service") as mock_service:
            mock_qs = AsyncMock()
            mock_qs.quarantine_device.return_value = mock_result
            mock_service.return_value = mock_qs

            with pytest.raises(HTTPException) as exc_info:
                await quarantine_device(
                    device_id=uuid4(),
                    request=request,
                    operator=mock_current_user_operator,
                )

        assert exc_info.value.status_code == 400


class TestReleaseDevice:
    """Tests for the release device from quarantine endpoint."""

    @pytest.fixture
    def mock_release_result(self):
        """Create a mock release result."""
        result = MagicMock()
        result.success = True
        result.device_id = uuid4()
        result.device_name = "test-device"
        result.mac_address = "AA:BB:CC:DD:EE:FF"
        result.message = "Device released successfully"
        result.integration_results = []
        result.errors = []
        return result

    @pytest.mark.asyncio
    async def test_release_device_success(self, mock_release_result, mock_current_user_operator):
        """Should release device successfully."""
        from fastapi import Request

        from app.api.v1.devices import release_device

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        device_id = uuid4()

        with patch("app.api.v1.devices.get_quarantine_service") as mock_service:
            mock_qs = AsyncMock()
            mock_qs.release_device.return_value = mock_release_result
            mock_service.return_value = mock_qs

            response = await release_device(
                device_id=device_id,
                request=request,
                operator=mock_current_user_operator,
            )

        assert response.success is True

    @pytest.mark.asyncio
    async def test_release_device_not_quarantined(self, mock_current_user_operator):
        """Should return 400 if device not quarantined."""
        from fastapi import Request

        from app.api.v1.devices import release_device

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message = "Device is not quarantined"

        with patch("app.api.v1.devices.get_quarantine_service") as mock_service:
            mock_qs = AsyncMock()
            mock_qs.release_device.return_value = mock_result
            mock_service.return_value = mock_qs

            with pytest.raises(HTTPException) as exc_info:
                await release_device(
                    device_id=uuid4(),
                    request=request,
                    operator=mock_current_user_operator,
                )

        assert exc_info.value.status_code == 400


class TestTagManagement:
    """Tests for device tag management endpoints."""

    @pytest.fixture
    def mock_device(self):
        """Create a mock device."""
        device = MagicMock()
        device.id = uuid4()
        device.mac_address = "AA:BB:CC:DD:EE:FF"
        device.ip_addresses = ["192.168.1.100"]
        device.hostname = "test-device"
        device.manufacturer = "Test Corp"
        device.device_type = DeviceType.PC
        device.profile_tags = ["existing-tag"]
        device.first_seen = datetime.now(UTC) - timedelta(days=30)
        device.last_seen = datetime.now(UTC)
        device.status = DeviceStatus.ACTIVE
        device.baseline_ready = True
        return device

    @pytest.mark.asyncio
    async def test_add_device_tag(self, mock_device, mock_db_session, mock_current_user_operator):
        """Should add a tag to device."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import add_device_tag

        await add_device_tag(
            device_id=mock_device.id,
            session=mock_db_session,
            _operator=mock_current_user_operator,
            tag="new-tag",
        )

        assert "new-tag" in mock_device.profile_tags
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_remove_device_tag(
        self, mock_device, mock_db_session, mock_current_user_operator
    ):
        """Should remove a tag from device."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import remove_device_tag

        await remove_device_tag(
            device_id=mock_device.id,
            tag="existing-tag",
            session=mock_db_session,
            _operator=mock_current_user_operator,
        )

        assert "existing-tag" not in mock_device.profile_tags
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_device_tags(self, mock_device, mock_db_session, mock_current_user_operator):
        """Should replace all device tags."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import set_device_tags

        new_tags = ["tag1", "tag2", "tag3"]

        await set_device_tags(
            device_id=mock_device.id,
            tags=new_tags,
            session=mock_db_session,
            _operator=mock_current_user_operator,
        )

        assert mock_device.profile_tags == sorted(new_tags)
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_all_tags(self, mock_db_session, mock_current_user_viewer):
        """Should return all unique tags with counts."""
        # Create mock devices with tags
        devices = []
        for tags in [["tag1", "tag2"], ["tag1", "tag3"], ["tag2"]]:
            device = MagicMock()
            device.profile_tags = tags
            devices.append(device)

        mock_scalars = MagicMock()
        mock_scalars.all.return_value = devices

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import get_all_tags

        response = await get_all_tags(
            session=mock_db_session,
            _current_user=mock_current_user_viewer,
        )

        assert "tag1" in response.tags
        assert "tag2" in response.tags
        assert "tag3" in response.tags
        assert response.counts["tag1"] == 2
        assert response.counts["tag2"] == 2
        assert response.counts["tag3"] == 1


class TestBulkTagOperations:
    """Tests for bulk tag operations endpoint."""

    @pytest.fixture
    def mock_devices(self):
        """Create mock devices."""
        devices = []
        for i in range(3):
            device = MagicMock()
            device.id = uuid4()
            device.mac_address = f"AA:BB:CC:DD:EE:{i:02X}"
            device.ip_addresses = [f"192.168.1.{100 + i}"]
            device.hostname = f"device-{i}"
            device.manufacturer = "Test Corp"
            device.device_type = DeviceType.PC
            device.profile_tags = ["common-tag"]
            device.first_seen = datetime.now(UTC)
            device.last_seen = datetime.now(UTC)
            device.status = DeviceStatus.ACTIVE
            device.baseline_ready = True
            devices.append(device)
        return devices

    @pytest.mark.asyncio
    async def test_bulk_add_tags(self, mock_devices, mock_db_session, mock_current_user_operator):
        """Should add tags to multiple devices."""
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import BulkTagRequest, bulk_tag_devices

        request = BulkTagRequest(
            device_ids=[d.id for d in mock_devices],
            tags_to_add=["new-tag1", "new-tag2"],
        )

        response = await bulk_tag_devices(
            request=request,
            session=mock_db_session,
            _operator=mock_current_user_operator,
        )

        assert response.updated_count == 3
        for device in mock_devices:
            assert "new-tag1" in device.profile_tags
            assert "new-tag2" in device.profile_tags

    @pytest.mark.asyncio
    async def test_bulk_remove_tags(
        self, mock_devices, mock_db_session, mock_current_user_operator
    ):
        """Should remove tags from multiple devices."""
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import BulkTagRequest, bulk_tag_devices

        request = BulkTagRequest(
            device_ids=[d.id for d in mock_devices],
            tags_to_remove=["common-tag"],
        )

        response = await bulk_tag_devices(
            request=request,
            session=mock_db_session,
            _operator=mock_current_user_operator,
        )

        assert response.updated_count == 3
        for device in mock_devices:
            assert "common-tag" not in device.profile_tags

    @pytest.mark.asyncio
    async def test_bulk_tag_no_operations(self, mock_db_session, mock_current_user_operator):
        """Should reject request with no operations."""
        from app.api.v1.devices import BulkTagRequest, bulk_tag_devices

        request = BulkTagRequest(
            device_ids=[uuid4()],
        )

        with pytest.raises(HTTPException) as exc_info:
            await bulk_tag_devices(
                request=request,
                session=mock_db_session,
                _operator=mock_current_user_operator,
            )

        assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_bulk_tag_no_devices_found(self, mock_db_session, mock_current_user_operator):
        """Should return 404 if no devices found."""
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import BulkTagRequest, bulk_tag_devices

        request = BulkTagRequest(
            device_ids=[uuid4()],
            tags_to_add=["tag"],
        )

        with pytest.raises(HTTPException) as exc_info:
            await bulk_tag_devices(
                request=request,
                session=mock_db_session,
                _operator=mock_current_user_operator,
            )

        assert exc_info.value.status_code == 404


class TestExportDevices:
    """Tests for device export endpoints."""

    @pytest.fixture
    def mock_devices(self):
        """Create mock devices for export."""
        devices = []
        for i in range(3):
            device = MagicMock()
            device.hostname = f"device-{i}"
            device.mac_address = f"AA:BB:CC:DD:EE:{i:02X}"
            device.ip_addresses = [f"192.168.1.{100 + i}"]
            device.device_type = DeviceType.PC
            device.status = DeviceStatus.ACTIVE
            device.first_seen = datetime.now(UTC) - timedelta(days=30)
            device.last_seen = datetime.now(UTC)
            devices.append(device)
        return devices

    @pytest.mark.asyncio
    async def test_export_csv(self, mock_devices, mock_db_session, mock_current_user_viewer):
        """Should export devices to CSV."""
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import export_devices_csv

        with patch("app.api.v1.devices.ExportService") as mock_export:
            mock_export.to_csv.return_value = "csv,data\n"

            response = await export_devices_csv(
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
                status_filter=None,
                device_type=None,
                limit=10000,
            )

        assert response.media_type == "text/csv"
        mock_export.to_csv.assert_called_once()

    @pytest.mark.asyncio
    async def test_export_pdf(self, mock_devices, mock_db_session, mock_current_user_viewer):
        """Should export devices to PDF."""
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_devices

        mock_result = MagicMock()
        mock_result.scalars.return_value = mock_scalars
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.devices import export_devices_pdf

        with patch("app.api.v1.devices.ExportService") as mock_export:
            mock_export.to_pdf.return_value = b"pdf content"

            response = await export_devices_pdf(
                session=mock_db_session,
                _current_user=mock_current_user_viewer,
                status_filter=None,
                device_type=None,
                limit=1000,
            )

        assert response.media_type == "application/pdf"
        mock_export.to_pdf.assert_called_once()
