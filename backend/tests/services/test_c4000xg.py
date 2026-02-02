"""Tests for the C4000XG Integration Service.

Tests cover:
- Authentication and session management
- Device blocking via parental control rules
- Device unblocking
- Block status checking
- Connected device discovery
- Error handling
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.integrations.base import ActionType, IntegrationType
from app.services.integrations.c4000xg import C4000XGService, get_c4000xg_service


@pytest.fixture
def mock_settings():
    """Create mock settings for C4000XG configuration."""
    with patch("app.services.integrations.c4000xg.settings") as mock:
        mock.router_integration_type = "c4000xg"
        mock.router_url = "https://192.168.1.1"
        mock.router_username = "admin"
        mock.router_password = "password123"
        mock.router_verify_ssl = False
        yield mock


@pytest.fixture
def c4000xg_service(mock_settings):
    """Create a C4000XGService instance with mocked settings."""
    return C4000XGService()


@pytest.fixture
def mock_httpx_client():
    """Create a mock httpx AsyncClient."""
    client = AsyncMock(spec=httpx.AsyncClient)
    client.cookies = MagicMock()
    client.cookies.set = MagicMock()
    client.cookies.get = MagicMock(return_value="test-session-id")
    return client


class TestC4000XGServiceConfiguration:
    """Tests for C4000XG service configuration."""

    def test_is_configured_with_all_settings(self, mock_settings):
        """Should return True when all settings are provided."""
        service = C4000XGService()
        assert service.is_configured is True

    def test_is_configured_missing_url(self, mock_settings):
        """Should return False when URL is missing."""
        mock_settings.router_url = ""
        service = C4000XGService()
        assert service.is_configured is False

    def test_is_configured_missing_username(self, mock_settings):
        """Should return False when username is missing."""
        mock_settings.router_username = ""
        service = C4000XGService()
        assert service.is_configured is False

    def test_is_configured_missing_password(self, mock_settings):
        """Should return False when password is missing."""
        mock_settings.router_password = ""
        service = C4000XGService()
        assert service.is_configured is False

    def test_is_configured_wrong_integration_type(self, mock_settings):
        """Should return False when integration type is not c4000xg."""
        mock_settings.router_integration_type = "unifi"
        service = C4000XGService()
        assert service.is_configured is False

    def test_is_enabled_equals_is_configured(self, c4000xg_service):
        """is_enabled should equal is_configured."""
        assert c4000xg_service.is_enabled == c4000xg_service.is_configured

    def test_integration_type(self, c4000xg_service):
        """Should have C4000XG integration type."""
        assert c4000xg_service.integration_type == IntegrationType.C4000XG


class TestMACNormalization:
    """Tests for MAC address normalization."""

    def test_normalize_mac_colon_format(self, c4000xg_service):
        """Should normalize already colon-formatted MAC."""
        result = c4000xg_service._normalize_mac("aa:bb:cc:dd:ee:ff")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_dash_format(self, c4000xg_service):
        """Should normalize dash-formatted MAC."""
        result = c4000xg_service._normalize_mac("aa-bb-cc-dd-ee-ff")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_no_separator(self, c4000xg_service):
        """Should normalize MAC without separators."""
        result = c4000xg_service._normalize_mac("aabbccddeeff")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_dot_format(self, c4000xg_service):
        """Should normalize Cisco-style dot format."""
        result = c4000xg_service._normalize_mac("aabb.ccdd.eeff")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_invalid_length(self, c4000xg_service):
        """Should return uppercased original if invalid length."""
        result = c4000xg_service._normalize_mac("invalid")
        assert result == "INVALID"


class TestAuthentication:
    """Tests for C4000XG authentication."""

    @pytest.mark.asyncio
    async def test_login_success_302_redirect(self, c4000xg_service, mock_httpx_client):
        """Should successfully login on 302 redirect with session cookie."""
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_cookies = MagicMock()
        mock_cookies.get = MagicMock(return_value="test-session-123")
        mock_response.cookies = mock_cookies
        mock_httpx_client.post = AsyncMock(return_value=mock_response)

        result = await c4000xg_service._login(mock_httpx_client)

        assert result is True
        assert c4000xg_service._session_id == "test-session-123"

    @pytest.mark.asyncio
    async def test_login_success_200_response(self, c4000xg_service, mock_httpx_client):
        """Should successfully login on 200 response with session cookie."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_cookies = MagicMock()
        mock_cookies.get = MagicMock(return_value="test-session-456")
        mock_response.cookies = mock_cookies
        mock_httpx_client.post = AsyncMock(return_value=mock_response)

        result = await c4000xg_service._login(mock_httpx_client)

        assert result is True
        assert c4000xg_service._session_id == "test-session-456"

    @pytest.mark.asyncio
    async def test_login_failure_no_cookie(self, c4000xg_service, mock_httpx_client):
        """Should fail login when no session cookie returned."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_cookies = MagicMock()
        mock_cookies.get = MagicMock(return_value=None)
        mock_response.cookies = mock_cookies
        mock_response.text = "Login failed"
        mock_httpx_client.post = AsyncMock(return_value=mock_response)

        result = await c4000xg_service._login(mock_httpx_client)

        assert result is False

    @pytest.mark.asyncio
    async def test_login_exception(self, c4000xg_service, mock_httpx_client):
        """Should handle exceptions during login."""
        mock_httpx_client.post = AsyncMock(side_effect=Exception("Network error"))

        result = await c4000xg_service._login(mock_httpx_client)

        assert result is False


class TestTestConnection:
    """Tests for test_connection method."""

    @pytest.mark.asyncio
    async def test_connection_not_configured(self, mock_settings):
        """Should return failure when not configured."""
        mock_settings.router_url = ""
        service = C4000XGService()

        result = await service.test_connection()

        assert result.success is False
        assert result.action == ActionType.TEST
        assert "not configured" in result.message.lower()

    @pytest.mark.asyncio
    async def test_connection_success(self, c4000xg_service):
        """Should return success on successful connection."""
        mock_login_response = MagicMock()
        mock_login_response.status_code = 302
        mock_login_response.cookies = MagicMock()
        mock_login_response.cookies.get = MagicMock(return_value="session-123")

        mock_device_info_response = MagicMock()
        mock_device_info_response.status_code = 200
        mock_device_info_response.json = MagicMock(
            return_value={
                "ModelName": "C4000XG",
                "SoftwareVersion": "1.0.0",
                "HardwareVersion": "1.0",
                "SerialNumber": "ABC123",
            }
        )

        with patch.object(c4000xg_service, "_create_client") as mock_create:
            mock_client = AsyncMock()
            mock_client.cookies = MagicMock()
            mock_client.cookies.set = MagicMock()
            mock_client.post = AsyncMock(return_value=mock_login_response)
            mock_client.get = AsyncMock(return_value=mock_device_info_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_create.return_value = mock_client

            result = await c4000xg_service.test_connection()

        assert result.success is True
        assert result.action == ActionType.TEST
        assert "C4000XG" in result.details.get("model", "")

    @pytest.mark.asyncio
    async def test_connection_login_failure(self, c4000xg_service):
        """Should return failure when login fails."""
        mock_login_response = MagicMock()
        mock_login_response.status_code = 401
        mock_login_response.cookies = MagicMock()
        mock_login_response.cookies.get = MagicMock(return_value=None)
        mock_login_response.text = "Unauthorized"

        with patch.object(c4000xg_service, "_create_client") as mock_create:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_login_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_create.return_value = mock_client

            result = await c4000xg_service.test_connection()

        assert result.success is False
        assert "authenticate" in result.message.lower() or "login" in result.error.lower()

    @pytest.mark.asyncio
    async def test_connection_connect_error(self, c4000xg_service):
        """Should handle connection errors."""
        with patch.object(c4000xg_service, "_create_client") as mock_create:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_create.return_value = mock_client

            result = await c4000xg_service.test_connection()

        assert result.success is False
        assert "connect" in result.message.lower()


class TestBlockDevice:
    """Tests for block_device method."""

    @pytest.mark.asyncio
    async def test_block_device_not_enabled(self, mock_settings):
        """Should return failure when not enabled."""
        mock_settings.router_url = ""
        service = C4000XGService()

        result = await service.block_device("AA:BB:CC:DD:EE:FF")

        assert result.success is False
        assert result.action == ActionType.BLOCK
        assert "not enabled" in result.message.lower()

    @pytest.mark.asyncio
    async def test_block_device_success(self, c4000xg_service):
        """Should successfully block a device."""
        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(c4000xg_service, "_find_rule_for_mac", return_value=None):
                with patch.object(
                    c4000xg_service, "_ensure_parental_control_enabled", return_value=True
                ):
                    with patch.object(
                        c4000xg_service,
                        "_post_request",
                        return_value={"success": True},
                    ):
                        with patch.object(c4000xg_service, "_create_client") as mock_create:
                            mock_client = AsyncMock()
                            mock_client.cookies = MagicMock()
                            mock_client.cookies.set = MagicMock()
                            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                            mock_client.__aexit__ = AsyncMock(return_value=None)
                            mock_create.return_value = mock_client

                            c4000xg_service._session_id = "test-session"

                            result = await c4000xg_service.block_device(
                                mac_address="AA:BB:CC:DD:EE:FF",
                                reason="Suspicious activity",
                                device_name="Test Device",
                            )

        assert result.success is True
        assert result.action == ActionType.BLOCK
        assert result.target == "AA:BB:CC:DD:EE:FF"
        assert "parental_control" in result.details.get("method", "")

    @pytest.mark.asyncio
    async def test_block_device_already_blocked(self, c4000xg_service):
        """Should return success if device already blocked."""
        existing_rule = {"_index": 1, "MACAddress": "AA:BB:CC:DD:EE:FF", "Target": "Drop"}

        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(
                c4000xg_service, "_find_rule_for_mac", return_value=existing_rule
            ):
                with patch.object(c4000xg_service, "_create_client") as mock_create:
                    mock_client = AsyncMock()
                    mock_client.cookies = MagicMock()
                    mock_client.cookies.set = MagicMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=None)
                    mock_create.return_value = mock_client

                    c4000xg_service._session_id = "test-session"

                    result = await c4000xg_service.block_device("AA:BB:CC:DD:EE:FF")

        assert result.success is True
        assert result.details.get("already_blocked") is True

    @pytest.mark.asyncio
    async def test_block_device_login_failure(self, c4000xg_service):
        """Should return failure when login fails."""
        with patch.object(c4000xg_service, "_ensure_session", return_value=False):
            with patch.object(c4000xg_service, "_create_client") as mock_create:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_create.return_value = mock_client

                result = await c4000xg_service.block_device("AA:BB:CC:DD:EE:FF")

        assert result.success is False
        assert "authenticate" in result.message.lower()

    @pytest.mark.asyncio
    async def test_block_device_parental_control_enable_failure(self, c4000xg_service):
        """Should return failure when parental control cannot be enabled."""
        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(c4000xg_service, "_find_rule_for_mac", return_value=None):
                with patch.object(
                    c4000xg_service, "_ensure_parental_control_enabled", return_value=False
                ):
                    with patch.object(c4000xg_service, "_create_client") as mock_create:
                        mock_client = AsyncMock()
                        mock_client.cookies = MagicMock()
                        mock_client.cookies.set = MagicMock()
                        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                        mock_client.__aexit__ = AsyncMock(return_value=None)
                        mock_create.return_value = mock_client

                        c4000xg_service._session_id = "test-session"

                        result = await c4000xg_service.block_device("AA:BB:CC:DD:EE:FF")

        assert result.success is False
        assert "parental control" in result.message.lower()


class TestUnblockDevice:
    """Tests for unblock_device method."""

    @pytest.mark.asyncio
    async def test_unblock_device_not_enabled(self, mock_settings):
        """Should return failure when not enabled."""
        mock_settings.router_url = ""
        service = C4000XGService()

        result = await service.unblock_device("AA:BB:CC:DD:EE:FF")

        assert result.success is False
        assert result.action == ActionType.UNBLOCK

    @pytest.mark.asyncio
    async def test_unblock_device_success(self, c4000xg_service):
        """Should successfully unblock a device."""
        existing_rule = {"_index": 1, "MACAddress": "AA:BB:CC:DD:EE:FF", "Target": "Drop"}

        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(
                c4000xg_service, "_find_rule_for_mac", return_value=existing_rule
            ):
                with patch.object(
                    c4000xg_service, "_post_request", return_value={"success": True}
                ):
                    with patch.object(c4000xg_service, "_create_client") as mock_create:
                        mock_client = AsyncMock()
                        mock_client.cookies = MagicMock()
                        mock_client.cookies.set = MagicMock()
                        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                        mock_client.__aexit__ = AsyncMock(return_value=None)
                        mock_create.return_value = mock_client

                        c4000xg_service._session_id = "test-session"

                        result = await c4000xg_service.unblock_device(
                            mac_address="AA:BB:CC:DD:EE:FF",
                            reason="Investigation complete",
                        )

        assert result.success is True
        assert result.action == ActionType.UNBLOCK
        assert result.details.get("rule_index") == 1

    @pytest.mark.asyncio
    async def test_unblock_device_not_blocked(self, c4000xg_service):
        """Should return success if device is not blocked."""
        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(c4000xg_service, "_find_rule_for_mac", return_value=None):
                with patch.object(c4000xg_service, "_create_client") as mock_create:
                    mock_client = AsyncMock()
                    mock_client.cookies = MagicMock()
                    mock_client.cookies.set = MagicMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=None)
                    mock_create.return_value = mock_client

                    c4000xg_service._session_id = "test-session"

                    result = await c4000xg_service.unblock_device("AA:BB:CC:DD:EE:FF")

        assert result.success is True
        assert result.details.get("already_unblocked") is True

    @pytest.mark.asyncio
    async def test_unblock_device_delete_failure(self, c4000xg_service):
        """Should return failure when rule deletion fails."""
        existing_rule = {"_index": 1, "MACAddress": "AA:BB:CC:DD:EE:FF", "Target": "Drop"}

        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(
                c4000xg_service, "_find_rule_for_mac", return_value=existing_rule
            ):
                with patch.object(c4000xg_service, "_post_request", return_value=None):
                    with patch.object(c4000xg_service, "_create_client") as mock_create:
                        mock_client = AsyncMock()
                        mock_client.cookies = MagicMock()
                        mock_client.cookies.set = MagicMock()
                        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                        mock_client.__aexit__ = AsyncMock(return_value=None)
                        mock_create.return_value = mock_client

                        c4000xg_service._session_id = "test-session"

                        result = await c4000xg_service.unblock_device("AA:BB:CC:DD:EE:FF")

        assert result.success is False
        assert "delete" in result.error.lower() or "rule" in result.error.lower()


class TestIsDeviceBlocked:
    """Tests for is_device_blocked method."""

    @pytest.mark.asyncio
    async def test_is_device_blocked_not_enabled(self, mock_settings):
        """Should return False when not enabled."""
        mock_settings.router_url = ""
        service = C4000XGService()

        result = await service.is_device_blocked("AA:BB:CC:DD:EE:FF")

        assert result is False

    @pytest.mark.asyncio
    async def test_is_device_blocked_true(self, c4000xg_service):
        """Should return True when device has blocking rule."""
        existing_rule = {"_index": 1, "MACAddress": "AA:BB:CC:DD:EE:FF", "Target": "Drop"}

        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(
                c4000xg_service, "_find_rule_for_mac", return_value=existing_rule
            ):
                with patch.object(c4000xg_service, "_create_client") as mock_create:
                    mock_client = AsyncMock()
                    mock_client.cookies = MagicMock()
                    mock_client.cookies.set = MagicMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=None)
                    mock_create.return_value = mock_client

                    c4000xg_service._session_id = "test-session"

                    result = await c4000xg_service.is_device_blocked("AA:BB:CC:DD:EE:FF")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_device_blocked_false(self, c4000xg_service):
        """Should return False when device has no blocking rule."""
        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(c4000xg_service, "_find_rule_for_mac", return_value=None):
                with patch.object(c4000xg_service, "_create_client") as mock_create:
                    mock_client = AsyncMock()
                    mock_client.cookies = MagicMock()
                    mock_client.cookies.set = MagicMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=None)
                    mock_create.return_value = mock_client

                    c4000xg_service._session_id = "test-session"

                    result = await c4000xg_service.is_device_blocked("AA:BB:CC:DD:EE:FF")

        assert result is False

    @pytest.mark.asyncio
    async def test_is_device_blocked_session_failure(self, c4000xg_service):
        """Should return False on session failure."""
        with patch.object(c4000xg_service, "_ensure_session", return_value=False):
            with patch.object(c4000xg_service, "_create_client") as mock_create:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=None)
                mock_create.return_value = mock_client

                result = await c4000xg_service.is_device_blocked("AA:BB:CC:DD:EE:FF")

        assert result is False


class TestGetBlockedDevices:
    """Tests for get_blocked_devices method."""

    @pytest.mark.asyncio
    async def test_get_blocked_devices_not_enabled(self, mock_settings):
        """Should return empty list when not enabled."""
        mock_settings.router_url = ""
        service = C4000XGService()

        result = await service.get_blocked_devices()

        assert result == []

    @pytest.mark.asyncio
    async def test_get_blocked_devices_success(self, c4000xg_service):
        """Should return list of blocked devices."""
        rules = [
            {
                "_index": 1,
                "MACAddress": "AA:BB:CC:DD:EE:FF",
                "Target": "Drop",
                "Enable": "1",
                "TimeStart": "00:00",
                "TimeEnd": "23:59",
                "DaysOfTheWeek": "Sun,Mon,Tue,Wed,Thu,Fri,Sat",
            },
            {
                "_index": 2,
                "MACAddress": "11:22:33:44:55:66",
                "Target": "Drop",
                "Enable": "1",
                "TimeStart": "08:00",
                "TimeEnd": "18:00",
                "DaysOfTheWeek": "Mon,Tue,Wed,Thu,Fri",
            },
        ]

        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(
                c4000xg_service, "_get_parental_control_rules", return_value=rules
            ):
                with patch.object(c4000xg_service, "_create_client") as mock_create:
                    mock_client = AsyncMock()
                    mock_client.cookies = MagicMock()
                    mock_client.cookies.set = MagicMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=None)
                    mock_create.return_value = mock_client

                    c4000xg_service._session_id = "test-session"

                    result = await c4000xg_service.get_blocked_devices()

        assert len(result) == 2
        assert result[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
        assert result[1]["mac_address"] == "11:22:33:44:55:66"

    @pytest.mark.asyncio
    async def test_get_blocked_devices_filters_non_drop(self, c4000xg_service):
        """Should filter out non-Drop rules."""
        rules = [
            {"_index": 1, "MACAddress": "AA:BB:CC:DD:EE:FF", "Target": "Drop", "Enable": "1"},
            {"_index": 2, "MACAddress": "11:22:33:44:55:66", "Target": "Allow", "Enable": "1"},
        ]

        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(
                c4000xg_service, "_get_parental_control_rules", return_value=rules
            ):
                with patch.object(c4000xg_service, "_create_client") as mock_create:
                    mock_client = AsyncMock()
                    mock_client.cookies = MagicMock()
                    mock_client.cookies.set = MagicMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=None)
                    mock_create.return_value = mock_client

                    c4000xg_service._session_id = "test-session"

                    result = await c4000xg_service.get_blocked_devices()

        assert len(result) == 1
        assert result[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"


class TestGetConnectedDevices:
    """Tests for get_connected_devices method."""

    @pytest.mark.asyncio
    async def test_get_connected_devices_not_enabled(self, mock_settings):
        """Should return empty list when not enabled."""
        mock_settings.router_url = ""
        service = C4000XGService()

        result = await service.get_connected_devices()

        assert result == []

    @pytest.mark.asyncio
    async def test_get_connected_devices_success(self, c4000xg_service):
        """Should return list of connected devices."""
        host_data = {
            "HostNumberOfEntries": 2,
        }
        host_1 = {
            "PhysAddress": "aa:bb:cc:dd:ee:ff",
            "IPAddress": "192.168.1.100",
            "HostName": "Device1",
            "Active": "1",
            "Layer1Interface": "LAN",
            "AddressSource": "DHCP",
        }
        host_2 = {
            "PhysAddress": "11:22:33:44:55:66",
            "IPAddress": "192.168.1.101",
            "HostName": "Device2",
            "Active": "0",
            "Layer1Interface": "WiFi",
            "AddressSource": "Static",
        }

        async def mock_get_request(client, obj):
            if obj == "Device.Hosts.Host.":
                return host_data
            elif obj == "Device.Hosts.Host.1.":
                return host_1
            elif obj == "Device.Hosts.Host.2.":
                return host_2
            return None

        with patch.object(c4000xg_service, "_ensure_session", return_value=True):
            with patch.object(c4000xg_service, "_get_request", side_effect=mock_get_request):
                with patch.object(c4000xg_service, "_create_client") as mock_create:
                    mock_client = AsyncMock()
                    mock_client.cookies = MagicMock()
                    mock_client.cookies.set = MagicMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock(return_value=None)
                    mock_create.return_value = mock_client

                    c4000xg_service._session_id = "test-session"

                    result = await c4000xg_service.get_connected_devices()

        assert len(result) == 2
        assert result[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
        assert result[0]["hostname"] == "Device1"
        assert result[0]["active"] is True
        assert result[1]["active"] is False


class TestParseHostEntry:
    """Tests for _parse_host_entry helper method."""

    def test_parse_host_entry_full(self, c4000xg_service):
        """Should parse complete host entry."""
        host = {
            "PhysAddress": "aa:bb:cc:dd:ee:ff",
            "IPAddress": "192.168.1.100",
            "HostName": "MyDevice",
            "Active": "1",
            "Layer1Interface": "LAN1",
            "AddressSource": "DHCP",
        }

        result = c4000xg_service._parse_host_entry(host)

        assert result["mac_address"] == "AA:BB:CC:DD:EE:FF"
        assert result["ip_address"] == "192.168.1.100"
        assert result["hostname"] == "MyDevice"
        assert result["active"] is True
        assert result["interface"] == "LAN1"
        assert result["address_source"] == "DHCP"

    def test_parse_host_entry_inactive(self, c4000xg_service):
        """Should parse inactive host entry."""
        host = {
            "PhysAddress": "aa:bb:cc:dd:ee:ff",
            "Active": "0",
        }

        result = c4000xg_service._parse_host_entry(host)

        assert result["active"] is False

    def test_parse_host_entry_boolean_active(self, c4000xg_service):
        """Should handle boolean Active field."""
        host = {
            "PhysAddress": "aa:bb:cc:dd:ee:ff",
            "Active": True,
        }

        result = c4000xg_service._parse_host_entry(host)

        assert result["active"] is True

    def test_parse_host_entry_missing_fields(self, c4000xg_service):
        """Should handle missing fields."""
        host = {"PhysAddress": "aa:bb:cc:dd:ee:ff"}

        result = c4000xg_service._parse_host_entry(host)

        assert result["mac_address"] == "AA:BB:CC:DD:EE:FF"
        assert result["ip_address"] is None
        assert result["hostname"] is None
        assert result["active"] is False


class TestGlobalServiceInstance:
    """Tests for global service instance."""

    def test_get_c4000xg_service(self, mock_settings):
        """Should return global service instance."""
        # Reset singleton
        import app.services.integrations.c4000xg as module

        module._c4000xg_service = None

        service = get_c4000xg_service()

        assert isinstance(service, C4000XGService)

    def test_get_c4000xg_service_singleton(self, mock_settings):
        """Should return same instance."""
        # Reset singleton
        import app.services.integrations.c4000xg as module

        module._c4000xg_service = None

        service1 = get_c4000xg_service()
        service2 = get_c4000xg_service()

        assert service1 is service2
