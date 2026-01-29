"""Tests for Phase 4 integration services."""

from unittest.mock import patch

import pytest

from app.services.integrations.adguard import AdGuardHomeService
from app.services.integrations.base import ActionType, IntegrationResult, IntegrationType
from app.services.integrations.pfsense import PfSenseService
from app.services.integrations.unifi import UniFiService


class TestAdGuardHomeService:
    """Tests for AdGuard Home integration."""

    def test_is_configured_false_when_missing_config(self):
        """Test is_configured returns False when config is missing."""
        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = False
            mock_settings.adguard_url = ""
            mock_settings.adguard_username = ""
            mock_settings.adguard_password = ""

            service = AdGuardHomeService()
            assert not service.is_configured

    def test_is_configured_true_when_config_present(self):
        """Test is_configured returns True when config is present."""
        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = True
            mock_settings.adguard_url = "http://localhost:3000"
            mock_settings.adguard_username = "admin"
            mock_settings.adguard_password = "password"

            service = AdGuardHomeService()
            assert service.is_configured

    def test_is_enabled_requires_all_config(self):
        """Test is_enabled requires enabled flag and config."""
        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = True
            mock_settings.adguard_url = "http://localhost:3000"
            mock_settings.adguard_username = "admin"
            mock_settings.adguard_password = "password"

            service = AdGuardHomeService()
            assert service.is_enabled

    def test_integration_type(self):
        """Test integration type is correct."""
        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = False
            mock_settings.adguard_url = ""
            mock_settings.adguard_username = ""
            mock_settings.adguard_password = ""

            service = AdGuardHomeService()
            assert service.integration_type == IntegrationType.ADGUARD_HOME

    @pytest.mark.asyncio
    async def test_test_connection_not_configured(self):
        """Test connection test fails when not configured."""
        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = False
            mock_settings.adguard_url = ""
            mock_settings.adguard_username = ""
            mock_settings.adguard_password = ""

            service = AdGuardHomeService()
            result = await service.test_connection()

            assert not result.success
            assert result.action == ActionType.TEST
            assert "not configured" in result.message.lower()

    @pytest.mark.asyncio
    async def test_block_device_not_enabled(self):
        """Test block device fails when not enabled."""
        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = False
            mock_settings.adguard_url = ""
            mock_settings.adguard_username = ""
            mock_settings.adguard_password = ""

            service = AdGuardHomeService()
            result = await service.block_device(
                mac_address="AA:BB:CC:DD:EE:FF",
                ip_address="192.168.1.100",
            )

            assert not result.success
            assert result.action == ActionType.BLOCK_DEVICE
            assert "not enabled" in result.message.lower()

    @pytest.mark.asyncio
    async def test_get_all_clients_not_enabled(self):
        """Test get_all_clients returns empty list when not enabled."""
        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = False
            mock_settings.adguard_url = ""
            mock_settings.adguard_username = ""
            mock_settings.adguard_password = ""

            service = AdGuardHomeService()
            result = await service.get_all_clients()

            assert result == []

    @pytest.mark.asyncio
    async def test_get_device_name_mapping_not_enabled(self):
        """Test get_device_name_mapping returns empty dict when not enabled."""
        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = False
            mock_settings.adguard_url = ""
            mock_settings.adguard_username = ""
            mock_settings.adguard_password = ""

            service = AdGuardHomeService()
            result = await service.get_device_name_mapping()

            assert result == {}

    @pytest.mark.asyncio
    async def test_get_all_clients_processes_configured_and_auto(self):
        """Test get_all_clients processes both configured and auto clients."""
        from unittest.mock import AsyncMock

        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = True
            mock_settings.adguard_url = "http://localhost:3000"
            mock_settings.adguard_username = "admin"
            mock_settings.adguard_password = "password"
            mock_settings.adguard_verify_ssl = True

            service = AdGuardHomeService()

            # Mock _get_clients to return test data
            mock_clients_data = {
                "clients": [
                    {
                        "name": "Configured Device",
                        "ids": ["192.168.1.100", "aa:bb:cc:dd:ee:01"],
                        "tags": ["family"],
                    }
                ],
                "auto_clients": [
                    {
                        "name": "Auto Device",
                        "ip": "192.168.1.101",
                        "whois_info": {},
                    }
                ],
            }

            service._get_clients = AsyncMock(return_value=mock_clients_data)

            result = await service.get_all_clients()

            assert len(result) == 2

            # Check configured client
            configured = next(c for c in result if c["source"] == "configured")
            assert configured["name"] == "Configured Device"
            assert "192.168.1.100" in configured["ids"]

            # Check auto client
            auto = next(c for c in result if c["source"] == "auto")
            assert auto["name"] == "Auto Device"
            assert "192.168.1.101" in auto["ids"]

    @pytest.mark.asyncio
    async def test_get_device_name_mapping_normalizes_mac(self):
        """Test get_device_name_mapping normalizes MAC addresses."""
        from unittest.mock import AsyncMock

        with patch("app.services.integrations.adguard.settings") as mock_settings:
            mock_settings.adguard_enabled = True
            mock_settings.adguard_url = "http://localhost:3000"
            mock_settings.adguard_username = "admin"
            mock_settings.adguard_password = "password"
            mock_settings.adguard_verify_ssl = True

            service = AdGuardHomeService()

            # Mock get_all_clients
            mock_clients = [
                {
                    "name": "Device 1",
                    "ids": ["AA-BB-CC-DD-EE-01", "192.168.1.100"],
                    "source": "configured",
                },
                {
                    "name": "Device 2",
                    "ids": ["AA:BB:CC:DD:EE:02"],
                    "source": "configured",
                },
            ]

            service.get_all_clients = AsyncMock(return_value=mock_clients)

            result = await service.get_device_name_mapping()

            # MAC should be normalized (lowercase with colons)
            assert result.get("aa:bb:cc:dd:ee:01") == "Device 1"
            assert result.get("aa:bb:cc:dd:ee:02") == "Device 2"
            # IP should be preserved
            assert result.get("192.168.1.100") == "Device 1"


class TestUniFiService:
    """Tests for UniFi Controller integration."""

    def test_is_configured_false_when_missing_config(self):
        """Test is_configured returns False when config is missing."""
        with patch("app.services.integrations.unifi.settings") as mock_settings:
            mock_settings.router_integration_type = ""
            mock_settings.router_url = ""
            mock_settings.router_username = ""
            mock_settings.router_password = ""

            service = UniFiService()
            assert not service.is_configured

    def test_is_configured_true_for_unifi_type(self):
        """Test is_configured returns True for UniFi type."""
        with patch("app.services.integrations.unifi.settings") as mock_settings:
            mock_settings.router_integration_type = "unifi"
            mock_settings.router_url = "https://localhost:8443"
            mock_settings.router_username = "admin"
            mock_settings.router_password = "password"

            service = UniFiService()
            assert service.is_configured

    def test_integration_type(self):
        """Test integration type is correct."""
        with patch("app.services.integrations.unifi.settings") as mock_settings:
            mock_settings.router_integration_type = ""
            mock_settings.router_url = ""
            mock_settings.router_username = ""
            mock_settings.router_password = ""

            service = UniFiService()
            assert service.integration_type == IntegrationType.UNIFI

    @pytest.mark.asyncio
    async def test_test_connection_not_configured(self):
        """Test connection test fails when not configured."""
        with patch("app.services.integrations.unifi.settings") as mock_settings:
            mock_settings.router_integration_type = ""
            mock_settings.router_url = ""
            mock_settings.router_username = ""
            mock_settings.router_password = ""

            service = UniFiService()
            result = await service.test_connection()

            assert not result.success
            assert result.action == ActionType.TEST


class TestPfSenseService:
    """Tests for pfSense/OPNsense integration."""

    def test_is_configured_false_when_missing_config(self):
        """Test is_configured returns False when config is missing."""
        with patch("app.services.integrations.pfsense.settings") as mock_settings:
            mock_settings.router_integration_type = ""
            mock_settings.router_url = ""
            mock_settings.router_username = ""
            mock_settings.router_password = ""

            service = PfSenseService()
            assert not service.is_configured

    def test_is_configured_true_for_pfsense_type(self):
        """Test is_configured returns True for pfSense type."""
        with patch("app.services.integrations.pfsense.settings") as mock_settings:
            mock_settings.router_integration_type = "pfsense"
            mock_settings.router_url = "https://localhost"
            mock_settings.router_username = "admin"
            mock_settings.router_password = "password"

            service = PfSenseService()
            assert service.is_configured

    def test_is_configured_true_for_opnsense_type(self):
        """Test is_configured returns True for OPNsense type."""
        with patch("app.services.integrations.pfsense.settings") as mock_settings:
            mock_settings.router_integration_type = "opnsense"
            mock_settings.router_url = "https://localhost"
            mock_settings.router_username = "admin"
            mock_settings.router_password = "password"

            service = PfSenseService()
            assert service.is_configured

    def test_integration_type(self):
        """Test integration type is correct."""
        with patch("app.services.integrations.pfsense.settings") as mock_settings:
            mock_settings.router_integration_type = ""
            mock_settings.router_url = ""
            mock_settings.router_username = ""
            mock_settings.router_password = ""

            service = PfSenseService()
            assert service.integration_type == IntegrationType.PFSENSE


class TestIntegrationResult:
    """Tests for IntegrationResult dataclass."""

    def test_to_dict_returns_correct_structure(self):
        """Test to_dict returns correct dictionary structure."""
        result = IntegrationResult(
            success=True,
            action=ActionType.BLOCK_DEVICE,
            integration_type=IntegrationType.ADGUARD_HOME,
            target="AA:BB:CC:DD:EE:FF",
            message="Device blocked successfully",
            details={"ip": "192.168.1.100"},
            error=None,
        )

        result_dict = result.to_dict()

        assert result_dict["success"] is True
        assert result_dict["action"] == "block_device"
        assert result_dict["integration_type"] == "adguard_home"
        assert result_dict["target"] == "AA:BB:CC:DD:EE:FF"
        assert result_dict["message"] == "Device blocked successfully"
        assert result_dict["details"]["ip"] == "192.168.1.100"
        assert result_dict["error"] is None

    def test_to_dict_with_error(self):
        """Test to_dict includes error when present."""
        result = IntegrationResult(
            success=False,
            action=ActionType.BLOCK_DEVICE,
            integration_type=IntegrationType.ADGUARD_HOME,
            target="AA:BB:CC:DD:EE:FF",
            message="Failed to block device",
            error="Connection refused",
        )

        result_dict = result.to_dict()

        assert result_dict["success"] is False
        assert result_dict["error"] == "Connection refused"
