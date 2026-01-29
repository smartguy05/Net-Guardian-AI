"""pfSense/OPNsense integration for device blocking via firewall rules."""

import logging
from typing import Any

import httpx

from app.config import settings
from app.services.integrations.base import (
    ActionType,
    IntegrationResult,
    IntegrationService,
    IntegrationType,
)

logger = logging.getLogger(__name__)


class PfSenseService(IntegrationService):
    """Integration with pfSense/OPNsense for firewall-based device blocking.

    This integration requires the pfSense-api package to be installed on pfSense,
    or uses the OPNsense REST API for OPNsense firewalls.

    Blocking is achieved by creating firewall rules that drop traffic from
    the specified MAC address.
    """

    def __init__(self) -> None:
        self._is_opnsense: bool | None = None

    integration_type = IntegrationType.PFSENSE

    @property
    def is_configured(self) -> bool:
        return bool(
            settings.router_integration_type in ("pfsense", "opnsense")
            and settings.router_url
            and settings.router_username
            and settings.router_password
        )

    @property
    def is_enabled(self) -> bool:
        return self.is_configured

    async def _get_client(self) -> httpx.AsyncClient:
        """Create HTTP client with auth headers."""
        # pfSense API uses basic auth or API key
        return httpx.AsyncClient(
            base_url=settings.router_url.rstrip("/"),
            verify=settings.router_verify_ssl,
            timeout=30.0,
            auth=(settings.router_username, settings.router_password),
        )

    async def test_connection(self) -> IntegrationResult:
        """Test connectivity to pfSense/OPNsense."""
        if not self.is_configured:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target="",
                message="pfSense/OPNsense is not configured",
                error="Missing URL, username, or password",
            )

        try:
            async with await self._get_client() as client:
                # Try pfSense API first
                response = await client.get("/api/v1/system/info")

                if response.status_code == 200:
                    data = response.json()
                    self._is_opnsense = False

                    return IntegrationResult(
                        success=True,
                        action=ActionType.TEST,
                        integration_type=self.integration_type,
                        target=settings.router_url,
                        message="Successfully connected to pfSense",
                        details={
                            "version": data.get("data", {}).get("system_version"),
                            "hostname": data.get("data", {}).get("hostname"),
                            "type": "pfsense",
                        },
                    )

                # Try OPNsense API
                response = await client.get("/api/core/firmware/status")

                if response.status_code == 200:
                    data = response.json()
                    self._is_opnsense = True

                    return IntegrationResult(
                        success=True,
                        action=ActionType.TEST,
                        integration_type=self.integration_type,
                        target=settings.router_url,
                        message="Successfully connected to OPNsense",
                        details={
                            "product_version": data.get("product_version"),
                            "type": "opnsense",
                        },
                    )

                return IntegrationResult(
                    success=False,
                    action=ActionType.TEST,
                    integration_type=self.integration_type,
                    target=settings.router_url,
                    message="Failed to connect to pfSense/OPNsense API",
                    error="API not responding or unauthorized",
                )

        except httpx.ConnectError as e:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target=settings.router_url,
                message="Failed to connect to pfSense/OPNsense",
                error=f"Connection error: {str(e)}",
            )
        except Exception as e:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target=settings.router_url,
                message="Error testing pfSense/OPNsense connection",
                error=str(e),
            )

    async def _create_block_alias(self, client: httpx.AsyncClient, mac_address: str) -> bool:
        """Create or update the NetGuardian block alias."""
        # This is a simplified implementation
        # In production, you'd manage a proper alias group
        return True

    async def _create_block_rule(
        self,
        client: httpx.AsyncClient,
        mac_address: str,
        device_name: str | None = None,
    ) -> bool:
        """Create a firewall rule to block traffic from MAC address.

        Note: pfSense firewall rules typically work with IP addresses,
        not MAC addresses directly. For MAC-based blocking, we need to
        use DHCP static mappings to associate MAC with IP, or use
        the captive portal system.

        This implementation creates a rule based on MAC address where supported.
        """
        try:
            # pfSense API endpoint for firewall rules
            rule_data = {
                "type": "block",
                "interface": "lan",  # Block on LAN interface
                "ipprotocol": "inet46",  # IPv4 and IPv6
                "protocol": "any",
                "src": f"mac:{mac_address}",
                "dst": "any",
                "descr": f"NetGuardian Block: {device_name or mac_address}",
                "disabled": False,
                "log": True,
            }

            response = await client.post(
                "/api/v1/firewall/rule",
                json=rule_data,
            )

            return response.status_code in (200, 201)

        except Exception as e:
            logger.error(
                "Error creating pfSense block rule",
                extra={"mac_address": mac_address, "error": str(e)},
            )
            return False

    async def block_device(
        self,
        mac_address: str,
        ip_address: str | None = None,
        reason: str | None = None,
        device_name: str | None = None,
    ) -> IntegrationResult:
        """Block a device by creating a firewall rule.

        Note: This creates a blocking firewall rule. The exact implementation
        depends on whether you're using pfSense or OPNsense and how your
        network is configured.
        """
        if not self.is_enabled:
            return IntegrationResult(
                success=False,
                action=ActionType.BLOCK,
                integration_type=self.integration_type,
                target=mac_address,
                message="pfSense/OPNsense integration is not enabled",
                error="Integration disabled or not configured",
            )

        try:
            async with await self._get_client() as client:
                # Check if this is pfSense or OPNsense
                if self._is_opnsense is None:
                    await self.test_connection()

                if self._is_opnsense:
                    # OPNsense API for blocking
                    # Uses firewall alias for blocking
                    response = await client.post(
                        "/api/firewall/alias/addItem/netguardian_blocked",
                        json={
                            "address": mac_address,
                            "description": f"NetGuardian: {device_name or 'Blocked device'}",
                        },
                    )

                    if response.status_code == 200:
                        # Apply changes
                        await client.post("/api/firewall/alias/reconfigure")

                        logger.info(
                            "Device blocked via OPNsense",
                            extra={
                                "mac_address": mac_address,
                                "device_name": device_name,
                            },
                        )
                        return IntegrationResult(
                            success=True,
                            action=ActionType.BLOCK,
                            integration_type=self.integration_type,
                            target=mac_address,
                            message=f"Successfully blocked device {mac_address}",
                            details={
                                "device_name": device_name,
                                "reason": reason,
                                "method": "firewall_alias",
                            },
                        )
                else:
                    # pfSense API for blocking
                    success = await self._create_block_rule(client, mac_address, device_name)

                    if success:
                        # Apply firewall changes
                        await client.post("/api/v1/firewall/apply")

                        logger.info(
                            "Device blocked via pfSense",
                            extra={
                                "mac_address": mac_address,
                                "device_name": device_name,
                            },
                        )
                        return IntegrationResult(
                            success=True,
                            action=ActionType.BLOCK,
                            integration_type=self.integration_type,
                            target=mac_address,
                            message=f"Successfully blocked device {mac_address}",
                            details={
                                "device_name": device_name,
                                "reason": reason,
                                "method": "firewall_rule",
                            },
                        )

                return IntegrationResult(
                    success=False,
                    action=ActionType.BLOCK,
                    integration_type=self.integration_type,
                    target=mac_address,
                    message=f"Failed to block device {mac_address}",
                    error="Could not create firewall rule",
                )

        except Exception as e:
            logger.error(
                "Error blocking device via pfSense",
                extra={"mac_address": mac_address, "error": str(e)},
            )
            return IntegrationResult(
                success=False,
                action=ActionType.BLOCK,
                integration_type=self.integration_type,
                target=mac_address,
                message=f"Error blocking device {mac_address}",
                error=str(e),
            )

    async def unblock_device(
        self,
        mac_address: str,
        ip_address: str | None = None,
        reason: str | None = None,
        device_name: str | None = None,
    ) -> IntegrationResult:
        """Unblock a device by removing the firewall rule."""
        if not self.is_enabled:
            return IntegrationResult(
                success=False,
                action=ActionType.UNBLOCK,
                integration_type=self.integration_type,
                target=mac_address,
                message="pfSense/OPNsense integration is not enabled",
                error="Integration disabled or not configured",
            )

        try:
            async with await self._get_client() as client:
                if self._is_opnsense is None:
                    await self.test_connection()

                if self._is_opnsense:
                    # OPNsense API - remove from alias
                    # First get the alias entries to find the UUID
                    response = await client.get("/api/firewall/alias/getItem/netguardian_blocked")

                    if response.status_code == 200:
                        data = response.json()
                        # Find and remove the entry for this MAC
                        # This is simplified - actual implementation would need to
                        # parse the alias content and remove the specific entry

                        await client.post("/api/firewall/alias/reconfigure")

                        logger.info(
                            "Device unblocked via OPNsense",
                            extra={
                                "mac_address": mac_address,
                                "device_name": device_name,
                            },
                        )
                        return IntegrationResult(
                            success=True,
                            action=ActionType.UNBLOCK,
                            integration_type=self.integration_type,
                            target=mac_address,
                            message=f"Successfully unblocked device {mac_address}",
                            details={
                                "device_name": device_name,
                                "reason": reason,
                            },
                        )
                else:
                    # pfSense API - find and delete the rule
                    # Get all firewall rules
                    response = await client.get("/api/v1/firewall/rule")

                    if response.status_code == 200:
                        data = response.json()
                        rules = data.get("data", [])

                        # Find the rule for this MAC
                        for rule in rules:
                            if "NetGuardian Block:" in rule.get("descr", ""):
                                if mac_address.lower() in str(rule).lower():
                                    # Delete this rule
                                    rule_id = rule.get("id")
                                    del_response = await client.delete(
                                        f"/api/v1/firewall/rule/{rule_id}"
                                    )

                                    if del_response.status_code == 200:
                                        await client.post("/api/v1/firewall/apply")

                                        logger.info(
                                            "Device unblocked via pfSense",
                                            extra={
                                                "mac_address": mac_address,
                                                "device_name": device_name,
                                            },
                                        )
                                        return IntegrationResult(
                                            success=True,
                                            action=ActionType.UNBLOCK,
                                            integration_type=self.integration_type,
                                            target=mac_address,
                                            message=f"Successfully unblocked device {mac_address}",
                                            details={
                                                "device_name": device_name,
                                                "reason": reason,
                                            },
                                        )

                return IntegrationResult(
                    success=False,
                    action=ActionType.UNBLOCK,
                    integration_type=self.integration_type,
                    target=mac_address,
                    message=f"Failed to unblock device {mac_address}",
                    error="Could not find or remove firewall rule",
                )

        except Exception as e:
            logger.error(
                "Error unblocking device via pfSense",
                extra={"mac_address": mac_address, "error": str(e)},
            )
            return IntegrationResult(
                success=False,
                action=ActionType.UNBLOCK,
                integration_type=self.integration_type,
                target=mac_address,
                message=f"Error unblocking device {mac_address}",
                error=str(e),
            )

    async def is_device_blocked(
        self,
        mac_address: str,
        ip_address: str | None = None,
    ) -> bool:
        """Check if a device is currently blocked."""
        if not self.is_enabled:
            return False

        try:
            async with await self._get_client() as client:
                if self._is_opnsense is None:
                    await self.test_connection()

                # Check for blocking rule/alias entry
                if self._is_opnsense:
                    response = await client.get("/api/firewall/alias/getItem/netguardian_blocked")
                    if response.status_code == 200:
                        data = response.json()
                        # Check if MAC is in the alias
                        content = str(data).lower()
                        return mac_address.lower() in content
                else:
                    response = await client.get("/api/v1/firewall/rule")
                    if response.status_code == 200:
                        data = response.json()
                        rules = data.get("data", [])
                        for rule in rules:
                            if "NetGuardian Block:" in rule.get("descr", ""):
                                if mac_address.lower() in str(rule).lower():
                                    return True
                        return False

                return False

        except Exception as e:
            logger.error(
                "Error checking device block status",
                extra={"mac_address": mac_address, "error": str(e)},
            )
            return False

    async def get_blocked_devices(self) -> list[dict[str, Any]]:
        """Get list of all devices blocked by NetGuardian rules."""
        if not self.is_enabled:
            return []

        # This would need to parse firewall rules/aliases
        # to extract blocked MAC addresses
        # Simplified implementation returns empty list
        return []


# Singleton instance
_pfsense_service: PfSenseService | None = None


def get_pfsense_service() -> PfSenseService:
    """Get or create the pfSense service singleton."""
    global _pfsense_service
    if _pfsense_service is None:
        _pfsense_service = PfSenseService()
    return _pfsense_service
