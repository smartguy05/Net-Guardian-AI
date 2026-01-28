"""UniFi Controller integration for device blocking."""

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


class UniFiService(IntegrationService):
    """Integration with UniFi Controller for device management.

    UniFi Controller allows blocking devices by MAC address through
    firewall rules or by blocking them at the access point level.
    """

    def __init__(self):
        self._session_cookie: str | None = None
        self._csrf_token: str | None = None

    @property
    def integration_type(self) -> IntegrationType:
        return IntegrationType.UNIFI

    @property
    def is_configured(self) -> bool:
        return bool(
            settings.router_integration_type == "unifi"
            and settings.router_url
            and settings.router_username
            and settings.router_password
        )

    @property
    def is_enabled(self) -> bool:
        return self.is_configured and settings.router_integration_type == "unifi"

    async def _get_client(self) -> httpx.AsyncClient:
        """Create HTTP client with proper SSL settings."""
        return httpx.AsyncClient(
            base_url=settings.router_url.rstrip("/"),
            verify=settings.router_verify_ssl,
            timeout=30.0,
        )

    async def _login(self, client: httpx.AsyncClient) -> bool:
        """Authenticate with UniFi Controller."""
        try:
            # UniFi Controller login endpoint
            response = await client.post(
                "/api/login",
                json={
                    "username": settings.router_username,
                    "password": settings.router_password,
                },
            )

            if response.status_code == 200:
                # Store session cookie
                self._session_cookie = response.cookies.get("unifises")
                self._csrf_token = response.cookies.get("csrf_token")
                return True

            logger.warning(
                "UniFi login failed",
                extra={"status_code": response.status_code},
            )
            return False

        except Exception as e:
            logger.error("UniFi login error", extra={"error": str(e)})
            return False

    async def _logout(self, client: httpx.AsyncClient) -> None:
        """Logout from UniFi Controller."""
        try:
            await client.post("/api/logout")
        except Exception:
            pass  # Ignore logout errors

    async def test_connection(self) -> IntegrationResult:
        """Test connectivity to UniFi Controller."""
        if not self.is_configured:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target="",
                message="UniFi Controller is not configured",
                error="Missing URL, username, or password",
            )

        try:
            async with await self._get_client() as client:
                if await self._login(client):
                    # Get controller info
                    response = await client.get(
                        f"/api/s/{settings.router_site}/stat/sysinfo"
                    )

                    if response.status_code == 200:
                        data = response.json()
                        sysinfo = data.get("data", [{}])[0]

                        await self._logout(client)

                        return IntegrationResult(
                            success=True,
                            action=ActionType.TEST,
                            integration_type=self.integration_type,
                            target=settings.router_url,
                            message="Successfully connected to UniFi Controller",
                            details={
                                "version": sysinfo.get("version", "unknown"),
                                "site": settings.router_site,
                            },
                        )

                    await self._logout(client)

                return IntegrationResult(
                    success=False,
                    action=ActionType.TEST,
                    integration_type=self.integration_type,
                    target=settings.router_url,
                    message="Failed to authenticate with UniFi Controller",
                    error="Invalid credentials or unauthorized",
                )

        except httpx.ConnectError as e:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target=settings.router_url,
                message="Failed to connect to UniFi Controller",
                error=f"Connection error: {str(e)}",
            )
        except Exception as e:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target=settings.router_url,
                message="Error testing UniFi Controller connection",
                error=str(e),
            )

    async def block_device(
        self,
        mac_address: str,
        reason: str | None = None,
        device_name: str | None = None,
    ) -> IntegrationResult:
        """Block a device by MAC address using UniFi Controller.

        Uses the 'block' command to prevent the device from connecting
        to the network via any UniFi access points/switches.
        """
        if not self.is_enabled:
            return IntegrationResult(
                success=False,
                action=ActionType.BLOCK,
                integration_type=self.integration_type,
                target=mac_address,
                message="UniFi integration is not enabled",
                error="Integration disabled or not configured",
            )

        try:
            async with await self._get_client() as client:
                if not await self._login(client):
                    return IntegrationResult(
                        success=False,
                        action=ActionType.BLOCK,
                        integration_type=self.integration_type,
                        target=mac_address,
                        message="Failed to authenticate with UniFi Controller",
                        error="Login failed",
                    )

                # Block the client using stamp-cmd
                response = await client.post(
                    f"/api/s/{settings.router_site}/cmd/stamgr",
                    json={
                        "cmd": "block-sta",
                        "mac": mac_address.lower(),
                    },
                )

                await self._logout(client)

                if response.status_code == 200:
                    data = response.json()
                    if data.get("meta", {}).get("rc") == "ok":
                        logger.info(
                            "Device blocked via UniFi",
                            extra={
                                "mac_address": mac_address,
                                "device_name": device_name,
                                "reason": reason,
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
                                "method": "block-sta",
                            },
                        )

                return IntegrationResult(
                    success=False,
                    action=ActionType.BLOCK,
                    integration_type=self.integration_type,
                    target=mac_address,
                    message=f"Failed to block device {mac_address}",
                    error=f"UniFi API error: {response.text}",
                )

        except Exception as e:
            logger.error(
                "Error blocking device via UniFi",
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
        reason: str | None = None,
        device_name: str | None = None,
    ) -> IntegrationResult:
        """Unblock a device by MAC address."""
        if not self.is_enabled:
            return IntegrationResult(
                success=False,
                action=ActionType.UNBLOCK,
                integration_type=self.integration_type,
                target=mac_address,
                message="UniFi integration is not enabled",
                error="Integration disabled or not configured",
            )

        try:
            async with await self._get_client() as client:
                if not await self._login(client):
                    return IntegrationResult(
                        success=False,
                        action=ActionType.UNBLOCK,
                        integration_type=self.integration_type,
                        target=mac_address,
                        message="Failed to authenticate with UniFi Controller",
                        error="Login failed",
                    )

                # Unblock the client
                response = await client.post(
                    f"/api/s/{settings.router_site}/cmd/stamgr",
                    json={
                        "cmd": "unblock-sta",
                        "mac": mac_address.lower(),
                    },
                )

                await self._logout(client)

                if response.status_code == 200:
                    data = response.json()
                    if data.get("meta", {}).get("rc") == "ok":
                        logger.info(
                            "Device unblocked via UniFi",
                            extra={
                                "mac_address": mac_address,
                                "device_name": device_name,
                                "reason": reason,
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
                    error=f"UniFi API error: {response.text}",
                )

        except Exception as e:
            logger.error(
                "Error unblocking device via UniFi",
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

    async def is_device_blocked(self, mac_address: str) -> bool | None:
        """Check if a device is currently blocked."""
        if not self.is_enabled:
            return None

        try:
            async with await self._get_client() as client:
                if not await self._login(client):
                    return None

                # Get client info
                response = await client.get(
                    f"/api/s/{settings.router_site}/stat/sta/{mac_address.lower()}"
                )

                await self._logout(client)

                if response.status_code == 200:
                    data = response.json()
                    clients = data.get("data", [])
                    if clients:
                        return clients[0].get("blocked", False)

                return None

        except Exception as e:
            logger.error(
                "Error checking device block status",
                extra={"mac_address": mac_address, "error": str(e)},
            )
            return None

    async def get_blocked_devices(self) -> list[dict[str, Any]]:
        """Get list of all blocked devices."""
        if not self.is_enabled:
            return []

        try:
            async with await self._get_client() as client:
                if not await self._login(client):
                    return []

                # Get all clients
                response = await client.get(
                    f"/api/s/{settings.router_site}/list/user"
                )

                await self._logout(client)

                if response.status_code == 200:
                    data = response.json()
                    clients = data.get("data", [])

                    # Filter to blocked clients only
                    blocked = []
                    for client_data in clients:
                        if client_data.get("blocked", False):
                            blocked.append({
                                "mac_address": client_data.get("mac", "").upper(),
                                "hostname": client_data.get("hostname"),
                                "name": client_data.get("name"),
                                "blocked": True,
                                "source": "unifi",
                            })

                    return blocked

                return []

        except Exception as e:
            logger.error(
                "Error getting blocked devices from UniFi",
                extra={"error": str(e)},
            )
            return []


# Singleton instance
_unifi_service: UniFiService | None = None


def get_unifi_service() -> UniFiService:
    """Get or create the UniFi service singleton."""
    global _unifi_service
    if _unifi_service is None:
        _unifi_service = UniFiService()
    return _unifi_service
