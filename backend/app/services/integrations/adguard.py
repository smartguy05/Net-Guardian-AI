"""AdGuard Home integration service for DNS-level device blocking."""

import httpx
import structlog
from typing import Any, Dict, List, Optional

from app.config import settings
from app.core.http_client import get_http_client_pool
from app.services.integrations.base import (
    ActionType,
    IntegrationResult,
    IntegrationService,
    IntegrationType,
)

logger = structlog.get_logger()


class AdGuardHomeService(IntegrationService):
    """Integration service for AdGuard Home DNS-level blocking.

    AdGuard Home allows blocking devices by adding them as "clients" with
    specific settings that block all their DNS queries.
    """

    integration_type = IntegrationType.ADGUARD_HOME

    def __init__(self):
        """Initialize the AdGuard Home service."""
        self._client: Optional[httpx.AsyncClient] = None
        self._use_pool = True  # Use shared connection pool

    @property
    def is_configured(self) -> bool:
        """Check if AdGuard Home is properly configured."""
        return bool(
            settings.adguard_url
            and settings.adguard_username
            and settings.adguard_password
        )

    @property
    def is_enabled(self) -> bool:
        """Check if AdGuard integration is enabled."""
        return settings.adguard_enabled and self.is_configured

    @property
    def _base_url(self) -> str:
        """Get the base URL for AdGuard Home API."""
        url = settings.adguard_url.rstrip("/")
        return url

    @property
    def _auth(self) -> tuple:
        """Get authentication tuple."""
        return (settings.adguard_username, settings.adguard_password)

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client using shared pool."""
        if self._use_pool:
            pool = get_http_client_pool()
            return await pool.get_client(
                key="adguard",
                base_url=self._base_url,
                auth=self._auth,
                verify=settings.adguard_verify_ssl,
            )

        # Fallback to instance client if pool not available
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                auth=self._auth,
                timeout=30.0,
                verify=settings.adguard_verify_ssl,
            )
        return self._client

    async def close(self):
        """Close the HTTP client.

        Note: When using the shared pool, this only closes the instance client.
        The pool client is managed by the application lifecycle.
        """
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def test_connection(self) -> IntegrationResult:
        """Test connectivity to AdGuard Home."""
        if not self.is_configured:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target="",
                message="AdGuard Home is not configured",
                error="Missing URL, username, or password",
            )

        try:
            client = await self._get_client()
            response = await client.get("/control/status")
            response.raise_for_status()

            data = response.json()
            return IntegrationResult(
                success=True,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target="",
                message="Successfully connected to AdGuard Home",
                details={
                    "version": data.get("version"),
                    "running": data.get("running"),
                    "protection_enabled": data.get("protection_enabled"),
                },
            )
        except httpx.HTTPStatusError as e:
            logger.error("AdGuard Home connection failed", status=e.response.status_code)
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target="",
                message="Failed to connect to AdGuard Home",
                error=f"HTTP {e.response.status_code}: {e.response.text}",
            )
        except Exception as e:
            logger.error("AdGuard Home connection error", error=str(e))
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target="",
                message="Failed to connect to AdGuard Home",
                error=str(e),
            )

    async def _get_clients(self) -> Dict[str, Any]:
        """Get all configured clients from AdGuard Home."""
        client = await self._get_client()
        response = await client.get("/control/clients")
        response.raise_for_status()
        return response.json()

    async def _find_client(
        self, mac_address: str, ip_address: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Find a client by MAC address or IP."""
        clients_data = await self._get_clients()
        clients = clients_data.get("clients", [])

        # Normalize MAC for comparison
        mac_normalized = mac_address.lower().replace("-", ":")

        for client in clients:
            client_ids = client.get("ids", [])
            for cid in client_ids:
                # Check if it matches MAC
                if cid.lower().replace("-", ":") == mac_normalized:
                    return client
                # Check if it matches IP
                if ip_address and cid == ip_address:
                    return client

        return None

    def _generate_client_name(self, mac_address: str) -> str:
        """Generate a client name for quarantined devices."""
        mac_short = mac_address.replace(":", "").replace("-", "")[-6:].upper()
        return f"quarantine-{mac_short}"

    async def block_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> IntegrationResult:
        """Block a device by adding it to AdGuard Home with blocking enabled.

        This creates or updates a client entry in AdGuard Home with:
        - filtering_enabled: false (blocks all queries)
        - blocked: true (marks as blocked client)
        """
        if not self.is_enabled:
            return IntegrationResult(
                success=False,
                action=ActionType.BLOCK_DEVICE,
                integration_type=self.integration_type,
                target=mac_address,
                message="AdGuard Home integration is not enabled",
                error="Integration disabled or not configured",
            )

        try:
            client = await self._get_client()

            # Check if client already exists
            existing = await self._find_client(mac_address, ip_address)

            # Build client IDs (MAC and optionally IP)
            ids = [mac_address.lower()]
            if ip_address:
                ids.append(ip_address)

            client_name = self._generate_client_name(mac_address)

            # Client configuration for blocking
            client_config = {
                "name": client_name,
                "ids": ids,
                "blocked_services": [],
                "upstreams": [],
                "use_global_settings": False,
                "filtering_enabled": False,  # Disables filtering, effectively blocking
                "parental_enabled": False,
                "safesearch_enabled": False,
                "safebrowsing_enabled": False,
                "use_global_blocked_services": False,
                "tags": ["quarantined", "netguardian"],
            }

            if existing:
                # Update existing client
                response = await client.post(
                    "/control/clients/update",
                    json={
                        "name": existing.get("name"),
                        "data": client_config,
                    },
                )
            else:
                # Add new client
                response = await client.post(
                    "/control/clients/add",
                    json=client_config,
                )

            response.raise_for_status()

            logger.info(
                "Device blocked via AdGuard Home",
                mac=mac_address,
                ip=ip_address,
                reason=reason,
            )

            return IntegrationResult(
                success=True,
                action=ActionType.BLOCK_DEVICE,
                integration_type=self.integration_type,
                target=mac_address,
                message=f"Device {mac_address} blocked via AdGuard Home DNS",
                details={
                    "client_name": client_name,
                    "ip_address": ip_address,
                    "reason": reason,
                },
            )

        except httpx.HTTPStatusError as e:
            logger.error(
                "Failed to block device in AdGuard Home",
                mac=mac_address,
                status=e.response.status_code,
                error=e.response.text,
            )
            return IntegrationResult(
                success=False,
                action=ActionType.BLOCK_DEVICE,
                integration_type=self.integration_type,
                target=mac_address,
                message="Failed to block device in AdGuard Home",
                error=f"HTTP {e.response.status_code}: {e.response.text}",
            )
        except Exception as e:
            logger.error(
                "Error blocking device in AdGuard Home",
                mac=mac_address,
                error=str(e),
            )
            return IntegrationResult(
                success=False,
                action=ActionType.BLOCK_DEVICE,
                integration_type=self.integration_type,
                target=mac_address,
                message="Error blocking device in AdGuard Home",
                error=str(e),
            )

    async def unblock_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
    ) -> IntegrationResult:
        """Unblock a device by removing its blocking configuration."""
        if not self.is_enabled:
            return IntegrationResult(
                success=False,
                action=ActionType.UNBLOCK_DEVICE,
                integration_type=self.integration_type,
                target=mac_address,
                message="AdGuard Home integration is not enabled",
                error="Integration disabled or not configured",
            )

        try:
            client = await self._get_client()

            # Find the existing client
            existing = await self._find_client(mac_address, ip_address)

            if not existing:
                # Device not found - nothing to unblock
                return IntegrationResult(
                    success=True,
                    action=ActionType.UNBLOCK_DEVICE,
                    integration_type=self.integration_type,
                    target=mac_address,
                    message="Device was not blocked in AdGuard Home",
                    details={"was_blocked": False},
                )

            # Delete the client entry (removes blocking)
            response = await client.post(
                "/control/clients/delete",
                json={"name": existing.get("name")},
            )
            response.raise_for_status()

            logger.info(
                "Device unblocked via AdGuard Home",
                mac=mac_address,
                ip=ip_address,
            )

            return IntegrationResult(
                success=True,
                action=ActionType.UNBLOCK_DEVICE,
                integration_type=self.integration_type,
                target=mac_address,
                message=f"Device {mac_address} unblocked from AdGuard Home",
                details={
                    "client_name": existing.get("name"),
                    "ip_address": ip_address,
                },
            )

        except httpx.HTTPStatusError as e:
            logger.error(
                "Failed to unblock device in AdGuard Home",
                mac=mac_address,
                status=e.response.status_code,
                error=e.response.text,
            )
            return IntegrationResult(
                success=False,
                action=ActionType.UNBLOCK_DEVICE,
                integration_type=self.integration_type,
                target=mac_address,
                message="Failed to unblock device in AdGuard Home",
                error=f"HTTP {e.response.status_code}: {e.response.text}",
            )
        except Exception as e:
            logger.error(
                "Error unblocking device in AdGuard Home",
                mac=mac_address,
                error=str(e),
            )
            return IntegrationResult(
                success=False,
                action=ActionType.UNBLOCK_DEVICE,
                integration_type=self.integration_type,
                target=mac_address,
                message="Error unblocking device in AdGuard Home",
                error=str(e),
            )

    async def is_device_blocked(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Check if a device is currently blocked in AdGuard Home."""
        if not self.is_enabled:
            return False

        try:
            existing = await self._find_client(mac_address, ip_address)
            if not existing:
                return False

            # Check if the client has blocking tags or filtering disabled
            tags = existing.get("tags", [])
            filtering_enabled = existing.get("filtering_enabled", True)

            return "quarantined" in tags or not filtering_enabled

        except Exception as e:
            logger.error(
                "Error checking device block status",
                mac=mac_address,
                error=str(e),
            )
            return False

    async def get_blocked_devices(self) -> List[Dict[str, Any]]:
        """Get all devices currently blocked via AdGuard Home."""
        if not self.is_enabled:
            return []

        try:
            clients_data = await self._get_clients()
            clients = clients_data.get("clients", [])

            blocked = []
            for client in clients:
                tags = client.get("tags", [])
                if "quarantined" in tags or "netguardian" in tags:
                    blocked.append({
                        "name": client.get("name"),
                        "ids": client.get("ids", []),
                        "tags": tags,
                    })

            return blocked

        except Exception as e:
            logger.error("Error getting blocked devices", error=str(e))
            return []


# Global service instance
_adguard_service: Optional[AdGuardHomeService] = None


def get_adguard_service() -> AdGuardHomeService:
    """Get the global AdGuard Home service instance."""
    global _adguard_service
    if _adguard_service is None:
        _adguard_service = AdGuardHomeService()
    return _adguard_service
