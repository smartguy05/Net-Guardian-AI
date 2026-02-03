"""CenturyLink C4000XG router integration for device blocking via parental control rules.

This integration uses the undocumented CGI API of the C4000XG modem/router
to block devices via the parental control (Access Scheduler) feature.

Note: This is an undocumented API and may change with firmware updates.
"""

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

# Rule name prefix for NetGuardian-created rules
NETGUARDIAN_RULE_PREFIX = "NG_Block_"


class C4000XGService(IntegrationService):
    """Integration with CenturyLink C4000XG modem/router for device blocking.

    Blocking is achieved through the parental control / Access Scheduler feature,
    which creates firewall rules that drop traffic from specified MAC addresses.

    The C4000XG uses a CGI-based API that requires session-based authentication.
    """

    integration_type = IntegrationType.C4000XG

    def __init__(self) -> None:
        """Initialize the C4000XG service."""
        self._session_id: str | None = None

    @property
    def is_configured(self) -> bool:
        """Check if the integration is properly configured."""
        return bool(
            settings.router_integration_type == "c4000xg"
            and settings.router_url
            and settings.router_username
            and settings.router_password
        )

    @property
    def is_enabled(self) -> bool:
        """Check if the integration is enabled."""
        return self.is_configured

    def _get_base_url(self) -> str:
        """Get the base URL for the router."""
        return settings.router_url.rstrip("/")

    async def _create_client(self) -> httpx.AsyncClient:
        """Create HTTP client for API requests."""
        return httpx.AsyncClient(
            base_url=self._get_base_url(),
            verify=settings.router_verify_ssl,
            timeout=30.0,
            follow_redirects=False,  # We handle redirects manually for auth
        )

    async def _login(self, client: httpx.AsyncClient) -> bool:
        """Authenticate and get session cookie.

        Returns:
            True if login successful, False otherwise.
        """
        try:
            response = await client.post(
                "/cgi/cgi_action",
                data={
                    "username": settings.router_username,
                    "password": settings.router_password,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # Successful login returns 302 redirect and sets Session-Id cookie
            if response.status_code == 302:
                session_cookie = response.cookies.get("Session-Id")
                if session_cookie:
                    self._session_id = session_cookie
                    logger.debug("C4000XG login successful")
                    return True

            # Also check for success in 200 response
            if response.status_code == 200:
                session_cookie = response.cookies.get("Session-Id")
                if session_cookie:
                    self._session_id = session_cookie
                    logger.debug("C4000XG login successful (200 response)")
                    return True

            logger.warning(
                "C4000XG login failed",
                extra={
                    "status_code": response.status_code,
                    "response_text": response.text[:200] if response.text else "",
                },
            )
            return False

        except Exception as e:
            logger.error("C4000XG login error", extra={"error": str(e)})
            return False

    async def _ensure_session(self, client: httpx.AsyncClient) -> bool:
        """Ensure we have a valid session, re-login if needed.

        Returns:
            True if session is valid, False otherwise.
        """
        if self._session_id:
            # Test if session is still valid
            client.cookies.set("Session-Id", self._session_id)
            try:
                response = await client.get(
                    "/cgi/cgi_get",
                    params={"Object": "Device.DeviceInfo."},
                    headers={"X-Requested-With": "XMLHttpRequest"},
                )
                if response.status_code == 200:
                    return True
            except Exception:
                pass

        # Session invalid or missing, re-login
        self._session_id = None
        return await self._login(client)

    async def _get_request(
        self, client: httpx.AsyncClient, object_path: str
    ) -> dict[str, Any] | None:
        """Make a GET request to the CGI API.

        Args:
            client: HTTP client with session cookie set
            object_path: The Object parameter for cgi_get

        Returns:
            JSON response data or None on error.
        """
        try:
            response = await client.get(
                "/cgi/cgi_get",
                params={"Object": object_path},
                headers={"X-Requested-With": "XMLHttpRequest"},
            )

            if response.status_code == 200:
                result: dict[str, Any] = response.json()
                return result

            logger.warning(
                "C4000XG GET request failed",
                extra={
                    "object": object_path,
                    "status_code": response.status_code,
                },
            )
            return None

        except Exception as e:
            logger.error(
                "C4000XG GET request error",
                extra={"object": object_path, "error": str(e)},
            )
            return None

    async def _post_request(
        self, client: httpx.AsyncClient, data: dict[str, str]
    ) -> dict[str, Any] | None:
        """Make a POST request to the CGI API (cgi_set).

        Args:
            client: HTTP client with session cookie set
            data: Form data to POST

        Returns:
            JSON response data or None on error.
        """
        try:
            response = await client.post(
                "/cgi/cgi_set",
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest",
                },
            )

            if response.status_code == 200:
                try:
                    result: dict[str, Any] = response.json()
                    return result
                except Exception:
                    # Some responses aren't JSON
                    return {"success": True, "raw": response.text}

            logger.warning(
                "C4000XG POST request failed",
                extra={
                    "data": {k: v for k, v in data.items() if k != "password"},
                    "status_code": response.status_code,
                },
            )
            return None

        except Exception as e:
            logger.error(
                "C4000XG POST request error",
                extra={"error": str(e)},
            )
            return None

    async def _ensure_parental_control_enabled(self, client: httpx.AsyncClient) -> bool:
        """Ensure parental control is enabled.

        Returns:
            True if enabled or successfully enabled, False on error.
        """
        # Check current status
        data = await self._get_request(client, "Device.Firewall.X_LANTIQ_COM_ParentalControl.")

        if data:
            # Check if already enabled
            enable_value = data.get("Enable", "0")
            if enable_value == "1" or enable_value is True:
                return True

        # Enable parental control
        result = await self._post_request(
            client,
            {
                "Object": "Device.Firewall.X_LANTIQ_COM_ParentalControl.",
                "Operation": "Modify",
                "Enable": "1",
            },
        )

        return result is not None

    async def _get_parental_control_rules(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        """Get all parental control rules.

        Returns:
            List of rule dictionaries with index, MAC, and other fields.
        """
        rules: list[dict[str, Any]] = []

        # First get the number of rules
        data = await self._get_request(client, "Device.Firewall.X_LANTIQ_COM_ParentalControl.")

        if not data:
            return rules

        num_rules = int(data.get("RuleNumberOfEntries", 0))

        # Get each rule
        for i in range(1, num_rules + 1):
            rule_data = await self._get_request(
                client, f"Device.Firewall.X_LANTIQ_COM_ParentalControl.Rule.{i}."
            )

            if rule_data:
                rule_data["_index"] = i
                rules.append(rule_data)

        return rules

    async def _find_rule_for_mac(
        self, client: httpx.AsyncClient, mac_address: str
    ) -> dict[str, Any] | None:
        """Find a parental control rule for a specific MAC address.

        Args:
            mac_address: MAC address to search for

        Returns:
            Rule dictionary with _index field, or None if not found.
        """
        rules = await self._get_parental_control_rules(client)
        mac_upper = mac_address.upper().replace("-", ":")

        for rule in rules:
            rule_mac = rule.get("MACAddress", "").upper().replace("-", ":")
            if rule_mac == mac_upper:
                return rule

        return None

    def _normalize_mac(self, mac_address: str) -> str:
        """Normalize MAC address to XX:XX:XX:XX:XX:XX format."""
        # Remove common separators and normalize
        mac = mac_address.upper().replace("-", "").replace(":", "").replace(".", "")

        if len(mac) != 12:
            return mac_address.upper()

        # Format as XX:XX:XX:XX:XX:XX
        return ":".join(mac[i : i + 2] for i in range(0, 12, 2))

    async def test_connection(self) -> IntegrationResult:
        """Test connectivity to the C4000XG router."""
        if not self.is_configured:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target="",
                message="C4000XG is not configured",
                error="Missing URL, username, or password",
            )

        try:
            async with await self._create_client() as client:
                # Try to login
                if not await self._login(client):
                    return IntegrationResult(
                        success=False,
                        action=ActionType.TEST,
                        integration_type=self.integration_type,
                        target=settings.router_url,
                        message="Failed to authenticate with C4000XG",
                        error="Login failed - check username and password",
                    )

                # Get device info
                assert self._session_id is not None  # Set by successful _login
                client.cookies.set("Session-Id", self._session_id)
                device_info = await self._get_request(client, "Device.DeviceInfo.")

                if device_info:
                    return IntegrationResult(
                        success=True,
                        action=ActionType.TEST,
                        integration_type=self.integration_type,
                        target=settings.router_url,
                        message="Successfully connected to C4000XG",
                        details={
                            "model": device_info.get("ModelName", "C4000XG"),
                            "software_version": device_info.get("SoftwareVersion"),
                            "hardware_version": device_info.get("HardwareVersion"),
                            "serial_number": device_info.get("SerialNumber"),
                            "type": "c4000xg",
                        },
                    )

                return IntegrationResult(
                    success=True,
                    action=ActionType.TEST,
                    integration_type=self.integration_type,
                    target=settings.router_url,
                    message="Connected to C4000XG (limited info available)",
                    details={"type": "c4000xg"},
                )

        except httpx.ConnectError as e:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target=settings.router_url,
                message="Failed to connect to C4000XG",
                error=f"Connection error: {str(e)}",
            )
        except Exception as e:
            return IntegrationResult(
                success=False,
                action=ActionType.TEST,
                integration_type=self.integration_type,
                target=settings.router_url,
                message="Error testing C4000XG connection",
                error=str(e),
            )

    async def block_device(
        self,
        mac_address: str,
        ip_address: str | None = None,
        reason: str | None = None,
        device_name: str | None = None,
    ) -> IntegrationResult:
        """Block a device by creating a parental control rule.

        This creates a rule that blocks all traffic from the specified MAC address
        24/7 by setting the access schedule to all days, all hours.

        Args:
            mac_address: MAC address to block
            ip_address: Optional IP address (not used for C4000XG)
            reason: Optional reason for blocking
            device_name: Optional device name for rule labeling

        Returns:
            IntegrationResult with operation outcome.
        """
        if not self.is_enabled:
            return IntegrationResult(
                success=False,
                action=ActionType.BLOCK,
                integration_type=self.integration_type,
                target=mac_address,
                message="C4000XG integration is not enabled",
                error="Integration disabled or not configured",
            )

        normalized_mac = self._normalize_mac(mac_address)

        try:
            async with await self._create_client() as client:
                if not await self._ensure_session(client):
                    return IntegrationResult(
                        success=False,
                        action=ActionType.BLOCK,
                        integration_type=self.integration_type,
                        target=mac_address,
                        message="Failed to authenticate with C4000XG",
                        error="Login failed",
                    )

                assert self._session_id is not None  # Set by successful _ensure_session
                client.cookies.set("Session-Id", self._session_id)

                # Check if device is already blocked
                existing_rule = await self._find_rule_for_mac(client, normalized_mac)
                if existing_rule:
                    logger.info(
                        "Device already blocked in C4000XG",
                        extra={"mac_address": normalized_mac},
                    )
                    return IntegrationResult(
                        success=True,
                        action=ActionType.BLOCK,
                        integration_type=self.integration_type,
                        target=mac_address,
                        message=f"Device {mac_address} is already blocked",
                        details={
                            "rule_index": existing_rule.get("_index"),
                            "already_blocked": True,
                        },
                    )

                # Ensure parental control is enabled
                if not await self._ensure_parental_control_enabled(client):
                    return IntegrationResult(
                        success=False,
                        action=ActionType.BLOCK,
                        integration_type=self.integration_type,
                        target=mac_address,
                        message="Failed to enable parental control",
                        error="Could not enable parental control feature",
                    )

                # Create the blocking rule
                # Rule blocks device 24/7 by setting all days and full time range
                rule_data = {
                    "Object": "Device.Firewall.X_LANTIQ_COM_ParentalControl.Rule.",
                    "Operation": "Add",
                    "Enable": "1",
                    "Target": "Drop",
                    "TimeStart": "00:00",
                    "TimeEnd": "23:59",
                    "DaysOfTheWeek": "Sun,Mon,Tue,Wed,Thu,Fri,Sat",
                    "MACAddress": normalized_mac,
                }

                result = await self._post_request(client, rule_data)

                if result:
                    logger.info(
                        "Device blocked via C4000XG parental control",
                        extra={
                            "mac_address": normalized_mac,
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
                            "method": "parental_control_rule",
                        },
                    )

                return IntegrationResult(
                    success=False,
                    action=ActionType.BLOCK,
                    integration_type=self.integration_type,
                    target=mac_address,
                    message=f"Failed to block device {mac_address}",
                    error="Could not create parental control rule",
                )

        except Exception as e:
            logger.error(
                "Error blocking device via C4000XG",
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
        """Unblock a device by removing its parental control rule.

        Args:
            mac_address: MAC address to unblock
            ip_address: Optional IP address (not used for C4000XG)
            reason: Optional reason for unblocking
            device_name: Optional device name

        Returns:
            IntegrationResult with operation outcome.
        """
        if not self.is_enabled:
            return IntegrationResult(
                success=False,
                action=ActionType.UNBLOCK,
                integration_type=self.integration_type,
                target=mac_address,
                message="C4000XG integration is not enabled",
                error="Integration disabled or not configured",
            )

        normalized_mac = self._normalize_mac(mac_address)

        try:
            async with await self._create_client() as client:
                if not await self._ensure_session(client):
                    return IntegrationResult(
                        success=False,
                        action=ActionType.UNBLOCK,
                        integration_type=self.integration_type,
                        target=mac_address,
                        message="Failed to authenticate with C4000XG",
                        error="Login failed",
                    )

                assert self._session_id is not None  # Set by successful _ensure_session
                client.cookies.set("Session-Id", self._session_id)

                # Find the rule for this MAC
                existing_rule = await self._find_rule_for_mac(client, normalized_mac)

                if not existing_rule:
                    logger.info(
                        "No blocking rule found for device in C4000XG",
                        extra={"mac_address": normalized_mac},
                    )
                    return IntegrationResult(
                        success=True,
                        action=ActionType.UNBLOCK,
                        integration_type=self.integration_type,
                        target=mac_address,
                        message=f"Device {mac_address} is not blocked",
                        details={"already_unblocked": True},
                    )

                rule_index = existing_rule.get("_index")

                # Delete the rule
                delete_data = {
                    "Object": f"Device.Firewall.X_LANTIQ_COM_ParentalControl.Rule.{rule_index}.",
                    "Operation": "Del",
                }

                result = await self._post_request(client, delete_data)

                if result:
                    logger.info(
                        "Device unblocked via C4000XG",
                        extra={
                            "mac_address": normalized_mac,
                            "rule_index": rule_index,
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
                            "rule_index": rule_index,
                        },
                    )

                return IntegrationResult(
                    success=False,
                    action=ActionType.UNBLOCK,
                    integration_type=self.integration_type,
                    target=mac_address,
                    message=f"Failed to unblock device {mac_address}",
                    error="Could not delete parental control rule",
                )

        except Exception as e:
            logger.error(
                "Error unblocking device via C4000XG",
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
        """Check if a device is currently blocked.

        Args:
            mac_address: MAC address to check
            ip_address: Optional IP address (not used for C4000XG)

        Returns:
            True if device has a blocking rule, False otherwise.
        """
        if not self.is_enabled:
            return False

        normalized_mac = self._normalize_mac(mac_address)

        try:
            async with await self._create_client() as client:
                if not await self._ensure_session(client):
                    return False

                assert self._session_id is not None  # Set by successful _ensure_session
                client.cookies.set("Session-Id", self._session_id)

                rule = await self._find_rule_for_mac(client, normalized_mac)
                return rule is not None

        except Exception as e:
            logger.error(
                "Error checking device block status in C4000XG",
                extra={"mac_address": mac_address, "error": str(e)},
            )
            return False

    async def get_blocked_devices(self) -> list[dict[str, Any]]:
        """Get list of all devices blocked by parental control rules.

        Returns:
            List of dictionaries with blocked device info.
        """
        if not self.is_enabled:
            return []

        try:
            async with await self._create_client() as client:
                if not await self._ensure_session(client):
                    return []

                assert self._session_id is not None  # Set by successful _ensure_session
                client.cookies.set("Session-Id", self._session_id)

                rules = await self._get_parental_control_rules(client)

                blocked = []
                for rule in rules:
                    mac = rule.get("MACAddress", "")
                    if mac and rule.get("Target") == "Drop":
                        blocked.append(
                            {
                                "mac_address": mac,
                                "rule_index": rule.get("_index"),
                                "enabled": rule.get("Enable") == "1",
                                "time_start": rule.get("TimeStart"),
                                "time_end": rule.get("TimeEnd"),
                                "days": rule.get("DaysOfTheWeek"),
                            }
                        )

                return blocked

        except Exception as e:
            logger.error(
                "Error getting blocked devices from C4000XG",
                extra={"error": str(e)},
            )
            return []

    async def get_connected_devices(self) -> list[dict[str, Any]]:
        """Get list of connected devices from the router.

        This queries the Device.Hosts.Host object which contains
        all devices known to the router.

        Returns:
            List of dictionaries with device info (MAC, IP, hostname, etc.)
        """
        if not self.is_enabled:
            return []

        try:
            async with await self._create_client() as client:
                if not await self._ensure_session(client):
                    return []

                assert self._session_id is not None  # Set by successful _ensure_session
                client.cookies.set("Session-Id", self._session_id)

                # Get host list
                data = await self._get_request(client, "Device.Hosts.Host.")

                if not data:
                    return []

                # The response structure may vary, handle both list and dict
                devices = []

                # If it's a list of hosts
                if isinstance(data, list):
                    for host in data:
                        devices.append(self._parse_host_entry(host))
                elif isinstance(data, dict):
                    # May be indexed like Host.1, Host.2, etc.
                    # Or contain HostNumberOfEntries
                    num_hosts = int(data.get("HostNumberOfEntries", 0))

                    for i in range(1, num_hosts + 1):
                        host_data = await self._get_request(client, f"Device.Hosts.Host.{i}.")
                        if host_data:
                            devices.append(self._parse_host_entry(host_data))

                return devices

        except Exception as e:
            logger.error(
                "Error getting connected devices from C4000XG",
                extra={"error": str(e)},
            )
            return []

    def _parse_host_entry(self, host: dict[str, Any]) -> dict[str, Any]:
        """Parse a host entry from the router's device list.

        Args:
            host: Raw host data from the router

        Returns:
            Normalized device dictionary.
        """
        return {
            "mac_address": host.get("PhysAddress", "").upper(),
            "ip_address": host.get("IPAddress"),
            "hostname": host.get("HostName"),
            "active": host.get("Active") == "1" or host.get("Active") is True,
            "interface": host.get("Layer1Interface"),
            "address_source": host.get("AddressSource"),
        }


# Singleton instance
_c4000xg_service: C4000XGService | None = None


def get_c4000xg_service() -> C4000XGService:
    """Get or create the C4000XG service singleton."""
    global _c4000xg_service
    if _c4000xg_service is None:
        _c4000xg_service = C4000XGService()
    return _c4000xg_service
