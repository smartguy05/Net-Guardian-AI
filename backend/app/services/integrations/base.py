"""Base classes for integration services."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class IntegrationType(Enum):
    """Types of integrations."""

    ADGUARD_HOME = "adguard_home"
    UNIFI = "unifi"
    PFSENSE = "pfsense"
    OPNSENSE = "opnsense"
    SSH = "ssh"


class ActionType(Enum):
    """Types of actions that can be performed."""

    # Device actions
    BLOCK_DEVICE = "block_device"
    UNBLOCK_DEVICE = "unblock_device"
    BLOCK = "block"  # Alias for block_device
    UNBLOCK = "unblock"  # Alias for unblock_device

    # Domain actions
    BLOCK_DOMAIN = "block_domain"
    UNBLOCK_DOMAIN = "unblock_domain"

    # Other actions
    TEST = "test"
    SYNC = "sync"
    STATUS = "status"


@dataclass
class IntegrationResult:
    """Result of an integration action."""

    success: bool
    action: ActionType
    integration_type: IntegrationType
    target: str  # MAC address, IP, or domain
    message: str
    details: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "action": self.action.value,
            "integration_type": self.integration_type.value,
            "target": self.target,
            "message": self.message,
            "details": self.details,
            "error": self.error,
        }


class IntegrationService(ABC):
    """Base class for integration services."""

    integration_type: IntegrationType

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the integration is properly configured."""
        pass

    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if the integration is enabled."""
        pass

    @abstractmethod
    async def test_connection(self) -> IntegrationResult:
        """Test connectivity to the external service."""
        pass

    @abstractmethod
    async def block_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> IntegrationResult:
        """Block a device from the network."""
        pass

    @abstractmethod
    async def unblock_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
    ) -> IntegrationResult:
        """Unblock a device from the network."""
        pass

    @abstractmethod
    async def is_device_blocked(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Check if a device is currently blocked."""
        pass
