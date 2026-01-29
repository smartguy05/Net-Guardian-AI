"""Quarantine service for managing device isolation."""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.session import AsyncSessionLocal
from app.models.audit_log import AuditAction
from app.models.device import Device, DeviceStatus
from app.models.user import User
from app.services.audit_service import AuditService, get_audit_service
from app.services.integrations.adguard import AdGuardHomeService, get_adguard_service
from app.services.integrations.base import IntegrationService
from app.services.integrations.pfsense import get_pfsense_service
from app.services.integrations.unifi import get_unifi_service

logger = structlog.get_logger()


@dataclass
class QuarantineResult:
    """Result of a quarantine operation."""

    success: bool
    device_id: UUID
    device_name: str
    mac_address: str
    message: str
    integration_results: list[dict[str, Any]]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "device_id": str(self.device_id),
            "device_name": self.device_name,
            "mac_address": self.mac_address,
            "message": self.message,
            "integration_results": self.integration_results,
            "errors": self.errors,
        }


class QuarantineService:
    """Service for quarantining and releasing devices.

    This service orchestrates device quarantine operations across
    multiple integration points (AdGuard Home, routers, etc.) and
    maintains audit logs of all actions.
    """

    def __init__(
        self,
        session: AsyncSession | None = None,
        adguard_service: AdGuardHomeService | None = None,
        router_service: IntegrationService | None = None,
        audit_service: AuditService | None = None,
    ):
        """Initialize the quarantine service.

        Args:
            session: Optional database session
            adguard_service: Optional AdGuard Home service (uses global if not provided)
            router_service: Optional router service (auto-detected based on config)
            audit_service: Optional audit service (uses global if not provided)
        """
        self._session = session
        self._adguard = adguard_service or get_adguard_service()
        self._audit = audit_service or get_audit_service()

        # Auto-detect router service based on configuration
        self._router: IntegrationService | None
        if router_service:
            self._router = router_service
        elif settings.router_integration_type == "unifi":
            self._router = get_unifi_service()
        elif settings.router_integration_type in ("pfsense", "opnsense"):
            self._router = get_pfsense_service()
        else:
            self._router = None

    async def _get_session(self) -> AsyncSession:
        """Get a database session."""
        if self._session:
            return self._session
        return AsyncSessionLocal()

    async def _close_session(self, session: AsyncSession) -> None:
        """Close session if it was created internally."""
        if session != self._session:
            await session.close()

    async def quarantine_device(
        self,
        device_id: UUID,
        user: User,
        reason: str | None = None,
        ip_address: str | None = None,
    ) -> QuarantineResult:
        """Quarantine a device.

        This method:
        1. Updates the device status to quarantined
        2. Blocks the device via AdGuard Home (if configured)
        3. Blocks the device via router (if configured) - future
        4. Creates an audit log entry

        Args:
            device_id: The device to quarantine
            user: The user performing the action
            reason: Optional reason for quarantine
            ip_address: Client IP for audit logging

        Returns:
            QuarantineResult with operation outcome
        """
        session = await self._get_session()
        integration_results: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            # Get the device
            result = await session.execute(
                select(Device).where(Device.id == device_id)
            )
            device = result.scalar_one_or_none()

            if not device:
                return QuarantineResult(
                    success=False,
                    device_id=device_id,
                    device_name="Unknown",
                    mac_address="Unknown",
                    message="Device not found",
                    integration_results=[],
                    errors=["Device not found"],
                )

            if device.status == DeviceStatus.QUARANTINED:
                return QuarantineResult(
                    success=False,
                    device_id=device_id,
                    device_name=device.hostname or device.mac_address,
                    mac_address=device.mac_address,
                    message="Device is already quarantined",
                    integration_results=[],
                    errors=["Device is already quarantined"],
                )

            # Get device's primary IP for blocking
            device_ip = device.ip_addresses[0] if device.ip_addresses else None

            # Block via AdGuard Home
            if self._adguard.is_enabled:
                adguard_result = await self._adguard.block_device(
                    mac_address=device.mac_address,
                    ip_address=device_ip,
                    reason=reason,
                )
                integration_results.append(adguard_result.to_dict())

                if not adguard_result.success:
                    errors.append(f"AdGuard: {adguard_result.error}")

                # Log integration action
                await self._audit.log_integration_action(
                    action=AuditAction.INTEGRATION_BLOCK,
                    integration_type="adguard_home",
                    target=device.mac_address,
                    user=user,
                    success=adguard_result.success,
                    details=adguard_result.to_dict(),
                    error_message=adguard_result.error,
                )

            # Block via router integration (UniFi, pfSense, etc.)
            if self._router and self._router.is_enabled:
                router_result = await self._router.block_device(
                    mac_address=device.mac_address,
                    ip_address=device_ip,
                    reason=reason,
                )
                integration_results.append(router_result.to_dict())

                if not router_result.success:
                    errors.append(
                        f"{router_result.integration_type.value}: {router_result.error}"
                    )

                # Log integration action
                await self._audit.log_integration_action(
                    action=AuditAction.INTEGRATION_BLOCK,
                    integration_type=router_result.integration_type.value,
                    target=device.mac_address,
                    user=user,
                    success=router_result.success,
                    details=router_result.to_dict(),
                    error_message=router_result.error,
                )

            # Update device status
            device.status = DeviceStatus.QUARANTINED
            await session.commit()
            await session.refresh(device)

            # Create audit log
            await self._audit.log_device_quarantine(
                device_id=UUID(str(device.id)),
                device_name=device.hostname or device.mac_address,
                mac_address=device.mac_address,
                user=user,
                reason=reason,
                integration_results=integration_results,
                ip_address=ip_address,
            )

            logger.info(
                "Device quarantined",
                device_id=str(device.id),
                mac=device.mac_address,
                user=user.username,
                reason=reason,
            )

            # Consider it successful if at least the DB was updated
            # Even if some integrations failed
            return QuarantineResult(
                success=True,
                device_id=UUID(str(device.id)),
                device_name=device.hostname or device.mac_address,
                mac_address=device.mac_address,
                message="Device quarantined successfully" + (
                    f" with {len(errors)} integration warning(s)" if errors else ""
                ),
                integration_results=integration_results,
                errors=errors,
            )

        except Exception as e:
            await session.rollback()
            logger.error(
                "Failed to quarantine device",
                device_id=str(device_id),
                error=str(e),
            )
            return QuarantineResult(
                success=False,
                device_id=device_id,
                device_name="Unknown",
                mac_address="Unknown",
                message="Failed to quarantine device",
                integration_results=integration_results,
                errors=[str(e)],
            )
        finally:
            await self._close_session(session)

    async def release_device(
        self,
        device_id: UUID,
        user: User,
        reason: str | None = None,
        ip_address: str | None = None,
    ) -> QuarantineResult:
        """Release a device from quarantine.

        This method:
        1. Updates the device status to active
        2. Unblocks the device via AdGuard Home (if configured)
        3. Unblocks the device via router (if configured) - future
        4. Creates an audit log entry

        Args:
            device_id: The device to release
            user: The user performing the action
            reason: Optional reason for release
            ip_address: Client IP for audit logging

        Returns:
            QuarantineResult with operation outcome
        """
        session = await self._get_session()
        integration_results: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            # Get the device
            result = await session.execute(
                select(Device).where(Device.id == device_id)
            )
            device = result.scalar_one_or_none()

            if not device:
                return QuarantineResult(
                    success=False,
                    device_id=device_id,
                    device_name="Unknown",
                    mac_address="Unknown",
                    message="Device not found",
                    integration_results=[],
                    errors=["Device not found"],
                )

            if device.status != DeviceStatus.QUARANTINED:
                return QuarantineResult(
                    success=False,
                    device_id=device_id,
                    device_name=device.hostname or device.mac_address,
                    mac_address=device.mac_address,
                    message="Device is not quarantined",
                    integration_results=[],
                    errors=["Device is not quarantined"],
                )

            # Get device's primary IP
            device_ip = device.ip_addresses[0] if device.ip_addresses else None

            # Unblock via AdGuard Home
            if self._adguard.is_enabled:
                adguard_result = await self._adguard.unblock_device(
                    mac_address=device.mac_address,
                    ip_address=device_ip,
                )
                integration_results.append(adguard_result.to_dict())

                if not adguard_result.success:
                    errors.append(f"AdGuard: {adguard_result.error}")

                # Log integration action
                await self._audit.log_integration_action(
                    action=AuditAction.INTEGRATION_UNBLOCK,
                    integration_type="adguard_home",
                    target=device.mac_address,
                    user=user,
                    success=adguard_result.success,
                    details=adguard_result.to_dict(),
                    error_message=adguard_result.error,
                )

            # Unblock via router integration (UniFi, pfSense, etc.)
            if self._router and self._router.is_enabled:
                router_result = await self._router.unblock_device(
                    mac_address=device.mac_address,
                    ip_address=device_ip,
                )
                integration_results.append(router_result.to_dict())

                if not router_result.success:
                    errors.append(
                        f"{router_result.integration_type.value}: {router_result.error}"
                    )

                # Log integration action
                await self._audit.log_integration_action(
                    action=AuditAction.INTEGRATION_UNBLOCK,
                    integration_type=router_result.integration_type.value,
                    target=device.mac_address,
                    user=user,
                    success=router_result.success,
                    details=router_result.to_dict(),
                    error_message=router_result.error,
                )

            # Update device status
            device.status = DeviceStatus.ACTIVE
            await session.commit()
            await session.refresh(device)

            # Create audit log
            await self._audit.log_device_release(
                device_id=UUID(str(device.id)),
                device_name=device.hostname or device.mac_address,
                mac_address=device.mac_address,
                user=user,
                reason=reason,
                integration_results=integration_results,
                ip_address=ip_address,
            )

            logger.info(
                "Device released from quarantine",
                device_id=str(device.id),
                mac=device.mac_address,
                user=user.username,
                reason=reason,
            )

            return QuarantineResult(
                success=True,
                device_id=UUID(str(device.id)),
                device_name=device.hostname or device.mac_address,
                mac_address=device.mac_address,
                message="Device released from quarantine" + (
                    f" with {len(errors)} integration warning(s)" if errors else ""
                ),
                integration_results=integration_results,
                errors=errors,
            )

        except Exception as e:
            await session.rollback()
            logger.error(
                "Failed to release device",
                device_id=str(device_id),
                error=str(e),
            )
            return QuarantineResult(
                success=False,
                device_id=device_id,
                device_name="Unknown",
                mac_address="Unknown",
                message="Failed to release device",
                integration_results=integration_results,
                errors=[str(e)],
            )
        finally:
            await self._close_session(session)

    async def get_quarantined_devices(self) -> list[dict[str, Any]]:
        """Get all quarantined devices with their status."""
        session = await self._get_session()
        try:
            result = await session.execute(
                select(Device).where(Device.status == DeviceStatus.QUARANTINED)
            )
            devices = result.scalars().all()

            quarantined = []
            for device in devices:
                # Check AdGuard status
                adguard_blocked = False
                if self._adguard.is_enabled:
                    adguard_blocked = await self._adguard.is_device_blocked(
                        device.mac_address,
                        device.ip_addresses[0] if device.ip_addresses else None,
                    )

                # Check router status
                router_blocked = False
                router_type = None
                if self._router and self._router.is_enabled:
                    router_blocked = await self._router.is_device_blocked(
                        device.mac_address
                    )
                    router_type = self._router.integration_type.value

                quarantined.append({
                    "device_id": str(device.id),
                    "hostname": device.hostname,
                    "mac_address": device.mac_address,
                    "ip_addresses": device.ip_addresses,
                    "adguard_blocked": adguard_blocked,
                    "router_blocked": router_blocked,
                    "router_type": router_type,
                })

            return quarantined

        finally:
            await self._close_session(session)

    async def sync_quarantine_status(self) -> dict[str, Any]:
        """Sync quarantine status between database and integrations.

        This ensures that devices marked as quarantined in the DB
        are actually blocked in the integrations, and vice versa.

        Returns:
            Summary of sync actions taken
        """
        session = await self._get_session()
        checked: int = 0
        synced: int = 0
        errors: list[str] = []

        try:
            # Get all quarantined devices from DB
            result = await session.execute(
                select(Device).where(Device.status == DeviceStatus.QUARANTINED)
            )
            quarantined_devices = result.scalars().all()

            for device in quarantined_devices:
                checked += 1
                device_ip = device.ip_addresses[0] if device.ip_addresses else None

                # Sync with AdGuard
                if self._adguard.is_enabled:
                    is_blocked = await self._adguard.is_device_blocked(
                        device.mac_address,
                        device_ip,
                    )

                    if not is_blocked:
                        # Re-block in AdGuard
                        block_result = await self._adguard.block_device(
                            device.mac_address,
                            device_ip,
                            reason="Quarantine sync",
                        )

                        if block_result.success:
                            synced += 1
                            logger.info(
                                "Synced quarantine to AdGuard",
                                mac=device.mac_address,
                            )
                        else:
                            errors.append(
                                f"AdGuard sync failed for {device.mac_address}: {block_result.error}"
                            )

                # Sync with router integration
                if self._router and self._router.is_enabled:
                    is_blocked = await self._router.is_device_blocked(device.mac_address)

                    if not is_blocked:
                        # Re-block via router
                        block_result = await self._router.block_device(
                            mac_address=device.mac_address,
                            ip_address=device_ip,
                            reason="Quarantine sync",
                        )

                        if block_result.success:
                            synced += 1
                            logger.info(
                                "Synced quarantine to router",
                                mac=device.mac_address,
                                router=self._router.integration_type.value,
                            )
                        else:
                            errors.append(
                                f"Router sync failed for {device.mac_address}: {block_result.error}"
                            )

            return {"checked": checked, "synced": synced, "errors": errors}

        finally:
            await self._close_session(session)


# Global service instance
_quarantine_service: QuarantineService | None = None


def get_quarantine_service() -> QuarantineService:
    """Get the global quarantine service instance."""
    global _quarantine_service
    if _quarantine_service is None:
        _quarantine_service = QuarantineService()
    return _quarantine_service
