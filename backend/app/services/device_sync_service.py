"""Device sync service for syncing device names from external sources like AdGuard Home."""

from dataclasses import dataclass

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.device import Device
from app.services.integrations.adguard import get_adguard_service

logger = structlog.get_logger()


@dataclass
class DeviceSyncResult:
    """Result of a device sync operation."""

    total_devices: int
    updated_devices: int
    skipped_devices: int
    source: str
    details: list[dict[str, str]]


class DeviceSyncService:
    """Service for syncing device information from external sources."""

    async def sync_from_adguard(
        self,
        session: AsyncSession | None = None,
        overwrite_existing: bool = False,
    ) -> DeviceSyncResult:
        """Sync device names from AdGuard Home clients.

        This matches AdGuard Home clients to NetGuardian devices by:
        1. IP address match
        2. MAC address match

        Args:
            session: Optional database session. If not provided, creates a new one.
            overwrite_existing: If True, overwrites existing hostnames. If False,
                               only updates devices with no hostname set.

        Returns:
            DeviceSyncResult with sync statistics.
        """
        adguard = get_adguard_service()

        if not adguard.is_enabled:
            logger.warning("AdGuard Home integration not enabled for device sync")
            return DeviceSyncResult(
                total_devices=0,
                updated_devices=0,
                skipped_devices=0,
                source="adguard",
                details=[],
            )

        # Get device name mapping from AdGuard
        name_mapping = await adguard.get_device_name_mapping()

        if not name_mapping:
            logger.info("No device names found in AdGuard Home")
            return DeviceSyncResult(
                total_devices=0,
                updated_devices=0,
                skipped_devices=0,
                source="adguard",
                details=[],
            )

        logger.info("AdGuard device mapping fetched", count=len(name_mapping))

        # Get all devices from database
        owns_session = session is None
        if owns_session:
            session = AsyncSessionLocal()

        assert session is not None  # Type narrowing for mypy

        try:
            result = await session.execute(select(Device))
            devices = list(result.scalars().all())

            total_devices = len(devices)
            updated_count = 0
            skipped_count = 0
            details: list[dict[str, str]] = []

            for device in devices:
                # Skip if device already has a hostname and we're not overwriting
                if device.hostname and not overwrite_existing:
                    skipped_count += 1
                    continue

                # Try to find a matching name
                matched_name = None
                matched_by = None

                # Try matching by IP addresses
                for ip in device.ip_addresses:
                    if ip in name_mapping:
                        matched_name = name_mapping[ip]
                        matched_by = f"ip:{ip}"
                        break

                # Try matching by MAC address if no IP match
                if not matched_name:
                    normalized_mac = device.mac_address.lower().replace("-", ":")
                    if normalized_mac in name_mapping:
                        matched_name = name_mapping[normalized_mac]
                        matched_by = f"mac:{device.mac_address}"

                if matched_name:
                    old_hostname = device.hostname
                    device.hostname = matched_name
                    updated_count += 1

                    details.append(
                        {
                            "device_id": str(device.id),
                            "mac_address": device.mac_address,
                            "old_hostname": old_hostname or "(none)",
                            "new_hostname": matched_name,
                            "matched_by": matched_by or "",
                        }
                    )

                    logger.debug(
                        "Device hostname updated",
                        device_id=str(device.id),
                        old_hostname=old_hostname,
                        new_hostname=matched_name,
                        matched_by=matched_by,
                    )

            if owns_session:
                await session.commit()

            logger.info(
                "Device sync from AdGuard completed",
                total=total_devices,
                updated=updated_count,
                skipped=skipped_count,
            )

            return DeviceSyncResult(
                total_devices=total_devices,
                updated_devices=updated_count,
                skipped_devices=skipped_count,
                source="adguard",
                details=details,
            )

        except Exception as e:
            logger.error("Error syncing devices from AdGuard", error=str(e))
            if owns_session:
                await session.rollback()
            raise
        finally:
            if owns_session:
                await session.close()


# Global service instance
_device_sync_service: DeviceSyncService | None = None


def get_device_sync_service() -> DeviceSyncService:
    """Get the global device sync service instance."""
    global _device_sync_service
    if _device_sync_service is None:
        _device_sync_service = DeviceSyncService()
    return _device_sync_service
