"""Baseline calculator service for device behavioral profiling."""

import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from collections.abc import Sequence
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.device import Device
from app.models.device_baseline import BaselineStatus, BaselineType, DeviceBaseline
from app.models.raw_event import EventType, RawEvent

logger = structlog.get_logger()


class BaselineCalculator:
    """Service for calculating device behavioral baselines."""

    def __init__(self, session: AsyncSession):
        self._session = session

    async def calculate_dns_baseline(
        self,
        device_id: UUID,
        window_days: int = 7,
        min_samples: int = 100,
    ) -> DeviceBaseline:
        """Calculate DNS behavioral baseline for a device.

        Tracks:
        - Unique domains queried
        - Query frequency patterns (hourly distribution)
        - Top domains and their frequencies
        - Query volume statistics (mean, std dev)

        Args:
            device_id: Device UUID.
            window_days: Number of days to analyze.
            min_samples: Minimum samples needed for ready status.

        Returns:
            Updated or created DeviceBaseline.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch DNS events for this device
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(RawEvent.event_type == EventType.DNS)
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = result.scalars().all()

        # Calculate metrics
        metrics = self._calculate_dns_metrics(events)
        sample_count = len(events)

        # Get or create baseline
        baseline = await self._get_or_create_baseline(
            device_id, BaselineType.DNS, window_days, min_samples
        )

        # Update baseline
        baseline.metrics = metrics
        baseline.sample_count = sample_count
        baseline.last_calculated = datetime.now(UTC)
        baseline.status = self._determine_status(sample_count, min_samples, baseline)

        await self._session.flush()

        logger.info(
            "dns_baseline_calculated",
            device_id=str(device_id),
            sample_count=sample_count,
            status=baseline.status.value,
        )

        return baseline

    def _calculate_dns_metrics(self, events: Sequence[RawEvent]) -> dict[str, Any]:
        """Calculate DNS-specific metrics from events."""
        if not events:
            return {
                "unique_domains": [],
                "domain_frequencies": {},
                "hourly_distribution": [0] * 24,
                "daily_volumes": [],
                "volume_mean": 0.0,
                "volume_std": 0.0,
                "blocked_ratio": 0.0,
            }

        # Track domains
        domain_counter: Counter[str] = Counter()
        hourly_distribution = [0] * 24
        daily_volumes: dict[str, int] = defaultdict(int)
        blocked_count = 0

        for event in events:
            if event.domain:
                domain_counter[event.domain] += 1
            hourly_distribution[event.timestamp.hour] += 1
            daily_volumes[event.timestamp.date().isoformat()] += 1
            if event.action == "block":
                blocked_count += 1

        # Calculate statistics
        volumes = list(daily_volumes.values())
        volume_mean = statistics.mean(volumes) if volumes else 0.0
        volume_std = statistics.stdev(volumes) if len(volumes) > 1 else 0.0

        # Get top domains (limit to 100)
        top_domains = dict(domain_counter.most_common(100))

        return {
            "unique_domains": list(domain_counter.keys())[:500],  # Cap at 500
            "domain_frequencies": top_domains,
            "hourly_distribution": hourly_distribution,
            "daily_volumes": volumes[-30:],  # Last 30 days
            "volume_mean": volume_mean,
            "volume_std": volume_std,
            "blocked_ratio": blocked_count / len(events) if events else 0.0,
            "total_queries": len(events),
        }

    async def calculate_traffic_baseline(
        self,
        device_id: UUID,
        window_days: int = 7,
        min_samples: int = 100,
    ) -> DeviceBaseline:
        """Calculate traffic behavioral baseline for a device.

        Tracks:
        - Traffic volume patterns
        - Protocols used
        - Port distribution
        - Time-of-day patterns

        Args:
            device_id: Device UUID.
            window_days: Number of days to analyze.
            min_samples: Minimum samples needed for ready status.

        Returns:
            Updated or created DeviceBaseline.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch firewall/HTTP events for this device
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(RawEvent.event_type.in_([EventType.FIREWALL, EventType.HTTP]))
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = result.scalars().all()

        # Calculate metrics
        metrics = self._calculate_traffic_metrics(events)
        sample_count = len(events)

        # Get or create baseline
        baseline = await self._get_or_create_baseline(
            device_id, BaselineType.TRAFFIC, window_days, min_samples
        )

        # Update baseline
        baseline.metrics = metrics
        baseline.sample_count = sample_count
        baseline.last_calculated = datetime.now(UTC)
        baseline.status = self._determine_status(sample_count, min_samples, baseline)

        await self._session.flush()

        logger.info(
            "traffic_baseline_calculated",
            device_id=str(device_id),
            sample_count=sample_count,
            status=baseline.status.value,
        )

        return baseline

    def _calculate_traffic_metrics(self, events: Sequence[RawEvent]) -> dict[str, Any]:
        """Calculate traffic-specific metrics from events."""
        if not events:
            return {
                "protocol_distribution": {},
                "port_distribution": {},
                "hourly_distribution": [0] * 24,
                "daily_volumes": [],
                "volume_mean": 0.0,
                "volume_std": 0.0,
                "blocked_ratio": 0.0,
            }

        # Track patterns
        protocol_counter: Counter[str] = Counter()
        port_counter: Counter[str] = Counter()
        hourly_distribution = [0] * 24
        daily_volumes: dict[str, int] = defaultdict(int)
        blocked_count = 0

        for event in events:
            if event.protocol:
                protocol_counter[event.protocol] += 1
            if event.port:
                port_counter[str(event.port)] += 1
            hourly_distribution[event.timestamp.hour] += 1
            daily_volumes[event.timestamp.date().isoformat()] += 1
            if event.action in ("block", "drop", "deny"):
                blocked_count += 1

        # Calculate statistics
        volumes = list(daily_volumes.values())
        volume_mean = statistics.mean(volumes) if volumes else 0.0
        volume_std = statistics.stdev(volumes) if len(volumes) > 1 else 0.0

        return {
            "protocol_distribution": dict(protocol_counter),
            "port_distribution": dict(port_counter.most_common(50)),
            "hourly_distribution": hourly_distribution,
            "daily_volumes": volumes[-30:],
            "volume_mean": volume_mean,
            "volume_std": volume_std,
            "blocked_ratio": blocked_count / len(events) if events else 0.0,
            "total_events": len(events),
        }

    async def calculate_connection_baseline(
        self,
        device_id: UUID,
        window_days: int = 7,
        min_samples: int = 100,
    ) -> DeviceBaseline:
        """Calculate connection behavioral baseline for a device.

        Tracks:
        - Unique destination IPs
        - Connection patterns
        - External vs internal connections
        - Geographic patterns (if available)

        Args:
            device_id: Device UUID.
            window_days: Number of days to analyze.
            min_samples: Minimum samples needed for ready status.

        Returns:
            Updated or created DeviceBaseline.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch all events with target IPs for this device
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(RawEvent.target_ip.isnot(None))
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = result.scalars().all()

        # Calculate metrics
        metrics = self._calculate_connection_metrics(events)
        sample_count = len(events)

        # Get or create baseline
        baseline = await self._get_or_create_baseline(
            device_id, BaselineType.CONNECTION, window_days, min_samples
        )

        # Update baseline
        baseline.metrics = metrics
        baseline.sample_count = sample_count
        baseline.last_calculated = datetime.now(UTC)
        baseline.status = self._determine_status(sample_count, min_samples, baseline)

        await self._session.flush()

        logger.info(
            "connection_baseline_calculated",
            device_id=str(device_id),
            sample_count=sample_count,
            status=baseline.status.value,
        )

        return baseline

    def _calculate_connection_metrics(self, events: Sequence[RawEvent]) -> dict[str, Any]:
        """Calculate connection-specific metrics from events."""
        if not events:
            return {
                "unique_destinations": [],
                "destination_frequencies": {},
                "internal_external_ratio": 0.0,
                "port_distribution": {},
                "hourly_distribution": [0] * 24,
                "daily_connections": [],
                "connection_mean": 0.0,
                "connection_std": 0.0,
            }

        # Track patterns
        dest_counter: Counter[str] = Counter()
        port_counter: Counter[str] = Counter()
        hourly_distribution = [0] * 24
        daily_connections: dict[str, int] = defaultdict(int)
        internal_count = 0

        for event in events:
            if event.target_ip:
                dest_counter[event.target_ip] += 1
                if self._is_internal_ip(event.target_ip):
                    internal_count += 1
            if event.port:
                port_counter[str(event.port)] += 1
            hourly_distribution[event.timestamp.hour] += 1
            daily_connections[event.timestamp.date().isoformat()] += 1

        # Calculate statistics
        connections = list(daily_connections.values())
        connection_mean = statistics.mean(connections) if connections else 0.0
        connection_std = statistics.stdev(connections) if len(connections) > 1 else 0.0

        return {
            "unique_destinations": list(dest_counter.keys())[:500],
            "destination_frequencies": dict(dest_counter.most_common(100)),
            "internal_external_ratio": internal_count / len(events) if events else 0.0,
            "port_distribution": dict(port_counter.most_common(50)),
            "hourly_distribution": hourly_distribution,
            "daily_connections": connections[-30:],
            "connection_mean": connection_mean,
            "connection_std": connection_std,
            "total_connections": len(events),
        }

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if an IP address is internal/private."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])

            # RFC 1918 private ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:  # Loopback
                return True

            return False
        except (ValueError, IndexError):
            return False

    async def _get_or_create_baseline(
        self,
        device_id: UUID,
        baseline_type: BaselineType,
        window_days: int,
        min_samples: int,
    ) -> DeviceBaseline:
        """Get existing baseline or create a new one."""
        result = await self._session.execute(
            select(DeviceBaseline)
            .where(DeviceBaseline.device_id == device_id)
            .where(DeviceBaseline.baseline_type == baseline_type)
        )
        baseline = result.scalar_one_or_none()

        if baseline:
            baseline.baseline_window_days = window_days
            baseline.min_samples = min_samples
            return baseline

        baseline = DeviceBaseline(
            id=uuid4(),
            device_id=device_id,
            baseline_type=baseline_type,
            status=BaselineStatus.LEARNING,
            metrics={},
            sample_count=0,
            min_samples=min_samples,
            baseline_window_days=window_days,
        )
        self._session.add(baseline)
        return baseline

    def _determine_status(
        self,
        sample_count: int,
        min_samples: int,
        baseline: DeviceBaseline,
    ) -> BaselineStatus:
        """Determine baseline status based on sample count and age."""
        if sample_count < min_samples:
            return BaselineStatus.LEARNING

        # Check if baseline is stale (not updated in window period)
        if baseline.last_calculated:
            stale_threshold = datetime.now(UTC) - timedelta(
                days=baseline.baseline_window_days * 2
            )
            if baseline.last_calculated < stale_threshold:
                return BaselineStatus.STALE

        return BaselineStatus.READY

    async def calculate_all_baselines(
        self,
        device_id: UUID,
        window_days: int = 7,
        min_samples: int = 100,
    ) -> dict[str, DeviceBaseline]:
        """Calculate all baseline types for a device.

        Args:
            device_id: Device UUID.
            window_days: Number of days to analyze.
            min_samples: Minimum samples needed for ready status.

        Returns:
            Dict mapping baseline type to DeviceBaseline.
        """
        dns = await self.calculate_dns_baseline(device_id, window_days, min_samples)
        traffic = await self.calculate_traffic_baseline(
            device_id, window_days, min_samples
        )
        connection = await self.calculate_connection_baseline(
            device_id, window_days, min_samples
        )

        # Update device baseline_ready flag
        result = await self._session.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()
        if device:
            device.baseline_ready = all(
                b.status == BaselineStatus.READY for b in [dns, traffic, connection]
            )

        return {
            "dns": dns,
            "traffic": traffic,
            "connection": connection,
        }


class BaselineService:
    """High-level service for managing device baselines."""

    async def update_device_baseline(
        self,
        device_id: UUID,
        baseline_type: BaselineType | None = None,
    ) -> dict[str, DeviceBaseline]:
        """Update baselines for a specific device.

        Args:
            device_id: Device UUID.
            baseline_type: Specific type to update, or None for all.

        Returns:
            Updated baselines.
        """
        async with AsyncSessionLocal() as session:
            calculator = BaselineCalculator(session)

            if baseline_type:
                if baseline_type == BaselineType.DNS:
                    baseline = await calculator.calculate_dns_baseline(device_id)
                elif baseline_type == BaselineType.TRAFFIC:
                    baseline = await calculator.calculate_traffic_baseline(device_id)
                elif baseline_type == BaselineType.CONNECTION:
                    baseline = await calculator.calculate_connection_baseline(device_id)
                result = {baseline_type.value: baseline}
            else:
                result = await calculator.calculate_all_baselines(device_id)

            await session.commit()
            return result

    async def update_all_device_baselines(self) -> dict[str, int]:
        """Update baselines for all active devices.

        Returns:
            Dict with counts of updated baselines by status.
        """
        async with AsyncSessionLocal() as session:
            from app.models.device import DeviceStatus

            # Get all active devices
            result = await session.execute(
                select(Device).where(Device.status == DeviceStatus.ACTIVE)
            )
            devices = result.scalars().all()

            calculator = BaselineCalculator(session)
            stats = {"updated": 0, "learning": 0, "ready": 0, "stale": 0, "errors": 0}

            for device in devices:
                try:
                    baselines = await calculator.calculate_all_baselines(UUID(str(device.id)))
                    stats["updated"] += 1

                    # Count statuses
                    for baseline in baselines.values():
                        if baseline.status == BaselineStatus.LEARNING:
                            stats["learning"] += 1
                        elif baseline.status == BaselineStatus.READY:
                            stats["ready"] += 1
                        elif baseline.status == BaselineStatus.STALE:
                            stats["stale"] += 1

                except Exception as e:
                    logger.error(
                        "baseline_update_error",
                        device_id=str(device.id),
                        error=str(e),
                    )
                    stats["errors"] += 1

            await session.commit()

            logger.info("baseline_update_complete", **stats)
            return stats

    async def get_device_baselines(
        self,
        device_id: UUID,
    ) -> list[DeviceBaseline]:
        """Get all baselines for a device.

        Args:
            device_id: Device UUID.

        Returns:
            List of DeviceBaseline objects.
        """
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(DeviceBaseline).where(DeviceBaseline.device_id == device_id)
            )
            return list(result.scalars().all())

    async def get_baseline(
        self,
        device_id: UUID,
        baseline_type: BaselineType,
    ) -> DeviceBaseline | None:
        """Get a specific baseline for a device.

        Args:
            device_id: Device UUID.
            baseline_type: Type of baseline.

        Returns:
            DeviceBaseline or None.
        """
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(DeviceBaseline)
                .where(DeviceBaseline.device_id == device_id)
                .where(DeviceBaseline.baseline_type == baseline_type)
            )
            return result.scalar_one_or_none()


# Global service instance
_baseline_service: BaselineService | None = None


def get_baseline_service() -> BaselineService:
    """Get the global baseline service instance."""
    global _baseline_service
    if _baseline_service is None:
        _baseline_service = BaselineService()
    return _baseline_service
