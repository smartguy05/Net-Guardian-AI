"""Application log baseline service for tracking error rates and patterns."""

import statistics
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.raw_event import EventSeverity, EventType, RawEvent

logger = structlog.get_logger()

# Cache TTL for app baselines (5 minutes)
APP_BASELINE_CACHE_TTL_SECONDS = 300

# In-memory cache for device app baselines
# NOTE: This cache is process-local and not shared across workers.
# For multi-worker deployments, consider using Redis caching instead.
# See clear_device_baseline_cache() to manually invalidate entries.
_device_baseline_cache: dict[UUID, tuple[datetime, "DeviceAppBaselines"]] = {}


@dataclass
class DeviceAppBaselines:
    """Combined baselines for a device's application logs.

    Calculated from a single event fetch for efficiency.
    """

    device_id: UUID
    error_metrics: dict[str, Any] = field(default_factory=dict)
    container_metrics: dict[str, Any] = field(default_factory=dict)
    exception_metrics: dict[str, Any] = field(default_factory=dict)
    total_events: int = 0
    container_event_count: int = 0
    application_event_count: int = 0
    last_calculated: datetime = field(default_factory=lambda: datetime.now(UTC))


class AppBaseline:
    """Container for application baseline data (in-memory, not persisted)."""

    def __init__(
        self,
        source_id: str | None,
        metrics: dict[str, Any],
        sample_count: int,
        last_calculated: datetime,
        device_id: UUID | None = None,
    ):
        self.source_id = source_id
        self.device_id = device_id
        self.metrics = metrics
        self.sample_count = sample_count
        self.last_calculated = last_calculated


class AppBaselineCalculator:
    """Calculate baselines for application logs."""

    def __init__(self, session: AsyncSession):
        self._session = session

    async def calculate_error_rate_baseline(
        self,
        source_id: str,
        window_days: int = 7,
    ) -> AppBaseline:
        """Calculate error rate baseline for a log source.

        Tracks:
        - Hourly error counts
        - Error rate (errors per total events)
        - Error types and frequencies
        - Daily error patterns

        Args:
            source_id: Log source ID to analyze.
            window_days: Number of days to analyze.

        Returns:
            AppBaseline with error rate metrics.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch application events for this source
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.source_id == source_id)
            .where(
                RawEvent.event_type.in_(
                    [
                        EventType.CONTAINER,
                        EventType.JOURNAL,
                        EventType.APPLICATION,
                    ]
                )
            )
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = list(result.scalars().all())

        metrics = self._calculate_error_metrics(events)

        return AppBaseline(
            source_id=source_id,
            metrics=metrics,
            sample_count=len(events),
            last_calculated=datetime.now(UTC),
        )

    def _calculate_error_metrics(self, events: Sequence[RawEvent]) -> dict[str, Any]:
        """Calculate error-specific metrics."""
        if not events:
            return {
                "error_count": 0,
                "total_events": 0,
                "error_rate": 0.0,
                "hourly_error_mean": 0.0,
                "hourly_error_std": 0.0,
                "daily_error_counts": [],
                "error_types": {},
                "severity_distribution": {},
            }

        # Count errors and track patterns
        error_count = 0
        hourly_errors: dict[str, int] = defaultdict(int)
        daily_errors: dict[str, int] = defaultdict(int)
        error_types: Counter[str] = Counter()
        severity_dist: Counter[str] = Counter()

        for event in events:
            severity_dist[event.severity.value] += 1

            # Count errors (WARNING and above)
            if event.severity in (
                EventSeverity.WARNING,
                EventSeverity.ERROR,
                EventSeverity.CRITICAL,
            ):
                error_count += 1
                hour_key = event.timestamp.strftime("%Y-%m-%d-%H")
                day_key = event.timestamp.strftime("%Y-%m-%d")
                hourly_errors[hour_key] += 1
                daily_errors[day_key] += 1

                # Track error type from parsed fields
                error_type = event.parsed_fields.get("exception_type")
                if error_type:
                    error_types[error_type] += 1
                elif event.parsed_fields.get("container_event") == "oom_killed":
                    error_types["OOM Killed"] += 1
                elif event.parsed_fields.get("exit_code", 0) != 0:
                    error_types[f"Exit Code {event.parsed_fields.get('exit_code')}"] += 1

        # Calculate hourly statistics
        hourly_values = list(hourly_errors.values()) if hourly_errors else [0]
        hourly_mean = statistics.mean(hourly_values)
        hourly_std = statistics.stdev(hourly_values) if len(hourly_values) > 1 else 0.0

        return {
            "error_count": error_count,
            "total_events": len(events),
            "error_rate": error_count / len(events) if events else 0.0,
            "hourly_error_mean": hourly_mean,
            "hourly_error_std": hourly_std,
            "daily_error_counts": list(daily_errors.values())[-30:],
            "error_types": dict(error_types.most_common(50)),
            "severity_distribution": dict(severity_dist),
        }

    async def calculate_container_baseline(
        self,
        source_id: str,
        window_days: int = 7,
    ) -> AppBaseline:
        """Calculate container-specific baseline.

        Tracks:
        - Container restart counts
        - OOM kill events
        - Exit codes distribution
        - Container event patterns

        Args:
            source_id: Log source ID to analyze.
            window_days: Number of days to analyze.

        Returns:
            AppBaseline with container metrics.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch container events
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.source_id == source_id)
            .where(RawEvent.event_type == EventType.CONTAINER)
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = list(result.scalars().all())

        metrics = self._calculate_container_metrics(events)

        return AppBaseline(
            source_id=source_id,
            metrics=metrics,
            sample_count=len(events),
            last_calculated=datetime.now(UTC),
        )

    def _calculate_container_metrics(self, events: Sequence[RawEvent]) -> dict[str, Any]:
        """Calculate container-specific metrics."""
        if not events:
            return {
                "restart_count": 0,
                "oom_kill_count": 0,
                "exit_codes": {},
                "containers": {},
                "daily_restart_counts": [],
                "daily_restart_mean": 0.0,
                "daily_restart_std": 0.0,
            }

        restart_count = 0
        oom_count = 0
        exit_codes: Counter[int] = Counter()
        container_events: dict[str, Counter[str]] = defaultdict(Counter)
        daily_restarts: dict[str, int] = defaultdict(int)

        for event in events:
            container_name = event.parsed_fields.get("container_name", "unknown")
            container_event = event.parsed_fields.get("container_event")

            if container_event:
                container_events[container_name][container_event] += 1

                if container_event == "restart":
                    restart_count += 1
                    day_key = event.timestamp.strftime("%Y-%m-%d")
                    daily_restarts[day_key] += 1
                elif container_event == "oom_killed":
                    oom_count += 1

            exit_code = event.parsed_fields.get("exit_code")
            if exit_code is not None:
                exit_codes[exit_code] += 1

        # Calculate restart statistics
        restart_values = list(daily_restarts.values()) if daily_restarts else [0]
        restart_mean = statistics.mean(restart_values)
        restart_std = statistics.stdev(restart_values) if len(restart_values) > 1 else 0.0

        return {
            "restart_count": restart_count,
            "oom_kill_count": oom_count,
            "exit_codes": dict(exit_codes),
            "containers": {name: dict(events) for name, events in container_events.items()},
            "daily_restart_counts": list(daily_restarts.values())[-30:],
            "daily_restart_mean": restart_mean,
            "daily_restart_std": restart_std,
        }

    async def calculate_exception_baseline(
        self,
        source_id: str,
        window_days: int = 7,
    ) -> AppBaseline:
        """Calculate exception/stack trace baseline.

        Tracks:
        - Known exception types
        - Exception frequencies
        - New vs known exceptions

        Args:
            source_id: Log source ID to analyze.
            window_days: Number of days to analyze.

        Returns:
            AppBaseline with exception metrics.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch application events with exceptions
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.source_id == source_id)
            .where(RawEvent.event_type == EventType.APPLICATION)
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = list(result.scalars().all())

        metrics = self._calculate_exception_metrics(events)

        return AppBaseline(
            source_id=source_id,
            metrics=metrics,
            sample_count=len(events),
            last_calculated=datetime.now(UTC),
        )

    def _calculate_exception_metrics(self, events: Sequence[RawEvent]) -> dict[str, Any]:
        """Calculate exception-specific metrics."""
        exception_types: Counter[str] = Counter()
        exception_messages: Counter[str] = Counter()
        root_causes: Counter[str] = Counter()
        has_security_issues = 0

        for event in events:
            exc_type = event.parsed_fields.get("exception_type")
            if exc_type:
                exception_types[exc_type] += 1

            exc_msg = event.parsed_fields.get("exception_message", "")
            if exc_msg:
                # Normalize message (first 100 chars)
                exception_messages[exc_msg[:100]] += 1

            root_cause = event.parsed_fields.get("root_cause", {})
            if isinstance(root_cause, dict) and root_cause.get("exception_type"):
                root_causes[root_cause["exception_type"]] += 1

            if event.parsed_fields.get("security_issues"):
                has_security_issues += 1

        return {
            "known_exception_types": list(exception_types.keys()),
            "exception_type_counts": dict(exception_types.most_common(50)),
            "exception_message_counts": dict(exception_messages.most_common(20)),
            "root_cause_counts": dict(root_causes.most_common(20)),
            "security_issue_count": has_security_issues,
            "total_exceptions": sum(exception_types.values()),
        }

    # Device-based calculation methods (query by device_id instead of source_id)

    async def calculate_error_rate_baseline_for_device(
        self,
        device_id: UUID,
        window_days: int = 7,
    ) -> AppBaseline:
        """Calculate error rate baseline for a device.

        Tracks:
        - Hourly error counts
        - Error rate (errors per total events)
        - Error types and frequencies
        - Daily error patterns

        Args:
            device_id: Device UUID to analyze.
            window_days: Number of days to analyze.

        Returns:
            AppBaseline with error rate metrics.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch application events for this device
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(
                RawEvent.event_type.in_(
                    [
                        EventType.CONTAINER,
                        EventType.JOURNAL,
                        EventType.APPLICATION,
                    ]
                )
            )
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = list(result.scalars().all())

        metrics = self._calculate_error_metrics(events)

        return AppBaseline(
            source_id=None,
            device_id=device_id,
            metrics=metrics,
            sample_count=len(events),
            last_calculated=datetime.now(UTC),
        )

    async def calculate_container_baseline_for_device(
        self,
        device_id: UUID,
        window_days: int = 7,
    ) -> AppBaseline:
        """Calculate container-specific baseline for a device.

        Tracks:
        - Container restart counts
        - OOM kill events
        - Exit codes distribution
        - Container event patterns

        Args:
            device_id: Device UUID to analyze.
            window_days: Number of days to analyze.

        Returns:
            AppBaseline with container metrics.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch container events for this device
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(RawEvent.event_type == EventType.CONTAINER)
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = list(result.scalars().all())

        metrics = self._calculate_container_metrics(events)

        return AppBaseline(
            source_id=None,
            device_id=device_id,
            metrics=metrics,
            sample_count=len(events),
            last_calculated=datetime.now(UTC),
        )

    async def calculate_exception_baseline_for_device(
        self,
        device_id: UUID,
        window_days: int = 7,
    ) -> AppBaseline:
        """Calculate exception/stack trace baseline for a device.

        Tracks:
        - Known exception types
        - Exception frequencies
        - New vs known exceptions

        Args:
            device_id: Device UUID to analyze.
            window_days: Number of days to analyze.

        Returns:
            AppBaseline with exception metrics.
        """
        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch application events with exceptions for this device
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(RawEvent.event_type == EventType.APPLICATION)
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        events = list(result.scalars().all())

        metrics = self._calculate_exception_metrics(events)

        return AppBaseline(
            source_id=None,
            device_id=device_id,
            metrics=metrics,
            sample_count=len(events),
            last_calculated=datetime.now(UTC),
        )

    async def calculate_all_baselines_for_device(
        self,
        device_id: UUID,
        window_days: int = 7,
        use_cache: bool = True,
    ) -> DeviceAppBaselines:
        """Calculate all application baselines for a device in a single query.

        This is more efficient than calling the individual methods separately
        as it fetches all events once and calculates all metrics from that data.

        Args:
            device_id: Device UUID to analyze.
            window_days: Number of days to analyze.
            use_cache: Whether to use cached results if available.

        Returns:
            DeviceAppBaselines with all metrics.
        """
        # Check cache first
        if use_cache and device_id in _device_baseline_cache:
            cached_time, cached_baselines = _device_baseline_cache[device_id]
            age_seconds = (datetime.now(UTC) - cached_time).total_seconds()
            if age_seconds < APP_BASELINE_CACHE_TTL_SECONDS:
                logger.debug(
                    "app_baseline_cache_hit",
                    device_id=str(device_id),
                    age_seconds=age_seconds,
                )
                return cached_baselines

        cutoff = datetime.now(UTC) - timedelta(days=window_days)

        # Fetch ALL application events for this device in one query
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(
                RawEvent.event_type.in_(
                    [
                        EventType.CONTAINER,
                        EventType.JOURNAL,
                        EventType.APPLICATION,
                    ]
                )
            )
            .where(RawEvent.timestamp >= cutoff)
            .order_by(RawEvent.timestamp)
        )
        all_events = list(result.scalars().all())

        # Split events by type for specialized calculations
        container_events = [e for e in all_events if e.event_type == EventType.CONTAINER]
        application_events = [e for e in all_events if e.event_type == EventType.APPLICATION]

        # Calculate all metrics from the fetched events
        error_metrics = self._calculate_error_metrics(all_events)
        container_metrics = self._calculate_container_metrics(container_events)
        exception_metrics = self._calculate_exception_metrics(application_events)

        baselines = DeviceAppBaselines(
            device_id=device_id,
            error_metrics=error_metrics,
            container_metrics=container_metrics,
            exception_metrics=exception_metrics,
            total_events=len(all_events),
            container_event_count=len(container_events),
            application_event_count=len(application_events),
            last_calculated=datetime.now(UTC),
        )

        # Cache the result
        _device_baseline_cache[device_id] = (datetime.now(UTC), baselines)
        logger.debug(
            "app_baseline_calculated",
            device_id=str(device_id),
            total_events=len(all_events),
            container_events=len(container_events),
            application_events=len(application_events),
        )

        return baselines


def clear_device_baseline_cache(device_id: UUID | None = None) -> int:
    """Clear the app baseline cache.

    Args:
        device_id: If provided, only clear cache for this device.
                   If None, clear all cached baselines.

    Returns:
        Number of cache entries cleared.
    """
    if device_id is not None:
        if device_id in _device_baseline_cache:
            del _device_baseline_cache[device_id]
            return 1
        return 0
    else:
        count = len(_device_baseline_cache)
        _device_baseline_cache.clear()
        return count


class AppBaselineService:
    """High-level service for application log baselines."""

    async def get_error_baseline(
        self,
        source_id: str,
        window_days: int = 7,
    ) -> AppBaseline:
        """Get error rate baseline for a log source."""
        async with AsyncSessionLocal() as session:
            calculator = AppBaselineCalculator(session)
            return await calculator.calculate_error_rate_baseline(source_id, window_days)

    async def get_container_baseline(
        self,
        source_id: str,
        window_days: int = 7,
    ) -> AppBaseline:
        """Get container baseline for a log source."""
        async with AsyncSessionLocal() as session:
            calculator = AppBaselineCalculator(session)
            return await calculator.calculate_container_baseline(source_id, window_days)

    async def get_exception_baseline(
        self,
        source_id: str,
        window_days: int = 7,
    ) -> AppBaseline:
        """Get exception baseline for a log source."""
        async with AsyncSessionLocal() as session:
            calculator = AppBaselineCalculator(session)
            return await calculator.calculate_exception_baseline(source_id, window_days)

    async def check_error_spike(
        self,
        source_id: str,
        window_hours: int = 1,
        threshold_z_score: float = 2.0,
    ) -> dict[str, Any]:
        """Check if current error rate is abnormally high.

        Args:
            source_id: Log source ID to check.
            window_hours: Recent window to analyze.
            threshold_z_score: Z-score threshold for spike detection.

        Returns:
            Dict with spike detection results.
        """
        async with AsyncSessionLocal() as session:
            # Get baseline
            calculator = AppBaselineCalculator(session)
            baseline = await calculator.calculate_error_rate_baseline(source_id, window_days=7)

            # Get recent error count
            cutoff = datetime.now(UTC) - timedelta(hours=window_hours)
            result = await session.execute(
                select(func.count())
                .where(RawEvent.source_id == source_id)
                .where(
                    RawEvent.event_type.in_(
                        [
                            EventType.CONTAINER,
                            EventType.JOURNAL,
                            EventType.APPLICATION,
                        ]
                    )
                )
                .where(
                    RawEvent.severity.in_(
                        [
                            EventSeverity.WARNING,
                            EventSeverity.ERROR,
                            EventSeverity.CRITICAL,
                        ]
                    )
                )
                .where(RawEvent.timestamp >= cutoff)
            )
            recent_errors = result.scalar() or 0

            # Calculate Z-score
            hourly_mean = baseline.metrics.get("hourly_error_mean", 0)
            hourly_std = baseline.metrics.get("hourly_error_std", 1)

            # Normalize to hourly rate
            current_hourly = recent_errors / max(window_hours, 1)

            if hourly_std > 0:
                z_score = (current_hourly - hourly_mean) / hourly_std
            else:
                z_score = 0 if current_hourly <= hourly_mean else 3.0

            is_spike = z_score >= threshold_z_score

            return {
                "is_spike": is_spike,
                "z_score": z_score,
                "current_hourly_errors": current_hourly,
                "baseline_hourly_mean": hourly_mean,
                "baseline_hourly_std": hourly_std,
                "recent_error_count": recent_errors,
                "window_hours": window_hours,
            }

    async def check_new_exceptions(
        self,
        source_id: str,
        window_hours: int = 1,
    ) -> dict[str, Any]:
        """Check for new exception types not seen in baseline.

        Args:
            source_id: Log source ID to check.
            window_hours: Recent window to analyze.

        Returns:
            Dict with new exception detection results.
        """
        async with AsyncSessionLocal() as session:
            # Get baseline
            calculator = AppBaselineCalculator(session)
            baseline = await calculator.calculate_exception_baseline(source_id, window_days=7)

            known_types = baseline.metrics.get("known_exception_types", set())

            # Get recent exceptions
            cutoff = datetime.now(UTC) - timedelta(hours=window_hours)
            result = await session.execute(
                select(RawEvent)
                .where(RawEvent.source_id == source_id)
                .where(RawEvent.event_type == EventType.APPLICATION)
                .where(RawEvent.timestamp >= cutoff)
            )
            recent_events = result.scalars().all()

            # Find new exception types
            new_exceptions: list[dict[str, Any]] = []
            for event in recent_events:
                exc_type = event.parsed_fields.get("exception_type")
                if exc_type and exc_type not in known_types:
                    new_exceptions.append(
                        {
                            "exception_type": exc_type,
                            "message": event.parsed_fields.get("exception_message", "")[:200],
                            "timestamp": event.timestamp.isoformat(),
                        }
                    )

            return {
                "has_new_exceptions": len(new_exceptions) > 0,
                "new_exception_count": len(new_exceptions),
                "new_exceptions": new_exceptions[:20],  # Limit to 20
                "known_exception_count": len(known_types),
            }

    async def check_container_restarts(
        self,
        source_id: str,
        window_hours: int = 1,
        threshold_multiplier: float = 3.0,
    ) -> dict[str, Any]:
        """Check for abnormal container restart patterns.

        Args:
            source_id: Log source ID to check.
            window_hours: Recent window to analyze.
            threshold_multiplier: How many times normal to trigger alert.

        Returns:
            Dict with restart anomaly detection results.
        """
        async with AsyncSessionLocal() as session:
            # Get baseline
            calculator = AppBaselineCalculator(session)
            baseline = await calculator.calculate_container_baseline(source_id, window_days=7)

            daily_mean = baseline.metrics.get("daily_restart_mean", 0)

            # Get recent restarts
            cutoff = datetime.now(UTC) - timedelta(hours=window_hours)
            result = await session.execute(
                select(RawEvent)
                .where(RawEvent.source_id == source_id)
                .where(RawEvent.event_type == EventType.CONTAINER)
                .where(RawEvent.timestamp >= cutoff)
            )
            recent_events = result.scalars().all()

            # Count restarts and OOM kills
            restart_count = 0
            oom_count = 0
            restart_containers: list[str] = []

            for event in recent_events:
                container_event = event.parsed_fields.get("container_event")
                if container_event == "restart":
                    restart_count += 1
                    container_name = event.parsed_fields.get("container_name")
                    if container_name:
                        restart_containers.append(container_name)
                elif container_event == "oom_killed":
                    oom_count += 1

            # Normalize to daily rate for comparison
            hours_in_day = 24
            expected_hourly = daily_mean / hours_in_day
            expected_in_window = expected_hourly * window_hours

            is_anomaly = restart_count > max(expected_in_window * threshold_multiplier, 3)

            return {
                "is_anomaly": is_anomaly,
                "restart_count": restart_count,
                "oom_count": oom_count,
                "restart_containers": list(set(restart_containers)),
                "expected_in_window": expected_in_window,
                "baseline_daily_mean": daily_mean,
                "window_hours": window_hours,
            }


# Global service instance
_app_baseline_service: AppBaselineService | None = None


def get_app_baseline_service() -> AppBaselineService:
    """Get the global app baseline service instance."""
    global _app_baseline_service
    if _app_baseline_service is None:
        _app_baseline_service = AppBaselineService()
    return _app_baseline_service
