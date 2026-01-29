"""Anomaly detection service for identifying behavioral deviations."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import AsyncSessionLocal
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.anomaly import AnomalyDetection, AnomalyStatus, AnomalyType
from app.models.device import Device
from app.models.device_baseline import BaselineStatus, BaselineType, DeviceBaseline
from app.models.raw_event import EventType, RawEvent

logger = structlog.get_logger()


# Threshold constants for anomaly detection
Z_SCORE_THRESHOLD = 2.0  # Standard threshold for anomaly
HIGH_Z_SCORE_THRESHOLD = 3.0  # Threshold for high severity
CRITICAL_Z_SCORE_THRESHOLD = 4.0  # Threshold for critical severity
NEW_ITEM_SCORE = 3.0  # Score for completely new items (domains, connections)


class AnomalyDetector:
    """Detects anomalies by comparing current behavior against baselines."""

    def __init__(self, session: AsyncSession):
        self._session = session

    async def detect_anomalies(
        self,
        device_id: UUID,
        time_window_hours: int = 1,
        auto_create_alerts: bool = True,
    ) -> list[AnomalyDetection]:
        """Detect anomalies for a device by comparing recent activity to baseline.

        Args:
            device_id: Device UUID.
            time_window_hours: Hours of recent activity to analyze.
            auto_create_alerts: Whether to auto-create alerts for anomalies.

        Returns:
            List of detected AnomalyDetection objects.
        """
        anomalies: list[AnomalyDetection] = []

        # Get device baselines
        result = await self._session.execute(
            select(DeviceBaseline)
            .where(DeviceBaseline.device_id == device_id)
            .where(DeviceBaseline.status == BaselineStatus.READY)
        )
        baselines = {b.baseline_type: b for b in result.scalars().all()}

        if not baselines:
            logger.debug(
                "no_ready_baselines",
                device_id=str(device_id),
            )
            return anomalies

        # Detect anomalies for each baseline type
        if BaselineType.DNS in baselines:
            dns_anomalies = await self._detect_dns_anomalies(
                device_id, baselines[BaselineType.DNS], time_window_hours
            )
            anomalies.extend(dns_anomalies)

        if BaselineType.TRAFFIC in baselines:
            traffic_anomalies = await self._detect_traffic_anomalies(
                device_id, baselines[BaselineType.TRAFFIC], time_window_hours
            )
            anomalies.extend(traffic_anomalies)

        if BaselineType.CONNECTION in baselines:
            connection_anomalies = await self._detect_connection_anomalies(
                device_id, baselines[BaselineType.CONNECTION], time_window_hours
            )
            anomalies.extend(connection_anomalies)

        # Save anomalies and optionally create alerts
        for anomaly in anomalies:
            self._session.add(anomaly)

            if auto_create_alerts and anomaly.severity in (
                AlertSeverity.HIGH,
                AlertSeverity.CRITICAL,
            ):
                alert = await self._create_alert_for_anomaly(anomaly)
                anomaly.alert_id = alert.id

        await self._session.flush()

        logger.info(
            "anomalies_detected",
            device_id=str(device_id),
            count=len(anomalies),
        )

        return anomalies

    async def _detect_dns_anomalies(
        self,
        device_id: UUID,
        baseline: DeviceBaseline,
        time_window_hours: int,
    ) -> list[AnomalyDetection]:
        """Detect DNS-related anomalies."""
        anomalies: list[AnomalyDetection] = []
        cutoff = datetime.now(UTC) - timedelta(hours=time_window_hours)

        # Get recent DNS events
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(RawEvent.event_type == EventType.DNS)
            .where(RawEvent.timestamp >= cutoff)
        )
        recent_events = result.scalars().all()

        if not recent_events:
            return anomalies

        metrics = baseline.metrics
        baseline_domains = set(metrics.get("unique_domains", []))
        baseline_volume_mean = metrics.get("volume_mean", 0)
        baseline_volume_std = metrics.get("volume_std", 1)  # Avoid division by zero
        baseline_blocked_ratio = metrics.get("blocked_ratio", 0)
        baseline_hourly = metrics.get("hourly_distribution", [0] * 24)

        # Detect new domains
        current_domains = {e.domain for e in recent_events if e.domain}
        new_domains = current_domains - baseline_domains

        if new_domains:
            # Calculate severity based on count and nature
            score = min(NEW_ITEM_SCORE + len(new_domains) * 0.5, 10.0)
            anomaly = self._create_anomaly(
                device_id=device_id,
                anomaly_type=AnomalyType.NEW_DOMAIN,
                score=score,
                description=f"Device queried {len(new_domains)} new domain(s) not seen in baseline",
                details={
                    "new_domains": list(new_domains)[:20],  # Cap at 20
                    "new_domain_count": len(new_domains),
                },
                baseline_comparison={
                    "baseline_domain_count": len(baseline_domains),
                    "new_percentage": (
                        len(new_domains) / len(current_domains) * 100
                        if current_domains
                        else 0
                    ),
                },
            )
            anomalies.append(anomaly)

        # Detect volume spike
        # Normalize to hourly rate for comparison
        hours_in_window = max(time_window_hours, 1)
        current_hourly_volume = len(recent_events) / hours_in_window
        expected_hourly = baseline_volume_mean / 24  # Convert daily to hourly

        if baseline_volume_std > 0 and expected_hourly > 0:
            z_score = (current_hourly_volume - expected_hourly) / (
                baseline_volume_std / 24
            )

            if z_score >= Z_SCORE_THRESHOLD:
                anomaly = self._create_anomaly(
                    device_id=device_id,
                    anomaly_type=AnomalyType.VOLUME_SPIKE,
                    score=abs(z_score),
                    description=f"DNS query volume {z_score:.1f} standard deviations above normal",
                    details={
                        "current_hourly_volume": current_hourly_volume,
                        "expected_hourly_volume": expected_hourly,
                        "z_score": z_score,
                    },
                    baseline_comparison={
                        "baseline_daily_mean": baseline_volume_mean,
                        "baseline_daily_std": baseline_volume_std,
                    },
                )
                anomalies.append(anomaly)

        # Detect time anomaly (unusual activity hours)
        current_hour = datetime.now(UTC).hour
        current_count = sum(1 for e in recent_events if e.timestamp.hour == current_hour)

        if baseline_hourly:
            total_baseline = sum(baseline_hourly)
            if total_baseline > 0:
                expected_ratio = baseline_hourly[current_hour] / total_baseline
                current_ratio = current_count / len(recent_events)

                # Significant deviation from expected hourly pattern
                if expected_ratio > 0 and current_ratio > 0:
                    ratio_change = current_ratio / expected_ratio
                    if ratio_change > 3.0:  # 3x more activity than expected for this hour
                        score = min(2.0 + ratio_change, 6.0)
                        anomaly = self._create_anomaly(
                            device_id=device_id,
                            anomaly_type=AnomalyType.TIME_ANOMALY,
                            score=score,
                            description=f"Unusual DNS activity at hour {current_hour}:00 - {ratio_change:.1f}x expected",
                            details={
                                "current_hour": current_hour,
                                "current_ratio": current_ratio,
                                "expected_ratio": expected_ratio,
                                "ratio_change": ratio_change,
                            },
                            baseline_comparison={
                                "baseline_hourly_distribution": baseline_hourly,
                            },
                        )
                        anomalies.append(anomaly)

        # Detect blocked spike
        blocked_count = sum(1 for e in recent_events if e.action == "block")
        current_blocked_ratio = blocked_count / len(recent_events) if recent_events else 0

        if baseline_blocked_ratio > 0:
            blocked_change = current_blocked_ratio / baseline_blocked_ratio
            if blocked_change > 2.0:  # 2x more blocks than baseline
                score = min(3.0 + blocked_change, 8.0)
                anomaly = self._create_anomaly(
                    device_id=device_id,
                    anomaly_type=AnomalyType.BLOCKED_SPIKE,
                    score=score,
                    description=f"Blocked DNS query ratio {blocked_change:.1f}x higher than baseline",
                    details={
                        "current_blocked_ratio": current_blocked_ratio,
                        "blocked_count": blocked_count,
                        "total_queries": len(recent_events),
                    },
                    baseline_comparison={
                        "baseline_blocked_ratio": baseline_blocked_ratio,
                    },
                )
                anomalies.append(anomaly)
        elif blocked_count > 10:  # Many blocks when baseline had none
            anomaly = self._create_anomaly(
                device_id=device_id,
                anomaly_type=AnomalyType.BLOCKED_SPIKE,
                score=4.0,
                description=f"{blocked_count} DNS queries blocked when baseline showed minimal blocking",
                details={
                    "current_blocked_ratio": current_blocked_ratio,
                    "blocked_count": blocked_count,
                },
                baseline_comparison={
                    "baseline_blocked_ratio": baseline_blocked_ratio,
                },
            )
            anomalies.append(anomaly)

        return anomalies

    async def _detect_traffic_anomalies(
        self,
        device_id: UUID,
        baseline: DeviceBaseline,
        time_window_hours: int,
    ) -> list[AnomalyDetection]:
        """Detect traffic-related anomalies."""
        anomalies: list[AnomalyDetection] = []
        cutoff = datetime.now(UTC) - timedelta(hours=time_window_hours)

        # Get recent traffic events
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(RawEvent.event_type.in_([EventType.FIREWALL, EventType.HTTP]))
            .where(RawEvent.timestamp >= cutoff)
        )
        recent_events = result.scalars().all()

        if not recent_events:
            return anomalies

        metrics = baseline.metrics
        baseline_ports = set(metrics.get("port_distribution", {}).keys())
        baseline_volume_mean = metrics.get("volume_mean", 0)
        baseline_volume_std = metrics.get("volume_std", 1)

        # Detect new ports
        current_ports = {str(e.port) for e in recent_events if e.port}
        new_ports = current_ports - baseline_ports

        # Filter for potentially suspicious new ports
        suspicious_new_ports = {p for p in new_ports if self._is_suspicious_port(int(p))}

        if suspicious_new_ports:
            score = min(NEW_ITEM_SCORE + len(suspicious_new_ports), 8.0)
            anomaly = self._create_anomaly(
                device_id=device_id,
                anomaly_type=AnomalyType.NEW_PORT,
                score=score,
                description=f"Traffic on {len(suspicious_new_ports)} new potentially suspicious port(s)",
                details={
                    "new_ports": list(suspicious_new_ports),
                    "all_new_ports": list(new_ports)[:20],
                },
                baseline_comparison={
                    "baseline_port_count": len(baseline_ports),
                    "baseline_ports": list(baseline_ports)[:20],
                },
            )
            anomalies.append(anomaly)

        # Detect volume spike
        hours_in_window = max(time_window_hours, 1)
        current_hourly_volume = len(recent_events) / hours_in_window
        expected_hourly = baseline_volume_mean / 24

        if baseline_volume_std > 0 and expected_hourly > 0:
            z_score = (current_hourly_volume - expected_hourly) / (
                baseline_volume_std / 24
            )

            if z_score >= Z_SCORE_THRESHOLD:
                anomaly = self._create_anomaly(
                    device_id=device_id,
                    anomaly_type=AnomalyType.VOLUME_SPIKE,
                    score=abs(z_score),
                    description=f"Traffic volume {z_score:.1f} standard deviations above normal",
                    details={
                        "current_hourly_volume": current_hourly_volume,
                        "expected_hourly_volume": expected_hourly,
                        "z_score": z_score,
                        "event_type": "traffic",
                    },
                    baseline_comparison={
                        "baseline_daily_mean": baseline_volume_mean,
                        "baseline_daily_std": baseline_volume_std,
                    },
                )
                anomalies.append(anomaly)

        return anomalies

    async def _detect_connection_anomalies(
        self,
        device_id: UUID,
        baseline: DeviceBaseline,
        time_window_hours: int,
    ) -> list[AnomalyDetection]:
        """Detect connection-related anomalies."""
        anomalies: list[AnomalyDetection] = []
        cutoff = datetime.now(UTC) - timedelta(hours=time_window_hours)

        # Get recent events with target IPs
        result = await self._session.execute(
            select(RawEvent)
            .where(RawEvent.device_id == device_id)
            .where(RawEvent.target_ip.isnot(None))
            .where(RawEvent.timestamp >= cutoff)
        )
        recent_events = result.scalars().all()

        if not recent_events:
            return anomalies

        metrics = baseline.metrics
        baseline_destinations = set(metrics.get("unique_destinations", []))
        baseline_connection_mean = metrics.get("connection_mean", 0)
        baseline_connection_std = metrics.get("connection_std", 1)
        baseline_internal_ratio = metrics.get("internal_external_ratio", 0.5)

        # Detect new connections (external IPs)
        current_destinations = {e.target_ip for e in recent_events if e.target_ip}
        new_destinations = current_destinations - baseline_destinations

        # Filter for external new destinations
        new_external = {d for d in new_destinations if not self._is_internal_ip(d)}

        if new_external and len(new_external) >= 3:  # Only alert if multiple new external
            score = min(NEW_ITEM_SCORE + len(new_external) * 0.3, 7.0)
            anomaly = self._create_anomaly(
                device_id=device_id,
                anomaly_type=AnomalyType.NEW_CONNECTION,
                score=score,
                description=f"Connections to {len(new_external)} new external IP(s)",
                details={
                    "new_external_ips": list(new_external)[:20],
                    "new_destination_count": len(new_destinations),
                },
                baseline_comparison={
                    "baseline_destination_count": len(baseline_destinations),
                },
            )
            anomalies.append(anomaly)

        # Detect connection volume anomaly
        hours_in_window = max(time_window_hours, 1)
        current_hourly_connections = len(recent_events) / hours_in_window
        expected_hourly = baseline_connection_mean / 24

        if baseline_connection_std > 0 and expected_hourly > 0:
            z_score = (current_hourly_connections - expected_hourly) / (
                baseline_connection_std / 24
            )

            if z_score >= Z_SCORE_THRESHOLD:
                anomaly = self._create_anomaly(
                    device_id=device_id,
                    anomaly_type=AnomalyType.VOLUME_SPIKE,
                    score=abs(z_score),
                    description=f"Connection volume {z_score:.1f} standard deviations above normal",
                    details={
                        "current_hourly_connections": current_hourly_connections,
                        "expected_hourly_connections": expected_hourly,
                        "z_score": z_score,
                        "event_type": "connection",
                    },
                    baseline_comparison={
                        "baseline_daily_mean": baseline_connection_mean,
                        "baseline_daily_std": baseline_connection_std,
                    },
                )
                anomalies.append(anomaly)

        # Detect pattern change (internal/external ratio shift)
        internal_count = sum(
            1 for e in recent_events if self._is_internal_ip(e.target_ip or "")
        )
        current_internal_ratio = (
            internal_count / len(recent_events) if recent_events else 0
        )

        # Significant shift to more external connections
        if baseline_internal_ratio > 0.3:  # Baseline was mostly internal
            if current_internal_ratio < 0.1:  # Now mostly external
                score = 4.0
                anomaly = self._create_anomaly(
                    device_id=device_id,
                    anomaly_type=AnomalyType.PATTERN_CHANGE,
                    score=score,
                    description="Significant shift from internal to external connections",
                    details={
                        "current_internal_ratio": current_internal_ratio,
                        "internal_connections": internal_count,
                        "external_connections": len(recent_events) - internal_count,
                    },
                    baseline_comparison={
                        "baseline_internal_ratio": baseline_internal_ratio,
                    },
                )
                anomalies.append(anomaly)

        return anomalies

    def _create_anomaly(
        self,
        device_id: UUID,
        anomaly_type: AnomalyType,
        score: float,
        description: str,
        details: dict[str, Any],
        baseline_comparison: dict[str, Any],
    ) -> AnomalyDetection:
        """Create an AnomalyDetection object."""
        severity = AnomalyDetection.calculate_severity(score, anomaly_type)

        return AnomalyDetection(
            id=uuid4(),
            device_id=device_id,
            anomaly_type=anomaly_type,
            severity=severity,
            score=score,
            status=AnomalyStatus.ACTIVE,
            description=description,
            details=details,
            baseline_comparison=baseline_comparison,
            detected_at=datetime.now(UTC),
        )

    async def _create_alert_for_anomaly(
        self,
        anomaly: AnomalyDetection,
    ) -> Alert:
        """Create an alert for a detected anomaly."""
        alert = Alert(
            id=uuid4(),
            timestamp=anomaly.detected_at,
            device_id=anomaly.device_id,
            rule_id=f"anomaly_{anomaly.anomaly_type.value}",
            severity=anomaly.severity,
            title=f"Anomaly Detected: {anomaly.anomaly_type.value.replace('_', ' ').title()}",
            description=anomaly.description,
            status=AlertStatus.NEW,
            actions_taken=[],
        )
        self._session.add(alert)
        await self._session.flush()

        logger.info(
            "alert_created_for_anomaly",
            anomaly_id=str(anomaly.id),
            alert_id=str(alert.id),
            severity=anomaly.severity.value,
        )

        return alert

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if an IP address is internal/private."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])

            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True

            return False
        except (ValueError, IndexError):
            return False

    def _is_suspicious_port(self, port: int) -> bool:
        """Check if a port is potentially suspicious."""
        # Common safe ports
        safe_ports = {
            80,
            443,
            53,
            22,
            21,
            25,
            110,
            143,
            993,
            995,
            587,
            465,
            8080,
            8443,
            3389,
            5900,
            123,
            67,
            68,
            161,
            162,
            389,
            636,
            1900,
            5353,
        }

        if port in safe_ports:
            return False

        # High ports are less suspicious
        if 1024 <= port <= 65535:
            return False

        # Low ports that aren't in safe list are suspicious
        return True


class AnomalyService:
    """High-level service for anomaly detection and management."""

    async def run_detection_for_device(
        self,
        device_id: UUID,
        time_window_hours: int = 1,
        auto_create_alerts: bool = True,
    ) -> list[AnomalyDetection]:
        """Run anomaly detection for a specific device.

        Args:
            device_id: Device UUID.
            time_window_hours: Hours of activity to analyze.
            auto_create_alerts: Whether to create alerts.

        Returns:
            List of detected anomalies.
        """
        async with AsyncSessionLocal() as session:
            detector = AnomalyDetector(session)
            anomalies = await detector.detect_anomalies(
                device_id, time_window_hours, auto_create_alerts
            )
            await session.commit()
            return anomalies

    async def run_detection_for_all_devices(
        self,
        time_window_hours: int = 1,
        auto_create_alerts: bool = True,
    ) -> dict[str, Any]:
        """Run anomaly detection for all active devices.

        Args:
            time_window_hours: Hours of activity to analyze.
            auto_create_alerts: Whether to create alerts.

        Returns:
            Dict with detection statistics.
        """
        async with AsyncSessionLocal() as session:
            from app.models.device import DeviceStatus

            # Get all active devices with ready baselines
            result = await session.execute(
                select(Device)
                .where(Device.status == DeviceStatus.ACTIVE)
                .where(Device.baseline_ready.is_(True))
            )
            devices = result.scalars().all()

            detector = AnomalyDetector(session)
            devices_checked = 0
            anomalies_detected = 0
            alerts_created = 0
            by_type: dict[str, int] = {}
            by_severity: dict[str, int] = {}
            errors = 0

            for device in devices:
                try:
                    device_uuid = UUID(str(device.id))
                    anomalies = await detector.detect_anomalies(
                        device_uuid, time_window_hours, auto_create_alerts
                    )

                    devices_checked += 1
                    anomalies_detected += len(anomalies)

                    for anomaly in anomalies:
                        # Count by type
                        type_key = anomaly.anomaly_type.value
                        by_type[type_key] = by_type.get(type_key, 0) + 1

                        # Count by severity
                        sev_key = anomaly.severity.value
                        by_severity[sev_key] = by_severity.get(sev_key, 0) + 1

                        # Count alerts
                        if anomaly.alert_id:
                            alerts_created += 1

                except Exception as e:
                    logger.error(
                        "anomaly_detection_error",
                        device_id=str(device.id),
                        error=str(e),
                    )
                    errors += 1

            stats: dict[str, Any] = {
                "devices_checked": devices_checked,
                "anomalies_detected": anomalies_detected,
                "alerts_created": alerts_created,
                "by_type": by_type,
                "by_severity": by_severity,
                "errors": errors,
            }

            await session.commit()

            logger.info("anomaly_detection_complete", **stats)
            return stats

    async def get_device_anomalies(
        self,
        device_id: UUID,
        status: AnomalyStatus | None = None,
        anomaly_type: AnomalyType | None = None,
        limit: int = 100,
    ) -> list[AnomalyDetection]:
        """Get anomalies for a device.

        Args:
            device_id: Device UUID.
            status: Filter by status.
            anomaly_type: Filter by type.
            limit: Maximum results.

        Returns:
            List of AnomalyDetection objects.
        """
        async with AsyncSessionLocal() as session:
            query = (
                select(AnomalyDetection)
                .where(AnomalyDetection.device_id == device_id)
                .order_by(AnomalyDetection.detected_at.desc())
            )

            if status:
                query = query.where(AnomalyDetection.status == status)
            if anomaly_type:
                query = query.where(AnomalyDetection.anomaly_type == anomaly_type)

            query = query.limit(limit)

            result = await session.execute(query)
            return list(result.scalars().all())

    async def get_active_anomalies(
        self,
        limit: int = 100,
        min_severity: AlertSeverity | None = None,
    ) -> list[AnomalyDetection]:
        """Get all active anomalies.

        Args:
            limit: Maximum results.
            min_severity: Minimum severity to include.

        Returns:
            List of AnomalyDetection objects.
        """
        async with AsyncSessionLocal() as session:
            query = (
                select(AnomalyDetection)
                .where(AnomalyDetection.status == AnomalyStatus.ACTIVE)
                .order_by(AnomalyDetection.detected_at.desc())
            )

            if min_severity:
                severity_order = [
                    AlertSeverity.INFO,
                    AlertSeverity.LOW,
                    AlertSeverity.MEDIUM,
                    AlertSeverity.HIGH,
                    AlertSeverity.CRITICAL,
                ]
                min_index = severity_order.index(min_severity)
                allowed = severity_order[min_index:]
                query = query.where(AnomalyDetection.severity.in_(allowed))

            query = query.limit(limit)

            result = await session.execute(query)
            return list(result.scalars().all())

    async def update_anomaly_status(
        self,
        anomaly_id: UUID,
        status: AnomalyStatus,
        reviewed_by: UUID | None = None,
    ) -> AnomalyDetection | None:
        """Update anomaly status.

        Args:
            anomaly_id: Anomaly UUID.
            status: New status.
            reviewed_by: User who reviewed.

        Returns:
            Updated AnomalyDetection or None.
        """
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(AnomalyDetection).where(AnomalyDetection.id == anomaly_id)
            )
            anomaly = result.scalar_one_or_none()

            if not anomaly:
                return None

            anomaly.status = status
            if reviewed_by:
                anomaly.reviewed_by = reviewed_by
                anomaly.reviewed_at = datetime.now(UTC)

            await session.commit()

            logger.info(
                "anomaly_status_updated",
                anomaly_id=str(anomaly_id),
                status=status.value,
            )

            return anomaly


# Global service instance
_anomaly_service: AnomalyService | None = None


def get_anomaly_service() -> AnomalyService:
    """Get the global anomaly service instance."""
    global _anomaly_service
    if _anomaly_service is None:
        _anomaly_service = AnomalyService()
    return _anomaly_service
