"""Device baseline model for behavioral profiling."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import uuid4

if TYPE_CHECKING:
    from app.models.device import Device

from sqlalchemy import DateTime, ForeignKey, Integer
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class BaselineType(str, Enum):
    """Type of behavioral baseline."""

    DNS = "dns"
    TRAFFIC = "traffic"
    CONNECTION = "connection"


class BaselineStatus(str, Enum):
    """Baseline learning status."""

    LEARNING = "learning"
    READY = "ready"
    STALE = "stale"


class DeviceBaseline(Base, TimestampMixin):
    """Device behavioral baseline model.

    Stores learned normal behavior patterns for a device to enable
    anomaly detection. Separate baselines are maintained for different
    aspects of device behavior (DNS, traffic, connections).

    Attributes:
        id: Unique identifier (UUID).
        device_id: Associated device.
        baseline_type: Type of baseline (dns, traffic, connection).
        status: Current baseline status (learning, ready, stale).
        metrics: Baseline metrics stored as JSON.
        sample_count: Number of samples used to build baseline.
        min_samples: Minimum samples required for ready status.
        baseline_window_days: Number of days used for baseline calculation.
        last_calculated: When baseline was last recalculated.
    """

    __tablename__ = "device_baselines"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    device_id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    baseline_type: Mapped[BaselineType] = mapped_column(
        SQLEnum(BaselineType, name="baselinetype", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    status: Mapped[BaselineStatus] = mapped_column(
        SQLEnum(BaselineStatus, name="baselinestatus", values_callable=lambda x: [e.value for e in x]),
        default=BaselineStatus.LEARNING,
        nullable=False,
        index=True,
    )
    metrics: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    sample_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    min_samples: Mapped[int] = mapped_column(
        Integer,
        default=100,
        nullable=False,
    )
    baseline_window_days: Mapped[int] = mapped_column(
        Integer,
        default=7,
        nullable=False,
    )
    last_calculated: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    device: Mapped[Device] = relationship(
        "Device",
        back_populates="baselines",
    )

    def __repr__(self) -> str:
        return f"<DeviceBaseline {self.device_id} ({self.baseline_type.value})>"

    @property
    def is_ready(self) -> bool:
        """Check if baseline has enough data to be useful."""
        return self.sample_count >= self.min_samples

    def update_status(self) -> None:
        """Update status based on sample count."""
        if self.sample_count >= self.min_samples:
            self.status = BaselineStatus.READY
        else:
            self.status = BaselineStatus.LEARNING


class DNSBaselineMetrics:
    """Structure for DNS baseline metrics.

    This class documents the expected structure of the metrics JSON
    for DNS baselines.

    Metrics:
        domains_daily: Dict[str, float] - Domain -> avg queries/day
        total_queries_daily_avg: float - Average total queries per day
        total_queries_daily_std: float - Standard deviation of daily queries
        query_rate_hourly_avg: float - Average queries per hour
        query_rate_hourly_std: float - Std dev of hourly query rate
        peak_hours: List[int] - Hours (0-23) with highest activity
        unique_domains_daily_avg: float - Avg unique domains queried per day
        blocked_ratio: float - Ratio of blocked to total queries
    """

    pass


class TrafficBaselineMetrics:
    """Structure for traffic baseline metrics.

    Metrics:
        bytes_daily_avg: float - Average bytes per day
        bytes_daily_std: float - Standard deviation of daily bytes
        bytes_hourly_avg: Dict[int, float] - Hour -> avg bytes
        peak_hours: List[int] - Hours with highest traffic
        active_hours: List[int] - Hours when device is typically active
    """

    pass


class ConnectionBaselineMetrics:
    """Structure for connection baseline metrics.

    Metrics:
        common_destinations: Dict[str, int] - IP -> connection count
        common_ports: Dict[int, int] - Port -> usage count
        unique_ips_daily_avg: float - Avg unique IPs contacted per day
        unique_ports_daily_avg: float - Avg unique ports used per day
        internal_ratio: float - Ratio of internal to external connections
    """

    pass
