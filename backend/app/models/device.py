"""Device model for network device inventory."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Enum as SQLEnum, String
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin


class DeviceType(str, Enum):
    """Device type classification."""

    PC = "pc"
    MOBILE = "mobile"
    IOT = "iot"
    SERVER = "server"
    NETWORK = "network"
    UNKNOWN = "unknown"


class DeviceStatus(str, Enum):
    """Device operational status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    QUARANTINED = "quarantined"


class Device(Base, TimestampMixin):
    """Network device model.

    Attributes:
        id: Unique identifier (UUID).
        mac_address: Primary MAC address (unique).
        ip_addresses: List of known IP addresses.
        hostname: Device hostname if known.
        manufacturer: Manufacturer from OUI lookup.
        device_type: Classification (pc, mobile, iot, etc.).
        profile_tags: User-defined tags for profiling.
        first_seen: When device was first observed.
        last_seen: When device was last active.
        status: Current operational status.
        baseline_ready: Whether behavioral baseline is established.
    """

    __tablename__ = "devices"

    id: Mapped[UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    mac_address: Mapped[str] = mapped_column(
        String(17),
        unique=True,
        nullable=False,
        index=True,
    )
    ip_addresses: Mapped[List[str]] = mapped_column(
        ARRAY(String(45)),
        default=list,
        nullable=False,
    )
    hostname: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    manufacturer: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    device_type: Mapped[DeviceType] = mapped_column(
        SQLEnum(DeviceType, name="devicetype", values_callable=lambda x: [e.value for e in x]),
        default=DeviceType.UNKNOWN,
        nullable=False,
    )
    profile_tags: Mapped[List[str]] = mapped_column(
        ARRAY(String(50)),
        default=list,
        nullable=False,
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    status: Mapped[DeviceStatus] = mapped_column(
        SQLEnum(DeviceStatus, name="devicestatus", values_callable=lambda x: [e.value for e in x]),
        default=DeviceStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    baseline_ready: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Relationships
    raw_events: Mapped[List["RawEvent"]] = relationship(
        "RawEvent",
        back_populates="device",
        lazy="dynamic",
    )
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert",
        back_populates="device",
        lazy="dynamic",
    )
    baselines: Mapped[List["DeviceBaseline"]] = relationship(
        "DeviceBaseline",
        back_populates="device",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    anomalies: Mapped[List["AnomalyDetection"]] = relationship(
        "AnomalyDetection",
        back_populates="device",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Device {self.mac_address} ({self.hostname or 'unknown'})>"
