"""Statistics API endpoints."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.db.session import get_async_session
from app.models.alert import Alert, AlertStatus
from app.models.device import Device, DeviceStatus
from app.models.raw_event import EventType, RawEvent
from app.models.user import User

router = APIRouter()


# Pydantic schemas
class OverviewStats(BaseModel):
    device_count: int
    active_devices: int
    quarantined_devices: int
    total_events_24h: int
    dns_queries_24h: int
    blocked_queries_24h: int
    block_rate: float
    active_alerts: int
    critical_alerts: int
    source_count: int


class TopDomain(BaseModel):
    domain: str
    count: int


class TimelineBucket(BaseModel):
    timestamp: str
    count: int


class DeviceActivity(BaseModel):
    device_id: str
    hostname: str | None
    mac_address: str
    event_count: int


@router.get("/overview", response_model=OverviewStats)
async def get_overview(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> OverviewStats:
    """Get dashboard overview statistics."""
    now = datetime.now(UTC)
    last_24h = now - timedelta(hours=24)

    # Device counts
    device_result = await session.execute(select(Device))
    devices = device_result.scalars().all()
    device_count = len(devices)
    active_devices = len([d for d in devices if d.status == DeviceStatus.ACTIVE])
    quarantined_devices = len([d for d in devices if d.status == DeviceStatus.QUARANTINED])

    # Event counts (last 24h)
    event_count_result = await session.execute(
        select(func.count()).select_from(RawEvent).where(RawEvent.timestamp >= last_24h)
    )
    total_events_24h = event_count_result.scalar() or 0

    # DNS query counts (last 24h)
    dns_count_result = await session.execute(
        select(func.count())
        .select_from(RawEvent)
        .where(RawEvent.timestamp >= last_24h)
        .where(RawEvent.event_type == EventType.DNS)
    )
    dns_queries_24h = dns_count_result.scalar() or 0

    # Blocked DNS queries (last 24h)
    blocked_count_result = await session.execute(
        select(func.count())
        .select_from(RawEvent)
        .where(RawEvent.timestamp >= last_24h)
        .where(RawEvent.event_type == EventType.DNS)
        .where(RawEvent.response_status == "blocked")
    )
    blocked_queries_24h = blocked_count_result.scalar() or 0

    # Calculate block rate
    block_rate = (blocked_queries_24h / dns_queries_24h * 100) if dns_queries_24h > 0 else 0

    # Alert counts
    active_alerts_result = await session.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED]))
    )
    active_alerts = active_alerts_result.scalar() or 0

    critical_alerts_result = await session.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED]))
        .where(Alert.severity == "critical")
    )
    critical_alerts = critical_alerts_result.scalar() or 0

    # Source count
    from app.models.log_source import LogSource

    source_count_result = await session.execute(
        select(func.count()).select_from(LogSource).where(LogSource.enabled.is_(True))
    )
    source_count = source_count_result.scalar() or 0

    return OverviewStats(
        device_count=device_count,
        active_devices=active_devices,
        quarantined_devices=quarantined_devices,
        total_events_24h=total_events_24h,
        dns_queries_24h=dns_queries_24h,
        blocked_queries_24h=blocked_queries_24h,
        block_rate=round(block_rate, 1),
        active_alerts=active_alerts,
        critical_alerts=critical_alerts,
        source_count=source_count,
    )


@router.get("/dns/top-domains", response_model=list[TopDomain])
async def get_top_domains(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(10, ge=1, le=100),
) -> list[TopDomain]:
    """Get top queried domains."""
    since = datetime.now(UTC) - timedelta(hours=hours)

    result = await session.execute(
        select(RawEvent.domain, func.count().label("domain_count"))
        .where(RawEvent.timestamp >= since)
        .where(RawEvent.event_type == EventType.DNS)
        .where(RawEvent.domain.isnot(None))
        .group_by(RawEvent.domain)
        .order_by(func.count().desc())
        .limit(limit)
    )

    return [TopDomain(domain=row.domain, count=row.domain_count) for row in result]


@router.get("/dns/timeline", response_model=list[TimelineBucket])
async def get_dns_timeline(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    hours: int = Query(24, ge=1, le=720),
    bucket_minutes: int = Query(60, ge=5, le=1440),
) -> list[TimelineBucket]:
    """Get DNS query counts over time."""
    since = datetime.now(UTC) - timedelta(hours=hours)

    # Use TimescaleDB time_bucket function
    result = await session.execute(
        select(
            func.time_bucket(f"{bucket_minutes} minutes", RawEvent.timestamp).label("bucket"),
            func.count().label("event_count"),
        )
        .where(RawEvent.timestamp >= since)
        .where(RawEvent.event_type == EventType.DNS)
        .group_by("bucket")
        .order_by("bucket")
    )

    return [
        TimelineBucket(timestamp=row.bucket.isoformat(), count=row.event_count) for row in result
    ]


@router.get("/devices/activity", response_model=list[DeviceActivity])
async def get_device_activity(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(10, ge=1, le=100),
) -> list[DeviceActivity]:
    """Get most active devices by event count."""
    since = datetime.now(UTC) - timedelta(hours=hours)

    result = await session.execute(
        select(
            RawEvent.device_id,
            Device.hostname,
            Device.mac_address,
            func.count().label("event_count"),
        )
        .join(Device, RawEvent.device_id == Device.id)
        .where(RawEvent.timestamp >= since)
        .where(RawEvent.device_id.isnot(None))
        .group_by(RawEvent.device_id, Device.hostname, Device.mac_address)
        .order_by(func.count().desc())
        .limit(limit)
    )

    return [
        DeviceActivity(
            device_id=str(row.device_id),
            hostname=row.hostname,
            mac_address=row.mac_address,
            event_count=row.event_count,
        )
        for row in result
    ]
