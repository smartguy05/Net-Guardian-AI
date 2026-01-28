"""Event query API endpoints."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.db.session import get_async_session
from app.models.raw_event import EventSeverity, EventType, RawEvent
from app.models.user import User
from app.services.export_service import (
    EVENTS_COLUMNS,
    EVENTS_HEADERS,
    ExportService,
)

router = APIRouter()


# Pydantic schemas
class EventResponse(BaseModel):
    id: str
    timestamp: str
    source_id: str
    event_type: str
    severity: str
    client_ip: str | None
    target_ip: str | None
    domain: str | None
    port: int | None
    protocol: str | None
    action: str | None
    raw_message: str
    parsed_fields: dict[str, Any]
    device_id: str | None

    class Config:
        from_attributes = True


class EventListResponse(BaseModel):
    items: list[EventResponse]
    total: int


def _event_to_response(event: RawEvent) -> EventResponse:
    return EventResponse(
        id=str(event.id),
        timestamp=event.timestamp.isoformat(),
        source_id=event.source_id,
        event_type=event.event_type.value,
        severity=event.severity.value,
        client_ip=event.client_ip,
        target_ip=event.target_ip,
        domain=event.domain,
        port=event.port,
        protocol=event.protocol,
        action=event.action,
        raw_message=event.raw_message,
        parsed_fields=event.parsed_fields,
        device_id=str(event.device_id) if event.device_id else None,
    )


@router.get("", response_model=EventListResponse)
async def list_events(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    source_id: str | None = None,
    event_type: EventType | None = None,
    severity: EventSeverity | None = None,
    device_id: UUID | None = None,
    domain_contains: str | None = None,
    client_ip: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> EventListResponse:
    """Query events with filtering."""
    # Build query
    query = select(RawEvent)

    if source_id:
        query = query.where(RawEvent.source_id == source_id)
    if event_type:
        query = query.where(RawEvent.event_type == event_type)
    if severity:
        query = query.where(RawEvent.severity == severity)
    if device_id:
        query = query.where(RawEvent.device_id == device_id)
    if domain_contains:
        query = query.where(RawEvent.domain.ilike(f"%{domain_contains}%"))
    if client_ip:
        query = query.where(RawEvent.client_ip == client_ip)
    if start_time:
        query = query.where(RawEvent.timestamp >= start_time)
    if end_time:
        query = query.where(RawEvent.timestamp <= end_time)

    # Count total (approximate for hypertable)
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get results
    query = query.order_by(desc(RawEvent.timestamp)).offset(offset).limit(limit)
    result = await session.execute(query)
    events = result.scalars().all()

    return EventListResponse(
        items=[_event_to_response(e) for e in events],
        total=total,
    )


@router.get("/dns", response_model=EventListResponse)
async def list_dns_events(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    device_id: UUID | None = None,
    domain_contains: str | None = None,
    blocked_only: bool = False,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> EventListResponse:
    """Query DNS events specifically."""
    # Build query for DNS events only
    query = select(RawEvent).where(RawEvent.event_type == EventType.DNS)

    if device_id:
        query = query.where(RawEvent.device_id == device_id)
    if domain_contains:
        query = query.where(RawEvent.domain.ilike(f"%{domain_contains}%"))
    if blocked_only:
        query = query.where(RawEvent.response_status == "blocked")
    if start_time:
        query = query.where(RawEvent.timestamp >= start_time)
    if end_time:
        query = query.where(RawEvent.timestamp <= end_time)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get results
    query = query.order_by(desc(RawEvent.timestamp)).offset(offset).limit(limit)
    result = await session.execute(query)
    events = result.scalars().all()

    return EventListResponse(
        items=[_event_to_response(e) for e in events],
        total=total,
    )


async def _get_events_for_export(
    session: AsyncSession,
    source_id: str | None = None,
    event_type: EventType | None = None,
    severity: EventSeverity | None = None,
    device_id: UUID | None = None,
    domain_contains: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = 10000,
) -> list[dict[str, Any]]:
    """Get events formatted for export."""
    query = select(RawEvent)

    if source_id:
        query = query.where(RawEvent.source_id == source_id)
    if event_type:
        query = query.where(RawEvent.event_type == event_type)
    if severity:
        query = query.where(RawEvent.severity == severity)
    if device_id:
        query = query.where(RawEvent.device_id == device_id)
    if domain_contains:
        query = query.where(RawEvent.domain.ilike(f"%{domain_contains}%"))
    if start_time:
        query = query.where(RawEvent.timestamp >= start_time)
    if end_time:
        query = query.where(RawEvent.timestamp <= end_time)

    query = query.order_by(desc(RawEvent.timestamp)).limit(limit)
    result = await session.execute(query)
    events = result.scalars().all()

    return [
        {
            "timestamp": e.timestamp,
            "event_type": e.event_type.value,
            "source_ip": e.client_ip,
            "domain": e.domain,
            "severity": e.severity.value,
            "blocked": e.response_status == "blocked" if e.response_status else False,
        }
        for e in events
    ]


@router.get("/export/csv")
async def export_events_csv(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    source_id: str | None = None,
    event_type: EventType | None = None,
    severity: EventSeverity | None = None,
    device_id: UUID | None = None,
    domain_contains: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(10000, ge=1, le=100000),
) -> Response:
    """Export events to CSV format."""
    events = await _get_events_for_export(
        session,
        source_id=source_id,
        event_type=event_type,
        severity=severity,
        device_id=device_id,
        domain_contains=domain_contains,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )

    csv_content = ExportService.to_csv(events, EVENTS_COLUMNS, EVENTS_HEADERS)
    filename = f"events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/pdf")
async def export_events_pdf(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    source_id: str | None = None,
    event_type: EventType | None = None,
    severity: EventSeverity | None = None,
    device_id: UUID | None = None,
    domain_contains: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    limit: int = Query(1000, ge=1, le=10000),
) -> Response:
    """Export events to PDF format."""
    events = await _get_events_for_export(
        session,
        source_id=source_id,
        event_type=event_type,
        severity=severity,
        device_id=device_id,
        domain_contains=domain_contains,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )

    # Build subtitle with filters
    filters = []
    if event_type:
        filters.append(f"Type: {event_type.value}")
    if severity:
        filters.append(f"Severity: {severity.value}")
    if start_time:
        filters.append(f"From: {start_time.strftime('%Y-%m-%d')}")
    if end_time:
        filters.append(f"To: {end_time.strftime('%Y-%m-%d')}")
    subtitle = " | ".join(filters) if filters else None

    pdf_content = ExportService.to_pdf(
        events,
        title="Network Events Report",
        columns=EVENTS_COLUMNS,
        headers=EVENTS_HEADERS,
        subtitle=subtitle,
    )
    filename = f"events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
