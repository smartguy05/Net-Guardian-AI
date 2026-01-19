"""Event query API endpoints."""

from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.db.session import get_async_session
from app.models.raw_event import RawEvent, EventType, EventSeverity
from app.models.user import User

router = APIRouter()


# Pydantic schemas
class EventResponse(BaseModel):
    id: str
    timestamp: str
    source_id: str
    event_type: str
    severity: str
    client_ip: Optional[str]
    target_ip: Optional[str]
    domain: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    action: Optional[str]
    raw_message: str
    parsed_fields: Dict[str, Any]
    device_id: Optional[str]

    class Config:
        from_attributes = True


class EventListResponse(BaseModel):
    items: List[EventResponse]
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
    source_id: Optional[str] = None,
    event_type: Optional[EventType] = None,
    severity: Optional[EventSeverity] = None,
    device_id: Optional[UUID] = None,
    domain_contains: Optional[str] = None,
    client_ip: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
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
    device_id: Optional[UUID] = None,
    domain_contains: Optional[str] = None,
    blocked_only: bool = False,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
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
