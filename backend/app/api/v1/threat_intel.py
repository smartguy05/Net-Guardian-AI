"""Threat intelligence feed API endpoints."""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, HttpUrl, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin
from app.db.session import get_async_session
from app.models.user import User
from app.models.threat_intel import FeedType, IndicatorType
from app.services.threat_intel_service import ThreatIntelService

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


# Request/Response schemas
class FeedCreate(BaseModel):
    """Schema for creating a threat intel feed."""

    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    feed_type: FeedType
    url: HttpUrl
    enabled: bool = True
    update_interval_hours: int = Field(default=24, ge=1, le=168)
    auth_type: str = Field(default="none", pattern="^(none|basic|bearer|api_key)$")
    auth_config: dict = Field(default_factory=dict)
    field_mapping: dict = Field(default_factory=dict)


class FeedUpdate(BaseModel):
    """Schema for updating a threat intel feed."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    feed_type: Optional[FeedType] = None
    url: Optional[HttpUrl] = None
    enabled: Optional[bool] = None
    update_interval_hours: Optional[int] = Field(None, ge=1, le=168)
    auth_type: Optional[str] = Field(None, pattern="^(none|basic|bearer|api_key)$")
    auth_config: Optional[dict] = None
    field_mapping: Optional[dict] = None


class FeedResponse(BaseModel):
    """Schema for feed response."""

    id: UUID
    name: str
    description: Optional[str]
    feed_type: str
    url: str
    enabled: bool
    update_interval_hours: int
    auth_type: str
    auth_config: dict
    field_mapping: dict
    last_fetch_at: Optional[str]
    last_fetch_status: Optional[str]
    last_fetch_message: Optional[str]
    indicator_count: int
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class IndicatorResponse(BaseModel):
    """Schema for indicator response."""

    id: UUID
    feed_id: UUID
    feed_name: Optional[str] = None
    indicator_type: str
    value: str
    confidence: int
    severity: str
    tags: list[str]
    description: Optional[str]
    source_ref: Optional[str]
    first_seen_at: Optional[str]
    last_seen_at: Optional[str]
    expires_at: Optional[str]
    metadata: dict
    hit_count: int
    last_hit_at: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


class IndicatorCheckRequest(BaseModel):
    """Schema for checking an indicator."""

    value: str = Field(..., min_length=1)
    indicator_type: Optional[IndicatorType] = None


class IndicatorCheckResponse(BaseModel):
    """Schema for indicator check response."""

    found: bool
    matches: list[IndicatorResponse]


class FeedListResponse(BaseModel):
    """Schema for feed list response."""

    items: list[FeedResponse]
    total: int


class IndicatorListResponse(BaseModel):
    """Schema for indicator list response."""

    items: list[IndicatorResponse]
    total: int


class StatsResponse(BaseModel):
    """Schema for threat intel stats."""

    total_feeds: int
    enabled_feeds: int
    total_indicators: int
    indicators_by_type: dict[str, int]
    indicators_by_severity: dict[str, int]
    recent_hits: int


# Endpoints
@router.get("/feeds", response_model=FeedListResponse)
async def list_feeds(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    feed_type: Optional[FeedType] = Query(None, description="Filter by feed type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
):
    """List all threat intelligence feeds."""
    service = ThreatIntelService(session)
    feeds, total = await service.get_feeds(
        enabled=enabled,
        feed_type=feed_type,
        limit=limit,
        offset=offset,
    )

    items = []
    for feed in feeds:
        items.append(
            FeedResponse(
                id=feed.id,
                name=feed.name,
                description=feed.description,
                feed_type=feed.feed_type.value,
                url=feed.url,
                enabled=feed.enabled,
                update_interval_hours=feed.update_interval_hours,
                auth_type=feed.auth_type,
                auth_config=feed.auth_config,
                field_mapping=feed.field_mapping,
                last_fetch_at=feed.last_fetch_at.isoformat() if feed.last_fetch_at else None,
                last_fetch_status=feed.last_fetch_status,
                last_fetch_message=feed.last_fetch_message,
                indicator_count=feed.indicator_count,
                created_at=feed.created_at.isoformat(),
                updated_at=feed.updated_at.isoformat(),
            )
        )

    return FeedListResponse(items=items, total=total)


@router.get("/feeds/{feed_id}", response_model=FeedResponse)
async def get_feed(
    feed_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
):
    """Get a specific threat intelligence feed."""
    service = ThreatIntelService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    return FeedResponse(
        id=feed.id,
        name=feed.name,
        description=feed.description,
        feed_type=feed.feed_type.value,
        url=feed.url,
        enabled=feed.enabled,
        update_interval_hours=feed.update_interval_hours,
        auth_type=feed.auth_type,
        auth_config=feed.auth_config,
        field_mapping=feed.field_mapping,
        last_fetch_at=feed.last_fetch_at.isoformat() if feed.last_fetch_at else None,
        last_fetch_status=feed.last_fetch_status,
        last_fetch_message=feed.last_fetch_message,
        indicator_count=feed.indicator_count,
        created_at=feed.created_at.isoformat(),
        updated_at=feed.updated_at.isoformat(),
    )


@router.post("/feeds", response_model=FeedResponse, status_code=201)
async def create_feed(
    data: FeedCreate,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
):
    """Create a new threat intelligence feed."""
    service = ThreatIntelService(session)
    feed = await service.create_feed(
        name=data.name,
        description=data.description,
        feed_type=data.feed_type,
        url=str(data.url),
        enabled=data.enabled,
        update_interval_hours=data.update_interval_hours,
        auth_type=data.auth_type,
        auth_config=data.auth_config,
        field_mapping=data.field_mapping,
    )

    return FeedResponse(
        id=feed.id,
        name=feed.name,
        description=feed.description,
        feed_type=feed.feed_type.value,
        url=feed.url,
        enabled=feed.enabled,
        update_interval_hours=feed.update_interval_hours,
        auth_type=feed.auth_type,
        auth_config=feed.auth_config,
        field_mapping=feed.field_mapping,
        last_fetch_at=feed.last_fetch_at.isoformat() if feed.last_fetch_at else None,
        last_fetch_status=feed.last_fetch_status,
        last_fetch_message=feed.last_fetch_message,
        indicator_count=feed.indicator_count,
        created_at=feed.created_at.isoformat(),
        updated_at=feed.updated_at.isoformat(),
    )


@router.patch("/feeds/{feed_id}", response_model=FeedResponse)
async def update_feed(
    feed_id: UUID,
    data: FeedUpdate,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
):
    """Update a threat intelligence feed."""
    service = ThreatIntelService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    update_data = data.model_dump(exclude_unset=True)
    if "url" in update_data:
        update_data["url"] = str(update_data["url"])

    feed = await service.update_feed(feed_id, **update_data)

    return FeedResponse(
        id=feed.id,
        name=feed.name,
        description=feed.description,
        feed_type=feed.feed_type.value,
        url=feed.url,
        enabled=feed.enabled,
        update_interval_hours=feed.update_interval_hours,
        auth_type=feed.auth_type,
        auth_config=feed.auth_config,
        field_mapping=feed.field_mapping,
        last_fetch_at=feed.last_fetch_at.isoformat() if feed.last_fetch_at else None,
        last_fetch_status=feed.last_fetch_status,
        last_fetch_message=feed.last_fetch_message,
        indicator_count=feed.indicator_count,
        created_at=feed.created_at.isoformat(),
        updated_at=feed.updated_at.isoformat(),
    )


@router.delete("/feeds/{feed_id}", status_code=204)
async def delete_feed(
    feed_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
):
    """Delete a threat intelligence feed."""
    service = ThreatIntelService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    await service.delete_feed(feed_id)


@router.post("/feeds/{feed_id}/fetch")
async def fetch_feed(
    feed_id: UUID,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
):
    """Trigger a feed fetch (runs in background)."""
    service = ThreatIntelService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    # Run fetch in background
    async def do_fetch():
        async for s in get_async_session():
            svc = ThreatIntelService(s)
            await svc.fetch_feed(feed_id)

    background_tasks.add_task(do_fetch)

    return {"message": "Feed fetch started", "feed_id": str(feed_id)}


@router.post("/feeds/{feed_id}/enable", response_model=FeedResponse)
async def enable_feed(
    feed_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
):
    """Enable a threat intelligence feed."""
    service = ThreatIntelService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed = await service.update_feed(feed_id, enabled=True)

    return FeedResponse(
        id=feed.id,
        name=feed.name,
        description=feed.description,
        feed_type=feed.feed_type.value,
        url=feed.url,
        enabled=feed.enabled,
        update_interval_hours=feed.update_interval_hours,
        auth_type=feed.auth_type,
        auth_config=feed.auth_config,
        field_mapping=feed.field_mapping,
        last_fetch_at=feed.last_fetch_at.isoformat() if feed.last_fetch_at else None,
        last_fetch_status=feed.last_fetch_status,
        last_fetch_message=feed.last_fetch_message,
        indicator_count=feed.indicator_count,
        created_at=feed.created_at.isoformat(),
        updated_at=feed.updated_at.isoformat(),
    )


@router.post("/feeds/{feed_id}/disable", response_model=FeedResponse)
async def disable_feed(
    feed_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
):
    """Disable a threat intelligence feed."""
    service = ThreatIntelService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    feed = await service.update_feed(feed_id, enabled=False)

    return FeedResponse(
        id=feed.id,
        name=feed.name,
        description=feed.description,
        feed_type=feed.feed_type.value,
        url=feed.url,
        enabled=feed.enabled,
        update_interval_hours=feed.update_interval_hours,
        auth_type=feed.auth_type,
        auth_config=feed.auth_config,
        field_mapping=feed.field_mapping,
        last_fetch_at=feed.last_fetch_at.isoformat() if feed.last_fetch_at else None,
        last_fetch_status=feed.last_fetch_status,
        last_fetch_message=feed.last_fetch_message,
        indicator_count=feed.indicator_count,
        created_at=feed.created_at.isoformat(),
        updated_at=feed.updated_at.isoformat(),
    )


@router.get("/indicators", response_model=IndicatorListResponse)
async def list_indicators(
    feed_id: Optional[UUID] = Query(None, description="Filter by feed"),
    indicator_type: Optional[IndicatorType] = Query(None, description="Filter by type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    value_contains: Optional[str] = Query(None, description="Search by value"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
):
    """List threat indicators."""
    service = ThreatIntelService(session)
    indicators, total = await service.search_indicators(
        feed_id=feed_id,
        indicator_type=indicator_type,
        severity=severity,
        value_contains=value_contains,
        limit=limit,
        offset=offset,
    )

    items = []
    for ind in indicators:
        items.append(
            IndicatorResponse(
                id=ind.id,
                feed_id=ind.feed_id,
                feed_name=ind.feed.name if ind.feed else None,
                indicator_type=ind.indicator_type.value,
                value=ind.value,
                confidence=ind.confidence,
                severity=ind.severity,
                tags=ind.tags,
                description=ind.description,
                source_ref=ind.source_ref,
                first_seen_at=ind.first_seen_at.isoformat() if ind.first_seen_at else None,
                last_seen_at=ind.last_seen_at.isoformat() if ind.last_seen_at else None,
                expires_at=ind.expires_at.isoformat() if ind.expires_at else None,
                metadata=ind.extra_data or {},
                hit_count=ind.hit_count,
                last_hit_at=ind.last_hit_at.isoformat() if ind.last_hit_at else None,
                created_at=ind.created_at.isoformat(),
            )
        )

    return IndicatorListResponse(items=items, total=total)


@router.post("/check", response_model=IndicatorCheckResponse)
async def check_indicator(
    data: IndicatorCheckRequest,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
):
    """Check if a value matches any threat indicators."""
    service = ThreatIntelService(session)
    matches = await service.check_indicator(
        value=data.value,
        indicator_type=data.indicator_type,
    )

    items = []
    for ind in matches:
        items.append(
            IndicatorResponse(
                id=ind.id,
                feed_id=ind.feed_id,
                feed_name=ind.feed.name if ind.feed else None,
                indicator_type=ind.indicator_type.value,
                value=ind.value,
                confidence=ind.confidence,
                severity=ind.severity,
                tags=ind.tags,
                description=ind.description,
                source_ref=ind.source_ref,
                first_seen_at=ind.first_seen_at.isoformat() if ind.first_seen_at else None,
                last_seen_at=ind.last_seen_at.isoformat() if ind.last_seen_at else None,
                expires_at=ind.expires_at.isoformat() if ind.expires_at else None,
                metadata=ind.extra_data or {},
                hit_count=ind.hit_count,
                last_hit_at=ind.last_hit_at.isoformat() if ind.last_hit_at else None,
                created_at=ind.created_at.isoformat(),
            )
        )

    return IndicatorCheckResponse(found=len(items) > 0, matches=items)


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
):
    """Get threat intelligence statistics."""
    service = ThreatIntelService(session)
    stats = await service.get_stats()
    return StatsResponse(**stats)
