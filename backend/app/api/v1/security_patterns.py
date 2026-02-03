"""Security pattern API endpoints for managing attack detection patterns."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin
from app.db.session import AsyncSessionLocal, get_async_session
from app.models.alert import AlertSeverity
from app.models.security_pattern import PatternCategory, PatternSource, PatternType
from app.models.user import User
from app.services.security_pattern_service import SecurityPatternService

router = APIRouter(prefix="/security-patterns", tags=["security-patterns"])


# --- Request/Response Schemas ---


class PatternCreate(BaseModel):
    """Schema for creating a security pattern."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    category: PatternCategory
    pattern_type: PatternType
    pattern: str = Field(..., min_length=1)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    extra_data: dict[str, Any] = Field(default_factory=dict)
    examples: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class PatternUpdate(BaseModel):
    """Schema for updating a security pattern."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    category: PatternCategory | None = None
    pattern_type: PatternType | None = None
    pattern: str | None = Field(None, min_length=1)
    severity: AlertSeverity | None = None
    enabled: bool | None = None
    tags: list[str] | None = None
    extra_data: dict[str, Any] | None = None
    examples: list[str] | None = None
    references: list[str] | None = None


class PatternResponse(BaseModel):
    """Schema for pattern response."""

    id: UUID
    name: str
    description: str | None
    category: str
    pattern_type: str
    pattern: str
    severity: str
    enabled: bool
    tags: list[str]
    extra_data: dict[str, Any]
    source: str
    feed_id: UUID | None
    feed_name: str | None = None
    examples: list[str]
    references: list[str]
    hit_count: int
    last_hit_at: str | None
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class PatternListResponse(BaseModel):
    """Schema for pattern list response."""

    items: list[PatternResponse]
    total: int


class PatternTestRequest(BaseModel):
    """Schema for testing a pattern."""

    pattern_type: PatternType
    pattern: str = Field(..., min_length=1)
    test_text: str = Field(..., min_length=1)


class PatternTestResponse(BaseModel):
    """Schema for pattern test response."""

    success: bool
    error: str | None = None
    matches: list[dict[str, Any]]
    match_count: int


class PatternMatchRequest(BaseModel):
    """Schema for matching text against patterns."""

    text: str = Field(..., min_length=1)
    categories: list[PatternCategory] | None = None


class PatternMatchResponse(BaseModel):
    """Schema for pattern match response."""

    pattern_id: UUID
    pattern_name: str
    category: str
    severity: str
    matched_text: str
    match_start: int
    match_end: int
    context: dict[str, Any]


class PatternMatchListResponse(BaseModel):
    """Schema for pattern match list response."""

    matches: list[PatternMatchResponse]
    total_matches: int


# --- Feed Schemas ---


class FeedCreate(BaseModel):
    """Schema for creating a pattern feed."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    url: HttpUrl
    enabled: bool = True
    update_interval_hours: int = Field(default=24, ge=1, le=168)
    auth_type: str = Field(default="none", pattern="^(none|basic|bearer|api_key)$")
    auth_config: dict[str, Any] = Field(default_factory=dict)
    field_mapping: dict[str, Any] = Field(default_factory=dict)


class FeedUpdate(BaseModel):
    """Schema for updating a pattern feed."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    url: HttpUrl | None = None
    enabled: bool | None = None
    update_interval_hours: int | None = Field(None, ge=1, le=168)
    auth_type: str | None = Field(None, pattern="^(none|basic|bearer|api_key)$")
    auth_config: dict[str, Any] | None = None
    field_mapping: dict[str, Any] | None = None


class FeedResponse(BaseModel):
    """Schema for feed response."""

    id: UUID
    name: str
    description: str | None
    url: str
    enabled: bool
    update_interval_hours: int
    auth_type: str
    auth_config: dict[str, Any]
    field_mapping: dict[str, Any]
    last_fetch_at: str | None
    last_fetch_status: str | None
    last_fetch_message: str | None
    pattern_count: int
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class FeedListResponse(BaseModel):
    """Schema for feed list response."""

    items: list[FeedResponse]
    total: int


class StatsResponse(BaseModel):
    """Schema for security pattern stats."""

    total_patterns: int
    enabled_patterns: int
    total_feeds: int
    enabled_feeds: int
    patterns_by_category: dict[str, int]
    patterns_by_source: dict[str, int]
    total_hits: int


# --- Helper Functions ---

# Sensitive keys to mask in auth_config
SENSITIVE_AUTH_KEYS = {"password", "token", "api_key", "secret", "credential", "auth_token"}


def _mask_auth_config(auth_config: dict[str, Any]) -> dict[str, Any]:
    """Mask sensitive fields in auth_config for API responses."""
    if not auth_config:
        return {}

    masked = {}
    for key, value in auth_config.items():
        # Check if the key contains any sensitive word
        key_lower = key.lower()
        if any(sensitive in key_lower for sensitive in SENSITIVE_AUTH_KEYS):
            # Mask the value but indicate it's set
            if value:
                masked[key] = "********"
            else:
                masked[key] = ""
        else:
            masked[key] = value
    return masked


def _pattern_to_response(pattern: Any) -> PatternResponse:
    """Convert a SecurityPattern to PatternResponse."""
    return PatternResponse(
        id=pattern.id,
        name=pattern.name,
        description=pattern.description,
        category=pattern.category.value,
        pattern_type=pattern.pattern_type.value,
        pattern=pattern.pattern,
        severity=pattern.severity.value,
        enabled=pattern.enabled,
        tags=pattern.tags,
        extra_data=pattern.extra_data,
        source=pattern.source.value,
        feed_id=pattern.feed_id,
        feed_name=pattern.feed.name if pattern.feed else None,
        examples=pattern.examples,
        references=pattern.references,
        hit_count=pattern.hit_count,
        last_hit_at=pattern.last_hit_at.isoformat() if pattern.last_hit_at else None,
        created_at=pattern.created_at.isoformat(),
        updated_at=pattern.updated_at.isoformat(),
    )


def _feed_to_response(feed: Any) -> FeedResponse:
    """Convert a SecurityPatternFeed to FeedResponse."""
    return FeedResponse(
        id=feed.id,
        name=feed.name,
        description=feed.description,
        url=feed.url,
        enabled=feed.enabled,
        update_interval_hours=feed.update_interval_hours,
        auth_type=feed.auth_type,
        auth_config=_mask_auth_config(feed.auth_config),
        field_mapping=feed.field_mapping,
        last_fetch_at=feed.last_fetch_at.isoformat() if feed.last_fetch_at else None,
        last_fetch_status=feed.last_fetch_status,
        last_fetch_message=feed.last_fetch_message,
        pattern_count=feed.pattern_count,
        created_at=feed.created_at.isoformat(),
        updated_at=feed.updated_at.isoformat(),
    )


# --- Pattern Endpoints ---


@router.get("", response_model=PatternListResponse)
async def list_patterns(
    enabled: bool | None = Query(None, description="Filter by enabled status"),
    category: PatternCategory | None = Query(None, description="Filter by category"),
    source: PatternSource | None = Query(None, description="Filter by source"),
    feed_id: UUID | None = Query(None, description="Filter by feed"),
    tags: list[str] | None = Query(None, description="Filter by tags"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> PatternListResponse:
    """List all security patterns with filtering."""
    service = SecurityPatternService(session)
    patterns, total = await service.get_patterns(
        enabled=enabled,
        category=category,
        source=source,
        feed_id=feed_id,
        tags=tags,
        limit=limit,
        offset=offset,
    )

    items = [_pattern_to_response(p) for p in patterns]
    return PatternListResponse(items=items, total=total)


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> StatsResponse:
    """Get security pattern statistics."""
    service = SecurityPatternService(session)
    stats = await service.get_stats()
    return StatsResponse(**stats)


@router.get("/{pattern_id}", response_model=PatternResponse)
async def get_pattern(
    pattern_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> PatternResponse:
    """Get a specific security pattern."""
    service = SecurityPatternService(session)
    pattern = await service.get_pattern(pattern_id)

    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    return _pattern_to_response(pattern)


@router.post("", response_model=PatternResponse, status_code=201)
async def create_pattern(
    data: PatternCreate,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> PatternResponse:
    """Create a new security pattern."""
    service = SecurityPatternService(session)

    try:
        pattern = await service.create_pattern(
            name=data.name,
            description=data.description,
            category=data.category,
            pattern_type=data.pattern_type,
            pattern=data.pattern,
            severity=data.severity,
            enabled=data.enabled,
            tags=data.tags,
            extra_data=data.extra_data,
            source=PatternSource.USER,
            examples=data.examples,
            references=data.references,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    return _pattern_to_response(pattern)


@router.patch("/{pattern_id}", response_model=PatternResponse)
async def update_pattern(
    pattern_id: UUID,
    data: PatternUpdate,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> PatternResponse:
    """Update a security pattern."""
    service = SecurityPatternService(session)
    pattern = await service.get_pattern(pattern_id)

    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    update_data = data.model_dump(exclude_unset=True)

    try:
        updated_pattern = await service.update_pattern(pattern_id, **update_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    if not updated_pattern:
        raise HTTPException(status_code=404, detail="Pattern not found after update")

    return _pattern_to_response(updated_pattern)


@router.delete("/{pattern_id}", status_code=204)
async def delete_pattern(
    pattern_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> None:
    """Delete a security pattern (not allowed for builtin patterns)."""
    service = SecurityPatternService(session)
    pattern = await service.get_pattern(pattern_id)

    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    try:
        await service.delete_pattern(pattern_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.post("/{pattern_id}/enable", response_model=PatternResponse)
async def enable_pattern(
    pattern_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> PatternResponse:
    """Enable a security pattern."""
    service = SecurityPatternService(session)
    pattern = await service.get_pattern(pattern_id)

    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    updated_pattern = await service.update_pattern(pattern_id, enabled=True)

    if not updated_pattern:
        raise HTTPException(status_code=404, detail="Pattern not found after update")

    return _pattern_to_response(updated_pattern)


@router.post("/{pattern_id}/disable", response_model=PatternResponse)
async def disable_pattern(
    pattern_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> PatternResponse:
    """Disable a security pattern."""
    service = SecurityPatternService(session)
    pattern = await service.get_pattern(pattern_id)

    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")

    updated_pattern = await service.update_pattern(pattern_id, enabled=False)

    if not updated_pattern:
        raise HTTPException(status_code=404, detail="Pattern not found after update")

    return _pattern_to_response(updated_pattern)


@router.post("/test", response_model=PatternTestResponse)
async def test_pattern(
    data: PatternTestRequest,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> PatternTestResponse:
    """Test a pattern against sample text without saving."""
    service = SecurityPatternService(session)
    result = await service.test_pattern(
        pattern_type=data.pattern_type,
        pattern=data.pattern,
        test_text=data.test_text,
    )
    return PatternTestResponse(
        success=result["success"],
        error=result.get("error"),
        matches=result["matches"],
        match_count=result.get("match_count", 0),
    )


@router.post("/match", response_model=PatternMatchListResponse)
async def match_text(
    data: PatternMatchRequest,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> PatternMatchListResponse:
    """Match text against all enabled patterns."""
    service = SecurityPatternService(session)
    matches = await service.match_text(
        text=data.text,
        categories=data.categories,
    )

    items = [
        PatternMatchResponse(
            pattern_id=m.pattern_id,
            pattern_name=m.pattern_name,
            category=m.category.value,
            severity=m.severity.value,
            matched_text=m.matched_text,
            match_start=m.match_start,
            match_end=m.match_end,
            context=m.context,
        )
        for m in matches
    ]

    return PatternMatchListResponse(matches=items, total_matches=len(items))


# --- Feed Endpoints ---


@router.get("/feeds", response_model=FeedListResponse)
async def list_feeds(
    enabled: bool | None = Query(None, description="Filter by enabled status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> FeedListResponse:
    """List all pattern feeds."""
    service = SecurityPatternService(session)
    feeds, total = await service.get_feeds(
        enabled=enabled,
        limit=limit,
        offset=offset,
    )

    items = [_feed_to_response(f) for f in feeds]
    return FeedListResponse(items=items, total=total)


@router.get("/feeds/{feed_id}", response_model=FeedResponse)
async def get_feed(
    feed_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user),
) -> FeedResponse:
    """Get a specific pattern feed."""
    service = SecurityPatternService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    return _feed_to_response(feed)


@router.post("/feeds", response_model=FeedResponse, status_code=201)
async def create_feed(
    data: FeedCreate,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> FeedResponse:
    """Create a new pattern feed."""
    service = SecurityPatternService(session)
    feed = await service.create_feed(
        name=data.name,
        description=data.description,
        url=str(data.url),
        enabled=data.enabled,
        update_interval_hours=data.update_interval_hours,
        auth_type=data.auth_type,
        auth_config=data.auth_config,
        field_mapping=data.field_mapping,
    )

    return _feed_to_response(feed)


@router.patch("/feeds/{feed_id}", response_model=FeedResponse)
async def update_feed(
    feed_id: UUID,
    data: FeedUpdate,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> FeedResponse:
    """Update a pattern feed."""
    service = SecurityPatternService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    update_data = data.model_dump(exclude_unset=True)
    if "url" in update_data:
        update_data["url"] = str(update_data["url"])

    updated_feed = await service.update_feed(feed_id, **update_data)

    if not updated_feed:
        raise HTTPException(status_code=404, detail="Feed not found after update")

    return _feed_to_response(updated_feed)


@router.delete("/feeds/{feed_id}", status_code=204)
async def delete_feed(
    feed_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> None:
    """Delete a pattern feed and all its patterns."""
    service = SecurityPatternService(session)
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
) -> dict[str, str]:
    """Trigger a feed fetch (runs in background)."""
    service = SecurityPatternService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    async def do_fetch() -> None:
        async with AsyncSessionLocal() as s:
            svc = SecurityPatternService(s)
            await svc.fetch_feed(feed_id)

    background_tasks.add_task(do_fetch)

    return {"message": "Feed fetch started", "feed_id": str(feed_id)}


@router.post("/feeds/{feed_id}/enable", response_model=FeedResponse)
async def enable_feed(
    feed_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> FeedResponse:
    """Enable a pattern feed."""
    service = SecurityPatternService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    updated_feed = await service.update_feed(feed_id, enabled=True)

    if not updated_feed:
        raise HTTPException(status_code=404, detail="Feed not found after update")

    return _feed_to_response(updated_feed)


@router.post("/feeds/{feed_id}/disable", response_model=FeedResponse)
async def disable_feed(
    feed_id: UUID,
    session: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(require_admin),
) -> FeedResponse:
    """Disable a pattern feed."""
    service = SecurityPatternService(session)
    feed = await service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")

    updated_feed = await service.update_feed(feed_id, enabled=False)

    if not updated_feed:
        raise HTTPException(status_code=404, detail="Feed not found after update")

    return _feed_to_response(updated_feed)
