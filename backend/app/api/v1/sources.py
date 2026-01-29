"""Log source management API endpoints (Admin only)."""

import secrets
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import require_admin
from app.collectors.registry import CollectorRegistry, get_collector
from app.db.session import get_async_session
from app.models.log_source import LogSource, ParserType, SourceType
from app.models.user import User

logger = structlog.get_logger()

router = APIRouter()


# Pydantic schemas
class LogSourceCreate(BaseModel):
    id: str
    name: str
    description: str | None = None
    source_type: SourceType
    parser_type: ParserType
    config: dict[str, Any] = {}
    parser_config: dict[str, Any] = {}


class LogSourceUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    parser_config: dict[str, Any] | None = None


class LogSourceResponse(BaseModel):
    id: str
    name: str
    description: str | None
    source_type: str
    enabled: bool
    config: dict[str, Any]
    parser_type: str
    parser_config: dict[str, Any]
    api_key: str | None
    last_event_at: str | None
    last_error: str | None
    event_count: int
    created_at: str

    class Config:
        from_attributes = True


class LogSourceListResponse(BaseModel):
    items: list[LogSourceResponse]
    total: int


class TestSourceResult(BaseModel):
    success: bool
    message: str
    sample_events: list[dict[str, Any]] = []


def _source_to_response(source: LogSource) -> LogSourceResponse:
    # Mask sensitive config fields
    safe_config = {**source.config}
    for key in ["password", "api_key", "secret", "token"]:
        if key in safe_config:
            safe_config[key] = "********"

    return LogSourceResponse(
        id=source.id,
        name=source.name,
        description=source.description,
        source_type=source.source_type.value,
        enabled=source.enabled,
        config=safe_config,
        parser_type=source.parser_type.value,
        parser_config=source.parser_config,
        api_key=source.api_key,
        last_event_at=source.last_event_at.isoformat() if source.last_event_at else None,
        last_error=source.last_error,
        event_count=source.event_count,
        created_at=source.created_at.isoformat(),
    )


@router.get("", response_model=LogSourceListResponse)
async def list_sources(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> LogSourceListResponse:
    """List all configured log sources."""
    result = await session.execute(select(LogSource).order_by(LogSource.created_at.desc()))
    sources = result.scalars().all()

    return LogSourceListResponse(
        items=[_source_to_response(s) for s in sources],
        total=len(sources),
    )


@router.post("", response_model=LogSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    source_data: LogSourceCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> LogSourceResponse:
    """Create a new log source."""
    # Check for existing ID
    existing = await session.execute(
        select(LogSource).where(LogSource.id == source_data.id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Log source with ID '{source_data.id}' already exists",
        )

    # Generate API key for push sources
    api_key = None
    if source_data.source_type == SourceType.API_PUSH:
        api_key = secrets.token_urlsafe(32)

    # Create source
    source = LogSource(
        id=source_data.id,
        name=source_data.name,
        description=source_data.description,
        source_type=source_data.source_type,
        parser_type=source_data.parser_type,
        config=source_data.config,
        parser_config=source_data.parser_config,
        api_key=api_key,
        enabled=True,
    )

    session.add(source)
    await session.commit()
    await session.refresh(source)

    return _source_to_response(source)


@router.get("/{source_id}", response_model=LogSourceResponse)
async def get_source(
    source_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> LogSourceResponse:
    """Get log source details."""
    result = await session.execute(select(LogSource).where(LogSource.id == source_id))
    source = result.scalar_one_or_none()

    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log source not found",
        )

    return _source_to_response(source)


@router.put("/{source_id}", response_model=LogSourceResponse)
async def update_source(
    source_id: str,
    source_data: LogSourceUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> LogSourceResponse:
    """Update log source configuration."""
    result = await session.execute(select(LogSource).where(LogSource.id == source_id))
    source = result.scalar_one_or_none()

    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log source not found",
        )

    if source_data.name is not None:
        source.name = source_data.name
    if source_data.description is not None:
        source.description = source_data.description
    if source_data.enabled is not None:
        source.enabled = source_data.enabled
    if source_data.config is not None:
        source.config = source_data.config
    if source_data.parser_config is not None:
        source.parser_config = source_data.parser_config

    await session.commit()
    await session.refresh(source)

    return _source_to_response(source)


@router.delete("/{source_id}")
async def delete_source(
    source_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> dict[str, str]:
    """Delete a log source."""
    result = await session.execute(select(LogSource).where(LogSource.id == source_id))
    source = result.scalar_one_or_none()

    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log source not found",
        )

    await session.delete(source)
    await session.commit()

    return {"message": "Log source deleted successfully"}


@router.post("/{source_id}/test", response_model=TestSourceResult)
async def test_source(
    source_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> TestSourceResult:
    """Test log source connectivity and parsing."""
    result = await session.execute(select(LogSource).where(LogSource.id == source_id))
    source = result.scalar_one_or_none()

    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Log source not found",
        )

    # Handle API_PUSH sources - just validate configuration
    if source.source_type == SourceType.API_PUSH:
        if source.api_key:
            return TestSourceResult(
                success=True,
                message="API Push source is configured. Use the API key to push events to /api/v1/logs/ingest",
                sample_events=[],
            )
        else:
            return TestSourceResult(
                success=False,
                message="API Push source is missing API key",
                sample_events=[],
            )

    # For API_PULL and FILE_WATCH, use collector's test_connection method
    try:
        # Check if collector is registered for this source type
        if not CollectorRegistry.is_registered(source.source_type):
            return TestSourceResult(
                success=False,
                message=f"No collector registered for source type: {source.source_type.value}",
                sample_events=[],
            )

        # Create collector instance
        collector = get_collector(source)

        # Test the connection
        success, message = await collector.test_connection()

        # If successful for API_PULL, try to fetch sample events
        sample_events = []
        if success and source.source_type == SourceType.API_PULL:
            try:
                # Poll once to get sample events
                results = await collector._poll_once()  # type: ignore[attr-defined]
                sample_events = [
                    {
                        "event_type": r.event_type.value if r.event_type else None,
                        "severity": r.severity.value if r.severity else None,
                        "client_ip": r.client_ip,
                        "domain": r.domain,
                        "action": r.action,
                        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    }
                    for r in results[:5]  # Limit to 5 sample events
                ]
                if results:
                    message = f"{message}. Retrieved {len(results)} events."
            except Exception as e:
                logger.warning(
                    "test_source_sample_failed",
                    source_id=source_id,
                    error=str(e),
                )
                # Don't fail the test, just note we couldn't get samples
                message = f"{message}. Could not fetch sample events: {str(e)}"

        # Clean up collector
        await collector.stop()

        logger.info(
            "test_source_result",
            source_id=source_id,
            success=success,
            message=message,
        )

        return TestSourceResult(
            success=success,
            message=message,
            sample_events=sample_events,
        )

    except Exception as e:
        logger.error(
            "test_source_error",
            source_id=source_id,
            error=str(e),
        )
        return TestSourceResult(
            success=False,
            message=f"Test failed: {str(e)}",
            sample_events=[],
        )
