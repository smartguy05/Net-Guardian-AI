"""Log ingestion API endpoints for push sources."""

import structlog
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_async_session
from app.models.log_source import LogSource, SourceType
from app.models.raw_event import RawEvent, EventType, EventSeverity
from app.services.semantic_analysis_service import get_semantic_analysis_service

logger = structlog.get_logger()

router = APIRouter()


# Pydantic schemas
class EventIngest(BaseModel):
    timestamp: Optional[datetime] = None
    event_type: Optional[EventType] = EventType.UNKNOWN
    severity: Optional[EventSeverity] = EventSeverity.INFO
    client_ip: Optional[str] = None
    target_ip: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    raw_message: str
    parsed_fields: Dict[str, Any] = {}


class BatchIngestRequest(BaseModel):
    events: List[EventIngest]


class IngestResponse(BaseModel):
    success: bool
    events_received: int
    events_stored: int
    message: str


async def verify_source_api_key(
    x_source_api_key: Annotated[str, Header()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> LogSource:
    """Verify the source API key and return the source."""
    result = await session.execute(
        select(LogSource).where(
            LogSource.api_key == x_source_api_key,
            LogSource.source_type == SourceType.API_PUSH,
            LogSource.enabled == True,
        )
    )
    source = result.scalar_one_or_none()

    if not source:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or disabled source API key",
        )

    return source


@router.post("/ingest", response_model=IngestResponse)
async def ingest_events(
    request: BatchIngestRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    source: Annotated[LogSource, Depends(verify_source_api_key)],
) -> IngestResponse:
    """Ingest a batch of events from a push source."""
    if not request.events:
        return IngestResponse(
            success=True,
            events_received=0,
            events_stored=0,
            message="No events to process",
        )

    now = datetime.now(timezone.utc)
    events_stored = 0

    for event_data in request.events:
        event = RawEvent(
            id=uuid4(),
            timestamp=event_data.timestamp or now,
            source_id=source.id,
            event_type=event_data.event_type,
            severity=event_data.severity,
            client_ip=event_data.client_ip,
            target_ip=event_data.target_ip,
            domain=event_data.domain,
            port=event_data.port,
            protocol=event_data.protocol,
            action=event_data.action,
            raw_message=event_data.raw_message,
            parsed_fields=event_data.parsed_fields,
        )
        session.add(event)
        events_stored += 1

    # Update source metadata
    source.last_event_at = now
    source.event_count += events_stored
    source.last_error = None

    await session.commit()

    # Process events for semantic analysis (non-blocking, best-effort)
    try:
        semantic_service = get_semantic_analysis_service(session)
        for event_data in request.events:
            # Re-query the event to get the ORM object
            # Note: For better performance, could store events in a list and process after commit
            pass  # Semantic analysis is handled async by scheduler for batch efficiency
    except Exception as e:
        logger.warning(
            "semantic_analysis_batch_error",
            source_id=source.id,
            events_count=events_stored,
            error=str(e),
        )

    return IngestResponse(
        success=True,
        events_received=len(request.events),
        events_stored=events_stored,
        message=f"Successfully stored {events_stored} events",
    )


@router.post("/ingest/json", response_model=IngestResponse)
async def ingest_json_events(
    request: BatchIngestRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    source: Annotated[LogSource, Depends(verify_source_api_key)],
) -> IngestResponse:
    """Ingest JSON-formatted events (same as /ingest)."""
    return await ingest_events(request, session, source)


class SyslogEvent(BaseModel):
    message: str
    facility: Optional[int] = None
    severity: Optional[int] = None
    timestamp: Optional[datetime] = None
    hostname: Optional[str] = None
    app_name: Optional[str] = None


class SyslogBatchRequest(BaseModel):
    events: List[SyslogEvent]


@router.post("/ingest/syslog", response_model=IngestResponse)
async def ingest_syslog_events(
    request: SyslogBatchRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    source: Annotated[LogSource, Depends(verify_source_api_key)],
) -> IngestResponse:
    """Ingest syslog-formatted events."""
    if not request.events:
        return IngestResponse(
            success=True,
            events_received=0,
            events_stored=0,
            message="No events to process",
        )

    now = datetime.now(timezone.utc)
    events_stored = 0

    # Map syslog severity to our severity enum
    severity_map = {
        0: EventSeverity.CRITICAL,  # Emergency
        1: EventSeverity.CRITICAL,  # Alert
        2: EventSeverity.CRITICAL,  # Critical
        3: EventSeverity.ERROR,     # Error
        4: EventSeverity.WARNING,   # Warning
        5: EventSeverity.INFO,      # Notice
        6: EventSeverity.INFO,      # Informational
        7: EventSeverity.DEBUG,     # Debug
    }

    for syslog_event in request.events:
        severity = EventSeverity.INFO
        if syslog_event.severity is not None:
            severity = severity_map.get(syslog_event.severity, EventSeverity.INFO)

        event = RawEvent(
            id=uuid4(),
            timestamp=syslog_event.timestamp or now,
            source_id=source.id,
            event_type=EventType.SYSTEM,
            severity=severity,
            raw_message=syslog_event.message,
            parsed_fields={
                "facility": syslog_event.facility,
                "syslog_severity": syslog_event.severity,
                "hostname": syslog_event.hostname,
                "app_name": syslog_event.app_name,
            },
        )
        session.add(event)
        events_stored += 1

    # Update source metadata
    source.last_event_at = now
    source.event_count += events_stored
    source.last_error = None

    await session.commit()

    return IngestResponse(
        success=True,
        events_received=len(request.events),
        events_stored=events_stored,
        message=f"Successfully stored {events_stored} syslog events",
    )
