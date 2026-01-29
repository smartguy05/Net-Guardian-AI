"""Chat and natural language query API endpoints."""

from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.db.session import get_async_session
from app.models.alert import Alert, AlertStatus
from app.models.anomaly import AnomalyDetection, AnomalyStatus
from app.models.device import Device, DeviceStatus
from app.models.raw_event import EventType, RawEvent
from app.models.user import User
from app.services.llm_service import LLMModel, get_llm_service

router = APIRouter()


# Pydantic schemas
class ChatMessage(BaseModel):
    role: str = Field(..., description="Message role: user or assistant")
    content: str = Field(..., description="Message content")


class QueryRequest(BaseModel):
    query: str = Field(..., description="Natural language query about the network")
    model: str | None = Field(None, description="Model to use: fast, default, or deep")


class QueryResponse(BaseModel):
    query: str
    response: str
    model_used: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(..., description="Conversation history")
    stream: bool = Field(False, description="Whether to stream the response")


class ChatResponse(BaseModel):
    response: str
    model_used: str


class IncidentSummaryRequest(BaseModel):
    alert_ids: list[UUID] | None = Field(None, description="Alert IDs to include")
    anomaly_ids: list[UUID] | None = Field(None, description="Anomaly IDs to include")
    device_id: UUID | None = Field(None, description="Device to summarize incidents for")
    hours: int = Field(24, description="Time range in hours", ge=1, le=720)


class IncidentSummaryResponse(BaseModel):
    title: str
    executive_summary: str
    technical_summary: str | None = None
    timeline: list[str] = []
    impact_assessment: str | None = None
    root_cause: str | None = None
    recommendations: list[str] = []
    severity: str
    confidence: int
    alert_count: int
    anomaly_count: int
    event_count: int


class LLMStatusResponse(BaseModel):
    enabled: bool
    configured: bool
    model_default: str
    model_fast: str
    model_deep: str


async def _build_network_context(session: AsyncSession) -> dict[str, Any]:
    """Build network context for LLM queries."""
    now = datetime.now(UTC)
    last_24h = now - timedelta(hours=24)

    context: dict[str, Any] = {}

    # Get overview stats
    device_result = await session.execute(select(Device))
    devices = device_result.scalars().all()

    active_devices = len([d for d in devices if d.status == DeviceStatus.ACTIVE])

    # Event counts
    event_count_result = await session.execute(
        select(func.count()).select_from(RawEvent).where(RawEvent.timestamp >= last_24h)
    )
    total_events_24h = event_count_result.scalar() or 0

    # DNS counts
    dns_count_result = await session.execute(
        select(func.count())
        .select_from(RawEvent)
        .where(RawEvent.timestamp >= last_24h)
        .where(RawEvent.event_type == EventType.DNS)
    )
    dns_queries_24h = dns_count_result.scalar() or 0

    blocked_count_result = await session.execute(
        select(func.count())
        .select_from(RawEvent)
        .where(RawEvent.timestamp >= last_24h)
        .where(RawEvent.event_type == EventType.DNS)
        .where(RawEvent.response_status == "blocked")
    )
    blocked_queries_24h = blocked_count_result.scalar() or 0

    # Active alerts
    active_alerts_result = await session.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED]))
    )
    active_alerts = active_alerts_result.scalar() or 0

    context["stats"] = {
        "active_devices": active_devices,
        "total_events_24h": total_events_24h,
        "dns_queries_24h": dns_queries_24h,
        "blocked_queries_24h": blocked_queries_24h,
        "active_alerts": active_alerts,
    }

    # Device summary
    context["devices"] = [
        {
            "hostname": d.hostname,
            "mac_address": d.mac_address,
            "device_type": d.device_type.value,
            "status": d.status.value,
            "ip_addresses": d.ip_addresses,
        }
        for d in devices[:20]
    ]

    # Recent alerts
    alerts_result = await session.execute(
        select(Alert)
        .where(Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED]))
        .order_by(Alert.timestamp.desc())
        .limit(10)
    )
    alerts = alerts_result.scalars().all()
    context["alerts"] = [
        {
            "title": a.title,
            "severity": a.severity.value,
            "timestamp": a.timestamp.isoformat(),
        }
        for a in alerts
    ]

    # Recent anomalies
    anomalies_result = await session.execute(
        select(AnomalyDetection)
        .where(AnomalyDetection.status == AnomalyStatus.ACTIVE)
        .order_by(AnomalyDetection.detected_at.desc())
        .limit(10)
    )
    anomalies = anomalies_result.scalars().all()
    context["anomalies"] = [
        {
            "description": an.description,
            "severity": an.severity,
            "detected_at": an.detected_at.isoformat(),
        }
        for an in anomalies
    ]

    return context


@router.get("/status", response_model=LLMStatusResponse)
async def get_llm_status(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> LLMStatusResponse:
    """Get LLM service status and configuration."""
    from app.config import settings

    llm_service = get_llm_service()

    return LLMStatusResponse(
        enabled=settings.llm_enabled,
        configured=llm_service.is_enabled,
        model_default=settings.llm_model_default,
        model_fast=settings.llm_model_fast,
        model_deep=settings.llm_model_deep,
    )


@router.post("/query", response_model=QueryResponse)
async def query_network(
    request: QueryRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> QueryResponse:
    """Ask a natural language question about the network.

    This endpoint uses Claude to answer questions about:
    - Device status and activity
    - Network security posture
    - Recent alerts and anomalies
    - Traffic patterns and trends
    """
    llm_service = get_llm_service()

    if not llm_service.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM service is not enabled. Please configure your Anthropic API key.",
        )

    # Determine model
    model_type = LLMModel.DEFAULT
    if request.model:
        model_map = {"fast": LLMModel.FAST, "default": LLMModel.DEFAULT, "deep": LLMModel.DEEP}
        model_type = model_map.get(request.model, LLMModel.DEFAULT)

    # Build network context
    context = await _build_network_context(session)

    # Query the LLM
    response = await llm_service.query_network(
        query=request.query,
        context=context,
        model_type=model_type,
    )

    from app.config import settings

    model_id = {
        LLMModel.FAST: settings.llm_model_fast,
        LLMModel.DEFAULT: settings.llm_model_default,
        LLMModel.DEEP: settings.llm_model_deep,
    }[model_type]

    return QueryResponse(
        query=request.query,
        response=response,
        model_used=model_id,
    )


@router.post("/chat")
async def chat(
    request: ChatRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse | ChatResponse:
    """Chat with the AI assistant about your network.

    Supports both regular and streaming responses. For streaming,
    set stream=true in the request body.
    """
    llm_service = get_llm_service()

    if not llm_service.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM service is not enabled. Please configure your Anthropic API key.",
        )

    # Build network context
    context = await _build_network_context(session)

    # Convert messages to expected format
    messages = [{"role": m.role, "content": m.content} for m in request.messages]

    if request.stream:
        # Return streaming response
        async def generate() -> AsyncGenerator[str, None]:
            async for chunk in llm_service.stream_chat(messages, context):
                yield f"data: {chunk}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            },
        )
    else:
        # Non-streaming: collect full response
        full_response = ""
        async for chunk in llm_service.stream_chat(messages, context):
            full_response += chunk

        from app.config import settings

        return ChatResponse(
            response=full_response,
            model_used=settings.llm_model_default,
        )


@router.post("/summarize-incident", response_model=IncidentSummaryResponse)
async def summarize_incident(
    request: IncidentSummaryRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> IncidentSummaryResponse:
    """Generate an incident summary from alerts and anomalies.

    This endpoint correlates related security events and generates
    a comprehensive incident report using Claude.
    """
    llm_service = get_llm_service()

    if not llm_service.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM service is not enabled. Please configure your Anthropic API key.",
        )

    cutoff = datetime.now(UTC) - timedelta(hours=request.hours)

    # Gather alerts
    alerts_query = select(Alert).where(Alert.timestamp >= cutoff)
    if request.alert_ids:
        alerts_query = alerts_query.where(Alert.id.in_(request.alert_ids))
    if request.device_id:
        alerts_query = alerts_query.where(Alert.device_id == request.device_id)

    alerts_result = await session.execute(alerts_query.order_by(Alert.timestamp.desc()).limit(50))
    alerts = alerts_result.scalars().all()

    # Gather anomalies
    anomalies_query = select(AnomalyDetection).where(AnomalyDetection.detected_at >= cutoff)
    if request.anomaly_ids:
        anomalies_query = anomalies_query.where(AnomalyDetection.id.in_(request.anomaly_ids))
    if request.device_id:
        anomalies_query = anomalies_query.where(AnomalyDetection.device_id == request.device_id)

    anomalies_result = await session.execute(
        anomalies_query.order_by(AnomalyDetection.detected_at.desc()).limit(50)
    )
    anomalies = anomalies_result.scalars().all()

    # Gather related events
    events_query = select(RawEvent).where(RawEvent.timestamp >= cutoff)
    if request.device_id:
        events_query = events_query.where(RawEvent.device_id == request.device_id)

    events_result = await session.execute(
        events_query.order_by(RawEvent.timestamp.desc()).limit(100)
    )
    events = events_result.scalars().all()

    if not alerts and not anomalies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No alerts or anomalies found for the specified criteria",
        )

    # Get device data if single device
    device_data = None
    if request.device_id:
        device_result = await session.execute(select(Device).where(Device.id == request.device_id))
        device = device_result.scalar_one_or_none()
        if device:
            device_data = {
                "hostname": device.hostname,
                "mac_address": device.mac_address,
                "device_type": device.device_type.value,
            }

    # Prepare data for LLM
    alerts_data = [
        {
            "timestamp": a.timestamp.isoformat(),
            "severity": a.severity.value,
            "title": a.title,
            "description": a.description,
        }
        for a in alerts
    ]

    anomalies_data = [
        {
            "detected_at": an.detected_at.isoformat(),
            "anomaly_type": an.anomaly_type.value
            if hasattr(an.anomaly_type, "value")
            else str(an.anomaly_type),
            "description": an.description,
            "severity": an.severity,
        }
        for an in anomalies
    ]

    events_data = [
        {
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type.value if e.event_type else "unknown",
            "domain": e.domain,
            "target_ip": e.target_ip,
        }
        for e in events
    ]

    # Generate summary
    summary = await llm_service.summarize_incident(
        alerts=alerts_data,
        anomalies=anomalies_data,
        events=events_data,
        device_data=device_data,
    )

    return IncidentSummaryResponse(
        title=summary.get("title", "Incident Summary"),
        executive_summary=summary.get("executive_summary", "No summary available"),
        technical_summary=summary.get("technical_summary"),
        timeline=summary.get("timeline", []),
        impact_assessment=summary.get("impact_assessment"),
        root_cause=summary.get("root_cause"),
        recommendations=summary.get("recommendations", []),
        severity=summary.get("severity", "medium"),
        confidence=summary.get("confidence", 50),
        alert_count=len(alerts),
        anomaly_count=len(anomalies),
        event_count=len(events),
    )
