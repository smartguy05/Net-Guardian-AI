"""Alert management API endpoints."""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_operator
from app.db.session import get_async_session
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.device import Device
from app.models.device_baseline import DeviceBaseline
from app.models.raw_event import RawEvent
from app.models.user import User
from app.services.llm_service import get_llm_service, LLMModel

router = APIRouter()


# Pydantic schemas
class AlertResponse(BaseModel):
    id: str
    timestamp: str
    device_id: Optional[str]
    rule_id: str
    severity: str
    title: str
    description: str
    llm_analysis: Optional[Dict[str, Any]]
    status: str
    actions_taken: List[Dict[str, Any]]
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[str]
    resolved_by: Optional[str]
    resolved_at: Optional[str]

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    items: List[AlertResponse]
    total: int


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


def _alert_to_response(alert: Alert) -> AlertResponse:
    return AlertResponse(
        id=str(alert.id),
        timestamp=alert.timestamp.isoformat(),
        device_id=str(alert.device_id) if alert.device_id else None,
        rule_id=alert.rule_id,
        severity=alert.severity.value,
        title=alert.title,
        description=alert.description,
        llm_analysis=alert.llm_analysis,
        status=alert.status.value,
        actions_taken=alert.actions_taken,
        acknowledged_by=str(alert.acknowledged_by) if alert.acknowledged_by else None,
        acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        resolved_by=str(alert.resolved_by) if alert.resolved_by else None,
        resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None,
    )


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    status_filter: Optional[AlertStatus] = Query(None, alias="status"),
    severity: Optional[AlertSeverity] = None,
    device_id: Optional[UUID] = None,
    rule_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> AlertListResponse:
    """List alerts with filtering."""
    # Build query
    query = select(Alert)

    if status_filter:
        query = query.where(Alert.status == status_filter)
    if severity:
        query = query.where(Alert.severity == severity)
    if device_id:
        query = query.where(Alert.device_id == device_id)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get results
    query = query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit)
    result = await session.execute(query)
    alerts = result.scalars().all()

    return AlertListResponse(
        items=[_alert_to_response(a) for a in alerts],
        total=total,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> AlertResponse:
    """Get alert details."""
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return _alert_to_response(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert_status(
    alert_id: UUID,
    update: AlertStatusUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    operator: Annotated[User, Depends(require_operator)],
) -> AlertResponse:
    """Update alert status."""
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    now = datetime.now(timezone.utc)

    # Update status and audit fields
    alert.status = update.status

    if update.status == AlertStatus.ACKNOWLEDGED and not alert.acknowledged_by:
        alert.acknowledged_by = operator.id
        alert.acknowledged_at = now
    elif update.status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
        if not alert.acknowledged_by:
            alert.acknowledged_by = operator.id
            alert.acknowledged_at = now
        alert.resolved_by = operator.id
        alert.resolved_at = now

    await session.commit()
    await session.refresh(alert)

    return _alert_to_response(alert)


class AnalyzeAlertRequest(BaseModel):
    model: Optional[str] = None  # fast, default, or deep


@router.post("/{alert_id}/analyze", response_model=AlertResponse)
async def analyze_alert(
    alert_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    request: Optional[AnalyzeAlertRequest] = None,
) -> AlertResponse:
    """Request LLM analysis for an alert.

    This endpoint uses Claude to analyze the alert with device context,
    behavioral baselines, and recent activity to provide:
    - Threat assessment with confidence score
    - Risk level assessment
    - Likely cause analysis
    - Recommended actions
    - False positive likelihood
    """
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    # Determine which model to use
    model_type = LLMModel.DEFAULT
    if request and request.model:
        model_map = {"fast": LLMModel.FAST, "default": LLMModel.DEFAULT, "deep": LLMModel.DEEP}
        model_type = model_map.get(request.model, LLMModel.DEFAULT)

    # Build alert data
    alert_data = {
        "id": str(alert.id),
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity.value,
        "rule_id": alert.rule_id,
        "timestamp": alert.timestamp.isoformat(),
        "status": alert.status.value,
    }

    # Get device context if available
    device_data = None
    baseline_data = None
    recent_events = None

    if alert.device_id:
        # Fetch device
        device_result = await session.execute(
            select(Device).where(Device.id == alert.device_id)
        )
        device = device_result.scalar_one_or_none()

        if device:
            device_data = {
                "hostname": device.hostname,
                "mac_address": device.mac_address,
                "ip_addresses": device.ip_addresses,
                "device_type": device.device_type.value,
                "manufacturer": device.manufacturer,
                "status": device.status.value,
                "profile_tags": device.profile_tags,
            }

            # Fetch baselines for this device
            baseline_result = await session.execute(
                select(DeviceBaseline).where(DeviceBaseline.device_id == device.id)
            )
            baselines = baseline_result.scalars().all()

            if baselines:
                baseline_data = {}
                for bl in baselines:
                    baseline_data[bl.baseline_type.value] = {
                        "status": bl.status.value,
                        "sample_count": bl.sample_count,
                        **bl.metrics,
                    }

            # Fetch recent events for this device (last 24 hours)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
            events_result = await session.execute(
                select(RawEvent)
                .where(RawEvent.device_id == device.id)
                .where(RawEvent.timestamp >= cutoff)
                .order_by(RawEvent.timestamp.desc())
                .limit(20)
            )
            events = events_result.scalars().all()

            if events:
                recent_events = [
                    {
                        "timestamp": e.timestamp.isoformat(),
                        "event_type": e.event_type.value if e.event_type else "unknown",
                        "domain": e.domain,
                        "target_ip": e.target_ip,
                        "action": e.action,
                    }
                    for e in events
                ]

    # Call LLM service
    llm_service = get_llm_service()
    analysis = await llm_service.analyze_alert(
        alert_data=alert_data,
        device_data=device_data,
        baseline_data=baseline_data,
        recent_events=recent_events,
        model_type=model_type,
    )

    # Store analysis in alert
    alert.llm_analysis = analysis
    await session.commit()
    await session.refresh(alert)

    return _alert_to_response(alert)
