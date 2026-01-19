"""Anomaly detection API endpoints."""

from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_operator, require_admin
from app.db.session import get_async_session
from app.models.alert import AlertSeverity
from app.models.anomaly import AnomalyDetection, AnomalyStatus, AnomalyType
from app.models.user import User
from app.services.anomaly_service import get_anomaly_service

router = APIRouter()


# Pydantic schemas
class AnomalyResponse(BaseModel):
    id: str
    device_id: str
    anomaly_type: str
    severity: str
    score: float
    status: str
    description: str
    details: Dict[str, Any]
    baseline_comparison: Dict[str, Any]
    detected_at: str
    alert_id: Optional[str]
    reviewed_by: Optional[str]
    reviewed_at: Optional[str]
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class AnomalyListResponse(BaseModel):
    items: List[AnomalyResponse]
    total: int


class AnomalyStatusUpdate(BaseModel):
    status: AnomalyStatus


class DetectionRunRequest(BaseModel):
    time_window_hours: int = 1
    auto_create_alerts: bool = True


class DetectionRunResponse(BaseModel):
    anomalies_detected: int
    alerts_created: int
    anomalies: List[AnomalyResponse]


class BulkDetectionResponse(BaseModel):
    devices_checked: int
    anomalies_detected: int
    alerts_created: int
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
    errors: int


def _anomaly_to_response(anomaly: AnomalyDetection) -> AnomalyResponse:
    return AnomalyResponse(
        id=str(anomaly.id),
        device_id=str(anomaly.device_id),
        anomaly_type=anomaly.anomaly_type.value,
        severity=anomaly.severity.value,
        score=anomaly.score,
        status=anomaly.status.value,
        description=anomaly.description,
        details=anomaly.details,
        baseline_comparison=anomaly.baseline_comparison,
        detected_at=anomaly.detected_at.isoformat(),
        alert_id=str(anomaly.alert_id) if anomaly.alert_id else None,
        reviewed_by=str(anomaly.reviewed_by) if anomaly.reviewed_by else None,
        reviewed_at=anomaly.reviewed_at.isoformat() if anomaly.reviewed_at else None,
        created_at=anomaly.created_at.isoformat(),
        updated_at=anomaly.updated_at.isoformat(),
    )


@router.get("", response_model=AnomalyListResponse)
async def list_anomalies(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    device_id: Optional[UUID] = None,
    anomaly_type: Optional[AnomalyType] = None,
    severity: Optional[AlertSeverity] = None,
    status_filter: Optional[AnomalyStatus] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> AnomalyListResponse:
    """List anomalies with filtering."""
    query = select(AnomalyDetection)

    if device_id:
        query = query.where(AnomalyDetection.device_id == device_id)
    if anomaly_type:
        query = query.where(AnomalyDetection.anomaly_type == anomaly_type)
    if severity:
        query = query.where(AnomalyDetection.severity == severity)
    if status_filter:
        query = query.where(AnomalyDetection.status == status_filter)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get results
    query = query.order_by(AnomalyDetection.detected_at.desc()).offset(offset).limit(limit)
    result = await session.execute(query)
    anomalies = result.scalars().all()

    return AnomalyListResponse(
        items=[_anomaly_to_response(a) for a in anomalies],
        total=total,
    )


@router.get("/active", response_model=AnomalyListResponse)
async def list_active_anomalies(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    min_severity: Optional[AlertSeverity] = None,
    limit: int = Query(100, ge=1, le=1000),
) -> AnomalyListResponse:
    """List all active anomalies."""
    service = get_anomaly_service()
    anomalies = await service.get_active_anomalies(limit=limit, min_severity=min_severity)

    return AnomalyListResponse(
        items=[_anomaly_to_response(a) for a in anomalies],
        total=len(anomalies),
    )


@router.get("/device/{device_id}", response_model=AnomalyListResponse)
async def get_device_anomalies(
    device_id: UUID,
    _current_user: Annotated[User, Depends(get_current_user)],
    status_filter: Optional[AnomalyStatus] = Query(None, alias="status"),
    anomaly_type: Optional[AnomalyType] = None,
    limit: int = Query(100, ge=1, le=1000),
) -> AnomalyListResponse:
    """Get all anomalies for a specific device."""
    service = get_anomaly_service()
    anomalies = await service.get_device_anomalies(
        device_id=device_id,
        status=status_filter,
        anomaly_type=anomaly_type,
        limit=limit,
    )

    return AnomalyListResponse(
        items=[_anomaly_to_response(a) for a in anomalies],
        total=len(anomalies),
    )


@router.get("/{anomaly_id}", response_model=AnomalyResponse)
async def get_anomaly(
    anomaly_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> AnomalyResponse:
    """Get anomaly details."""
    result = await session.execute(
        select(AnomalyDetection).where(AnomalyDetection.id == anomaly_id)
    )
    anomaly = result.scalar_one_or_none()

    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anomaly not found",
        )

    return _anomaly_to_response(anomaly)


@router.patch("/{anomaly_id}", response_model=AnomalyResponse)
async def update_anomaly_status(
    anomaly_id: UUID,
    update: AnomalyStatusUpdate,
    operator: Annotated[User, Depends(require_operator)],
) -> AnomalyResponse:
    """Update anomaly status (operator or admin only)."""
    service = get_anomaly_service()
    anomaly = await service.update_anomaly_status(
        anomaly_id=anomaly_id,
        status=update.status,
        reviewed_by=operator.id,
    )

    if not anomaly:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Anomaly not found",
        )

    return _anomaly_to_response(anomaly)


@router.post("/device/{device_id}/detect", response_model=DetectionRunResponse)
async def run_detection_for_device(
    device_id: UUID,
    request: DetectionRunRequest,
    _admin: Annotated[User, Depends(require_admin)],
) -> DetectionRunResponse:
    """Run anomaly detection for a specific device (admin only)."""
    service = get_anomaly_service()

    try:
        anomalies = await service.run_detection_for_device(
            device_id=device_id,
            time_window_hours=request.time_window_hours,
            auto_create_alerts=request.auto_create_alerts,
        )

        alerts_created = sum(1 for a in anomalies if a.alert_id)

        return DetectionRunResponse(
            anomalies_detected=len(anomalies),
            alerts_created=alerts_created,
            anomalies=[_anomaly_to_response(a) for a in anomalies],
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection failed: {str(e)}",
        )


@router.post("/detect-all", response_model=BulkDetectionResponse)
async def run_detection_for_all_devices(
    request: DetectionRunRequest,
    _admin: Annotated[User, Depends(require_admin)],
) -> BulkDetectionResponse:
    """Run anomaly detection for all active devices (admin only)."""
    service = get_anomaly_service()

    try:
        stats = await service.run_detection_for_all_devices(
            time_window_hours=request.time_window_hours,
            auto_create_alerts=request.auto_create_alerts,
        )

        return BulkDetectionResponse(**stats)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Detection failed: {str(e)}",
        )


@router.get("/stats/summary")
async def get_anomaly_stats(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> Dict[str, Any]:
    """Get summary statistics for anomalies."""
    # Count by status
    status_counts = {}
    for as_ in AnomalyStatus:
        result = await session.execute(
            select(func.count()).where(AnomalyDetection.status == as_)
        )
        status_counts[as_.value] = result.scalar() or 0

    # Count by type
    type_counts = {}
    for at in AnomalyType:
        result = await session.execute(
            select(func.count()).where(AnomalyDetection.anomaly_type == at)
        )
        type_counts[at.value] = result.scalar() or 0

    # Count by severity
    severity_counts = {}
    for sev in AlertSeverity:
        result = await session.execute(
            select(func.count()).where(AnomalyDetection.severity == sev)
        )
        severity_counts[sev.value] = result.scalar() or 0

    # Total anomalies
    total_result = await session.execute(select(func.count()).select_from(AnomalyDetection))
    total = total_result.scalar() or 0

    # Active anomalies
    active_result = await session.execute(
        select(func.count()).where(AnomalyDetection.status == AnomalyStatus.ACTIVE)
    )
    active = active_result.scalar() or 0

    return {
        "total": total,
        "active": active,
        "by_status": status_counts,
        "by_type": type_counts,
        "by_severity": severity_counts,
    }
