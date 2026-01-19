"""Device baseline API endpoints."""

from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin
from app.db.session import get_async_session
from app.models.device_baseline import DeviceBaseline, BaselineStatus, BaselineType
from app.models.user import User
from app.services.baseline_service import get_baseline_service

router = APIRouter()


# Pydantic schemas
class BaselineResponse(BaseModel):
    id: str
    device_id: str
    baseline_type: str
    status: str
    metrics: Dict[str, Any]
    sample_count: int
    min_samples: int
    baseline_window_days: int
    last_calculated: Optional[str]
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class BaselineListResponse(BaseModel):
    items: List[BaselineResponse]
    total: int


class BaselineUpdateRequest(BaseModel):
    baseline_window_days: Optional[int] = None
    min_samples: Optional[int] = None


class BaselineRecalculateResponse(BaseModel):
    device_id: str
    baselines: Dict[str, BaselineResponse]
    message: str


class BulkUpdateResponse(BaseModel):
    updated: int
    learning: int
    ready: int
    stale: int
    errors: int


def _baseline_to_response(baseline: DeviceBaseline) -> BaselineResponse:
    return BaselineResponse(
        id=str(baseline.id),
        device_id=str(baseline.device_id),
        baseline_type=baseline.baseline_type.value,
        status=baseline.status.value,
        metrics=baseline.metrics,
        sample_count=baseline.sample_count,
        min_samples=baseline.min_samples,
        baseline_window_days=baseline.baseline_window_days,
        last_calculated=(
            baseline.last_calculated.isoformat() if baseline.last_calculated else None
        ),
        created_at=baseline.created_at.isoformat(),
        updated_at=baseline.updated_at.isoformat(),
    )


@router.get("", response_model=BaselineListResponse)
async def list_baselines(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    device_id: Optional[UUID] = None,
    baseline_type: Optional[BaselineType] = None,
    status_filter: Optional[BaselineStatus] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> BaselineListResponse:
    """List device baselines with filtering."""
    query = select(DeviceBaseline)

    if device_id:
        query = query.where(DeviceBaseline.device_id == device_id)
    if baseline_type:
        query = query.where(DeviceBaseline.baseline_type == baseline_type)
    if status_filter:
        query = query.where(DeviceBaseline.status == status_filter)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get results
    query = query.order_by(DeviceBaseline.updated_at.desc()).offset(offset).limit(limit)
    result = await session.execute(query)
    baselines = result.scalars().all()

    return BaselineListResponse(
        items=[_baseline_to_response(b) for b in baselines],
        total=total,
    )


@router.get("/device/{device_id}", response_model=BaselineListResponse)
async def get_device_baselines(
    device_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> BaselineListResponse:
    """Get all baselines for a specific device."""
    result = await session.execute(
        select(DeviceBaseline).where(DeviceBaseline.device_id == device_id)
    )
    baselines = result.scalars().all()

    return BaselineListResponse(
        items=[_baseline_to_response(b) for b in baselines],
        total=len(baselines),
    )


@router.get("/{baseline_id}", response_model=BaselineResponse)
async def get_baseline(
    baseline_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> BaselineResponse:
    """Get baseline details."""
    result = await session.execute(
        select(DeviceBaseline).where(DeviceBaseline.id == baseline_id)
    )
    baseline = result.scalar_one_or_none()

    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Baseline not found",
        )

    return _baseline_to_response(baseline)


@router.patch("/{baseline_id}", response_model=BaselineResponse)
async def update_baseline(
    baseline_id: UUID,
    update: BaselineUpdateRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> BaselineResponse:
    """Update baseline configuration (admin only)."""
    result = await session.execute(
        select(DeviceBaseline).where(DeviceBaseline.id == baseline_id)
    )
    baseline = result.scalar_one_or_none()

    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Baseline not found",
        )

    if update.baseline_window_days is not None:
        baseline.baseline_window_days = update.baseline_window_days
    if update.min_samples is not None:
        baseline.min_samples = update.min_samples

    await session.commit()
    await session.refresh(baseline)

    return _baseline_to_response(baseline)


@router.post("/device/{device_id}/recalculate", response_model=BaselineRecalculateResponse)
async def recalculate_device_baselines(
    device_id: UUID,
    _admin: Annotated[User, Depends(require_admin)],
    baseline_type: Optional[BaselineType] = None,
) -> BaselineRecalculateResponse:
    """Recalculate baselines for a device (admin only)."""
    service = get_baseline_service()

    try:
        baselines = await service.update_device_baseline(device_id, baseline_type)

        return BaselineRecalculateResponse(
            device_id=str(device_id),
            baselines={
                k: _baseline_to_response(v) for k, v in baselines.items()
            },
            message="Baselines recalculated successfully",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to recalculate baselines: {str(e)}",
        )


@router.post("/recalculate-all", response_model=BulkUpdateResponse)
async def recalculate_all_baselines(
    _admin: Annotated[User, Depends(require_admin)],
) -> BulkUpdateResponse:
    """Recalculate baselines for all active devices (admin only)."""
    service = get_baseline_service()

    try:
        stats = await service.update_all_device_baselines()
        return BulkUpdateResponse(**stats)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to recalculate baselines: {str(e)}",
        )


@router.get("/stats/summary")
async def get_baseline_stats(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> Dict[str, Any]:
    """Get summary statistics for baselines."""
    # Count by status
    status_counts = {}
    for bs in BaselineStatus:
        result = await session.execute(
            select(func.count()).where(DeviceBaseline.status == bs)
        )
        status_counts[bs.value] = result.scalar() or 0

    # Count by type
    type_counts = {}
    for bt in BaselineType:
        result = await session.execute(
            select(func.count()).where(DeviceBaseline.baseline_type == bt)
        )
        type_counts[bt.value] = result.scalar() or 0

    # Total baselines
    total_result = await session.execute(select(func.count()).select_from(DeviceBaseline))
    total = total_result.scalar() or 0

    return {
        "total": total,
        "by_status": status_counts,
        "by_type": type_counts,
    }
