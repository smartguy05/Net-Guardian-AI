"""Device management API endpoints."""

from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_operator
from app.db.session import get_async_session
from app.models.device import Device, DeviceStatus, DeviceType
from app.models.user import User
from app.services.quarantine_service import get_quarantine_service

router = APIRouter()


# Pydantic schemas
class DeviceResponse(BaseModel):
    id: str
    mac_address: str
    ip_addresses: List[str]
    hostname: Optional[str]
    manufacturer: Optional[str]
    device_type: str
    profile_tags: List[str]
    first_seen: str
    last_seen: str
    status: str
    baseline_ready: bool

    class Config:
        from_attributes = True


class DeviceListResponse(BaseModel):
    items: List[DeviceResponse]
    total: int
    page: int
    page_size: int


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[DeviceType] = None
    profile_tags: Optional[List[str]] = None


class QuarantineRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Reason for quarantine")


class QuarantineResponse(BaseModel):
    success: bool
    device_id: str
    device_name: str
    mac_address: str
    message: str
    integration_results: List[Dict[str, Any]]
    errors: List[str]


def _device_to_response(device: Device) -> DeviceResponse:
    return DeviceResponse(
        id=str(device.id),
        mac_address=device.mac_address,
        ip_addresses=device.ip_addresses,
        hostname=device.hostname,
        manufacturer=device.manufacturer,
        device_type=device.device_type.value,
        profile_tags=device.profile_tags,
        first_seen=device.first_seen.isoformat(),
        last_seen=device.last_seen.isoformat(),
        status=device.status.value,
        baseline_ready=device.baseline_ready,
    )


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    status: Optional[DeviceStatus] = None,
    device_type: Optional[DeviceType] = None,
    search: Optional[str] = None,
) -> DeviceListResponse:
    """List all devices with filtering and pagination."""
    # Build query
    query = select(Device)

    if status:
        query = query.where(Device.status == status)
    if device_type:
        query = query.where(Device.device_type == device_type)
    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            (Device.hostname.ilike(search_pattern))
            | (Device.mac_address.ilike(search_pattern))
            | (Device.manufacturer.ilike(search_pattern))
        )

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(count_query)
    total = total_result.scalar() or 0

    # Get paginated results
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size).order_by(Device.last_seen.desc())
    result = await session.execute(query)
    devices = result.scalars().all()

    return DeviceListResponse(
        items=[_device_to_response(d) for d in devices],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> DeviceResponse:
    """Get device details."""
    result = await session.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    return _device_to_response(device)


@router.patch("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: UUID,
    device_data: DeviceUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _operator: Annotated[User, Depends(require_operator)],
) -> DeviceResponse:
    """Update device attributes."""
    result = await session.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    if device_data.hostname is not None:
        device.hostname = device_data.hostname
    if device_data.device_type is not None:
        device.device_type = device_data.device_type
    if device_data.profile_tags is not None:
        device.profile_tags = device_data.profile_tags

    await session.commit()
    await session.refresh(device)

    return _device_to_response(device)


@router.post("/{device_id}/quarantine", response_model=QuarantineResponse)
async def quarantine_device(
    device_id: UUID,
    request: Request,
    operator: Annotated[User, Depends(require_operator)],
    quarantine_request: Optional[QuarantineRequest] = None,
) -> QuarantineResponse:
    """Quarantine a device.

    This endpoint:
    - Updates the device status to quarantined
    - Blocks the device via AdGuard Home (if configured)
    - Creates an audit log entry
    """
    # Get client IP for audit logging
    client_ip = request.client.host if request.client else None

    quarantine_service = get_quarantine_service()
    result = await quarantine_service.quarantine_device(
        device_id=device_id,
        user=operator,
        reason=quarantine_request.reason if quarantine_request else None,
        ip_address=client_ip,
    )

    if not result.success and "not found" in result.message.lower():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.message,
        )

    if not result.success and "already quarantined" in result.message.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message,
        )

    return QuarantineResponse(
        success=result.success,
        device_id=str(result.device_id),
        device_name=result.device_name,
        mac_address=result.mac_address,
        message=result.message,
        integration_results=result.integration_results,
        errors=result.errors,
    )


@router.delete("/{device_id}/quarantine", response_model=QuarantineResponse)
async def release_device(
    device_id: UUID,
    request: Request,
    operator: Annotated[User, Depends(require_operator)],
    reason: Optional[str] = Query(None, description="Reason for release"),
) -> QuarantineResponse:
    """Release a device from quarantine.

    This endpoint:
    - Updates the device status to active
    - Unblocks the device via AdGuard Home (if configured)
    - Creates an audit log entry
    """
    # Get client IP for audit logging
    client_ip = request.client.host if request.client else None

    quarantine_service = get_quarantine_service()
    result = await quarantine_service.release_device(
        device_id=device_id,
        user=operator,
        reason=reason,
        ip_address=client_ip,
    )

    if not result.success and "not found" in result.message.lower():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.message,
        )

    if not result.success and "not quarantined" in result.message.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.message,
        )

    return QuarantineResponse(
        success=result.success,
        device_id=str(result.device_id),
        device_name=result.device_name,
        mac_address=result.mac_address,
        message=result.message,
        integration_results=result.integration_results,
        errors=result.errors,
    )


@router.get("/quarantined", response_model=List[Dict[str, Any]])
async def list_quarantined_devices(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> List[Dict[str, Any]]:
    """Get all quarantined devices with their blocking status."""
    quarantine_service = get_quarantine_service()
    return await quarantine_service.get_quarantined_devices()
