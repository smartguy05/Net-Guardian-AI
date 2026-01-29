"""Device management API endpoints."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_operator
from app.db.session import get_async_session
from app.models.device import Device, DeviceStatus, DeviceType
from app.models.user import User
from app.services.device_sync_service import get_device_sync_service
from app.services.export_service import (
    DEVICES_COLUMNS,
    DEVICES_HEADERS,
    ExportService,
)
from app.services.quarantine_service import get_quarantine_service

router = APIRouter()


# Pydantic schemas
class DeviceResponse(BaseModel):
    id: str
    mac_address: str
    ip_addresses: list[str]
    hostname: str | None
    manufacturer: str | None
    device_type: str
    profile_tags: list[str]
    first_seen: str
    last_seen: str
    status: str
    baseline_ready: bool

    class Config:
        from_attributes = True


class DeviceListResponse(BaseModel):
    items: list[DeviceResponse]
    total: int
    page: int
    page_size: int


class DeviceUpdate(BaseModel):
    hostname: str | None = None
    device_type: DeviceType | None = None
    profile_tags: list[str] | None = None


class QuarantineRequest(BaseModel):
    reason: str | None = Field(None, description="Reason for quarantine")


class QuarantineResponse(BaseModel):
    success: bool
    device_id: str
    device_name: str
    mac_address: str
    message: str
    integration_results: list[dict[str, Any]]
    errors: list[str]


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
    status: DeviceStatus | None = None,
    device_type: DeviceType | None = None,
    search: str | None = None,
    tags: str | None = Query(None, description="Comma-separated list of tags to filter by"),
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
    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        if tag_list:
            # Filter devices that have ALL specified tags
            for tag in tag_list:
                query = query.where(Device.profile_tags.contains([tag]))

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


# =============================================================================
# Static routes (must be defined before /{device_id} to avoid route conflicts)
# =============================================================================


@router.get("/quarantined", response_model=list[dict[str, Any]])
async def list_quarantined_devices(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Get all quarantined devices with their blocking status."""
    quarantine_service = get_quarantine_service()
    return await quarantine_service.get_quarantined_devices()


async def _get_devices_for_export(
    session: AsyncSession,
    status_filter: DeviceStatus | None = None,
    device_type: DeviceType | None = None,
    limit: int = 10000,
) -> list[dict[str, Any]]:
    """Get devices formatted for export."""
    query = select(Device)

    if status_filter:
        query = query.where(Device.status == status_filter)
    if device_type:
        query = query.where(Device.device_type == device_type)

    query = query.order_by(Device.last_seen.desc()).limit(limit)
    result = await session.execute(query)
    devices = result.scalars().all()

    return [
        {
            "hostname": d.hostname or "",
            "mac_address": d.mac_address,
            "ip_addresses": ", ".join(d.ip_addresses) if d.ip_addresses else "",
            "device_type": d.device_type.value,
            "status": d.status.value,
            "first_seen": d.first_seen,
            "last_seen": d.last_seen,
        }
        for d in devices
    ]


@router.get("/export/csv")
async def export_devices_csv(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    status_filter: DeviceStatus | None = Query(None, alias="status"),
    device_type: DeviceType | None = None,
    limit: int = Query(10000, ge=1, le=100000),
) -> Response:
    """Export devices to CSV format."""
    devices = await _get_devices_for_export(
        session,
        status_filter=status_filter,
        device_type=device_type,
        limit=limit,
    )

    csv_content = ExportService.to_csv(devices, DEVICES_COLUMNS, DEVICES_HEADERS)
    filename = f"devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/pdf")
async def export_devices_pdf(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    status_filter: DeviceStatus | None = Query(None, alias="status"),
    device_type: DeviceType | None = None,
    limit: int = Query(1000, ge=1, le=10000),
) -> Response:
    """Export devices to PDF format."""
    devices = await _get_devices_for_export(
        session,
        status_filter=status_filter,
        device_type=device_type,
        limit=limit,
    )

    # Build subtitle with filters
    filters = []
    if status_filter:
        filters.append(f"Status: {status_filter.value}")
    if device_type:
        filters.append(f"Type: {device_type.value}")
    subtitle = " | ".join(filters) if filters else None

    pdf_content = ExportService.to_pdf(
        devices,
        title="Network Devices Report",
        columns=DEVICES_COLUMNS,
        headers=DEVICES_HEADERS,
        subtitle=subtitle,
    )
    filename = f"devices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# Tag management schemas
class TagsResponse(BaseModel):
    tags: list[str]
    counts: dict[str, int]


class BulkTagRequest(BaseModel):
    device_ids: list[UUID]
    tags_to_add: list[str] | None = None
    tags_to_remove: list[str] | None = None


class BulkTagResponse(BaseModel):
    updated_count: int
    devices: list[DeviceResponse]


class DeviceSyncRequest(BaseModel):
    source: str = Field("adguard", description="Source to sync from (currently only 'adguard')")
    overwrite_existing: bool = Field(False, description="If true, overwrites existing hostnames")


class DeviceSyncResponse(BaseModel):
    success: bool
    total_devices: int
    updated_devices: int
    skipped_devices: int
    source: str
    details: list[dict[str, str]]


@router.get("/tags/all", response_model=TagsResponse)
async def get_all_tags(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> TagsResponse:
    """Get all unique tags used across devices with counts."""
    result = await session.execute(select(Device))
    devices = result.scalars().all()

    tag_counts: dict[str, int] = {}
    for device in devices:
        for tag in device.profile_tags or []:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    # Sort tags alphabetically
    sorted_tags = sorted(tag_counts.keys())

    return TagsResponse(tags=sorted_tags, counts=tag_counts)


@router.post("/bulk-tag", response_model=BulkTagResponse)
async def bulk_tag_devices(
    request: BulkTagRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _operator: Annotated[User, Depends(require_operator)],
) -> BulkTagResponse:
    """Add or remove tags from multiple devices at once."""
    if not request.tags_to_add and not request.tags_to_remove:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must specify tags_to_add or tags_to_remove",
        )

    result = await session.execute(select(Device).where(Device.id.in_(request.device_ids)))
    devices = list(result.scalars().all())

    if not devices:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No devices found with the specified IDs",
        )

    updated_devices = []
    for device in devices:
        current_tags = set(device.profile_tags or [])

        if request.tags_to_add:
            current_tags.update(request.tags_to_add)

        if request.tags_to_remove:
            current_tags -= set(request.tags_to_remove)

        device.profile_tags = sorted(list(current_tags))
        updated_devices.append(device)

    await session.commit()

    # Refresh all devices
    for device in updated_devices:
        await session.refresh(device)

    return BulkTagResponse(
        updated_count=len(updated_devices),
        devices=[_device_to_response(d) for d in updated_devices],
    )


@router.post("/sync", response_model=DeviceSyncResponse)
async def sync_device_names(
    request: DeviceSyncRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _operator: Annotated[User, Depends(require_operator)],
) -> DeviceSyncResponse:
    """Sync device names from external sources like AdGuard Home.

    This endpoint fetches device names from the specified source and updates
    matching devices in the database. Devices are matched by IP address or
    MAC address.

    Currently supported sources:
    - adguard: Syncs device names from AdGuard Home clients

    Requires operator or admin role.
    """
    if request.source != "adguard":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported sync source: {request.source}. Supported: adguard",
        )

    try:
        sync_service = get_device_sync_service()
        result = await sync_service.sync_from_adguard(
            session=session,
            overwrite_existing=request.overwrite_existing,
        )

        # Commit the session since we passed it to the service
        await session.commit()

        return DeviceSyncResponse(
            success=True,
            total_devices=result.total_devices,
            updated_devices=result.updated_devices,
            skipped_devices=result.skipped_devices,
            source=result.source,
            details=result.details,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync devices: {str(e)}",
        )


# =============================================================================
# Dynamic routes with {device_id} path parameter
# =============================================================================


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
    quarantine_request: QuarantineRequest | None = None,
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
    reason: str | None = Query(None, description="Reason for release"),
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


@router.put("/{device_id}/tags", response_model=DeviceResponse)
async def set_device_tags(
    device_id: UUID,
    tags: list[str],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _operator: Annotated[User, Depends(require_operator)],
) -> DeviceResponse:
    """Set the complete list of tags for a device."""
    result = await session.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Clean and deduplicate tags
    clean_tags = sorted(list(set(tag.strip() for tag in tags if tag.strip())))
    device.profile_tags = clean_tags

    await session.commit()
    await session.refresh(device)

    return _device_to_response(device)


@router.post("/{device_id}/tags", response_model=DeviceResponse)
async def add_device_tag(
    device_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _operator: Annotated[User, Depends(require_operator)],
    tag: str = Query(..., min_length=1, max_length=50),
) -> DeviceResponse:
    """Add a single tag to a device."""
    result = await session.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    current_tags = set(device.profile_tags or [])
    current_tags.add(tag.strip())
    device.profile_tags = sorted(list(current_tags))

    await session.commit()
    await session.refresh(device)

    return _device_to_response(device)


@router.delete("/{device_id}/tags/{tag}", response_model=DeviceResponse)
async def remove_device_tag(
    device_id: UUID,
    tag: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _operator: Annotated[User, Depends(require_operator)],
) -> DeviceResponse:
    """Remove a single tag from a device."""
    result = await session.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    current_tags = set(device.profile_tags or [])
    current_tags.discard(tag)
    device.profile_tags = sorted(list(current_tags))

    await session.commit()
    await session.refresh(device)

    return _device_to_response(device)
