"""Audit log API endpoints."""

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin
from app.db.session import get_async_session
from app.models.audit_log import AuditAction
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.export_service import (
    AUDIT_COLUMNS,
    AUDIT_HEADERS,
    ExportService,
)

router = APIRouter()


class AuditLogResponse(BaseModel):
    id: str
    timestamp: str
    action: str
    user_id: str | None
    username: str | None
    target_type: str
    target_id: str | None
    target_name: str | None
    description: str
    details: dict[str, Any]
    success: bool
    error_message: str | None
    ip_address: str | None

    class Config:
        from_attributes = True


class AuditLogListResponse(BaseModel):
    items: list[AuditLogResponse]
    total: int


class AuditStatsResponse(BaseModel):
    quarantines_24h: int
    releases_24h: int
    logins_24h: int
    user_actions_24h: int


def _audit_to_response(audit) -> AuditLogResponse:
    return AuditLogResponse(
        id=str(audit.id),
        timestamp=audit.timestamp.isoformat(),
        action=audit.action.value,
        user_id=str(audit.user_id) if audit.user_id else None,
        username=audit.username,
        target_type=audit.target_type,
        target_id=audit.target_id,
        target_name=audit.target_name,
        description=audit.description,
        details=audit.details,
        success=audit.success,
        error_message=audit.error_message,
        ip_address=audit.ip_address,
    )


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
    action: str | None = Query(None, description="Filter by action type"),
    target_type: str | None = Query(None, description="Filter by target type"),
    target_id: str | None = Query(None, description="Filter by target ID"),
    user_id: UUID | None = Query(None, description="Filter by user who performed action"),
    success_only: bool | None = Query(None, description="Filter by success status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> AuditLogListResponse:
    """List audit logs with filtering (Admin only)."""
    audit_service = AuditService(session)

    # Parse action enum if provided
    action_enum = None
    if action:
        try:
            action_enum = AuditAction(action)
        except ValueError:
            pass

    logs = await audit_service.get_logs(
        action=action_enum,
        target_type=target_type,
        target_id=target_id,
        user_id=user_id,
        success_only=success_only,
        limit=limit,
        offset=offset,
    )

    return AuditLogListResponse(
        items=[_audit_to_response(log) for log in logs],
        total=len(logs),  # TODO: Add total count query
    )


@router.get("/device/{device_id}", response_model=AuditLogListResponse)
async def get_device_audit_history(
    device_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(50, ge=1, le=200),
) -> AuditLogListResponse:
    """Get audit history for a specific device."""
    audit_service = AuditService(session)
    logs = await audit_service.get_device_history(device_id, limit=limit)

    return AuditLogListResponse(
        items=[_audit_to_response(log) for log in logs],
        total=len(logs),
    )


@router.get("/quarantine-history", response_model=AuditLogListResponse)
async def get_quarantine_history(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(100, ge=1, le=500),
) -> AuditLogListResponse:
    """Get recent quarantine actions."""
    audit_service = AuditService(session)
    logs = await audit_service.get_quarantine_history(hours=hours, limit=limit)

    return AuditLogListResponse(
        items=[_audit_to_response(log) for log in logs],
        total=len(logs),
    )


@router.get("/stats", response_model=AuditStatsResponse)
async def get_audit_stats(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _current_user: Annotated[User, Depends(get_current_user)],
) -> AuditStatsResponse:
    """Get audit statistics for the last 24 hours."""
    audit_service = AuditService(session)

    quarantines = await audit_service.count_actions(AuditAction.DEVICE_QUARANTINE, hours=24)
    releases = await audit_service.count_actions(AuditAction.DEVICE_RELEASE, hours=24)
    logins = await audit_service.count_actions(AuditAction.USER_LOGIN, hours=24)

    # Count all user-related actions
    user_actions = 0
    for action in [
        AuditAction.USER_CREATE,
        AuditAction.USER_UPDATE,
        AuditAction.USER_DEACTIVATE,
        AuditAction.USER_PASSWORD_RESET,
    ]:
        user_actions += await audit_service.count_actions(action, hours=24)

    return AuditStatsResponse(
        quarantines_24h=quarantines,
        releases_24h=releases,
        logins_24h=logins,
        user_actions_24h=user_actions,
    )


@router.get("/export/csv")
async def export_audit_csv(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
    action: str | None = Query(None, description="Filter by action type"),
    target_type: str | None = Query(None, description="Filter by target type"),
    user_id: UUID | None = Query(None, description="Filter by user"),
    success_only: bool | None = Query(None, description="Filter by success status"),
    limit: int = Query(10000, ge=1, le=100000),
) -> Response:
    """Export audit logs to CSV format (Admin only)."""
    audit_service = AuditService(session)

    # Parse action enum if provided
    action_enum = None
    if action:
        try:
            action_enum = AuditAction(action)
        except ValueError:
            pass

    logs = await audit_service.get_logs(
        action=action_enum,
        target_type=target_type,
        user_id=user_id,
        success_only=success_only,
        limit=limit,
    )

    audit_data = [
        {
            "timestamp": log.timestamp,
            "action": log.action.value,
            "username": log.username or "",
            "target_type": log.target_type,
            "target_name": log.target_name or "",
            "description": log.description,
            "success": log.success,
        }
        for log in logs
    ]

    csv_content = ExportService.to_csv(audit_data, AUDIT_COLUMNS, AUDIT_HEADERS)
    filename = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/export/pdf")
async def export_audit_pdf(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
    action: str | None = Query(None, description="Filter by action type"),
    target_type: str | None = Query(None, description="Filter by target type"),
    user_id: UUID | None = Query(None, description="Filter by user"),
    success_only: bool | None = Query(None, description="Filter by success status"),
    limit: int = Query(1000, ge=1, le=10000),
) -> Response:
    """Export audit logs to PDF format (Admin only)."""
    audit_service = AuditService(session)

    # Parse action enum if provided
    action_enum = None
    if action:
        try:
            action_enum = AuditAction(action)
        except ValueError:
            pass

    logs = await audit_service.get_logs(
        action=action_enum,
        target_type=target_type,
        user_id=user_id,
        success_only=success_only,
        limit=limit,
    )

    audit_data = [
        {
            "timestamp": log.timestamp,
            "action": log.action.value,
            "username": log.username or "",
            "target_type": log.target_type,
            "target_name": log.target_name or "",
            "description": log.description,
            "success": log.success,
        }
        for log in logs
    ]

    # Build subtitle with filters
    filters = []
    if action_enum:
        filters.append(f"Action: {action_enum.value}")
    if target_type:
        filters.append(f"Target: {target_type}")
    subtitle = " | ".join(filters) if filters else None

    pdf_content = ExportService.to_pdf(
        audit_data,
        title="Audit Log Report",
        columns=AUDIT_COLUMNS,
        headers=AUDIT_HEADERS,
        subtitle=subtitle,
    )
    filename = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
