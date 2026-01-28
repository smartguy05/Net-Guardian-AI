"""Playbook management API endpoints."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin, require_operator
from app.db.session import get_async_session
from app.models.playbook import (
    ExecutionStatus,
    PlaybookActionType,
    PlaybookStatus,
    PlaybookTriggerType,
)
from app.models.user import User
from app.services.playbook_engine import get_playbook_engine

router = APIRouter()


# Pydantic schemas
class PlaybookActionCreate(BaseModel):
    type: PlaybookActionType
    params: dict[str, Any] = {}
    stop_on_failure: bool = False


class PlaybookCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = None
    trigger_type: PlaybookTriggerType
    trigger_conditions: dict[str, Any] = {}
    actions: list[PlaybookActionCreate]
    cooldown_minutes: int = Field(60, ge=1, le=1440)
    max_executions_per_hour: int = Field(10, ge=1, le=100)
    require_approval: bool = False


class PlaybookUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = None
    status: PlaybookStatus | None = None
    trigger_type: PlaybookTriggerType | None = None
    trigger_conditions: dict[str, Any] | None = None
    actions: list[PlaybookActionCreate] | None = None
    cooldown_minutes: int | None = Field(None, ge=1, le=1440)
    max_executions_per_hour: int | None = Field(None, ge=1, le=100)
    require_approval: bool | None = None


class PlaybookResponse(BaseModel):
    id: str
    name: str
    description: str | None
    status: str
    trigger_type: str
    trigger_conditions: dict[str, Any]
    actions: list[dict[str, Any]]
    cooldown_minutes: int
    max_executions_per_hour: int
    require_approval: bool
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class PlaybookListResponse(BaseModel):
    items: list[PlaybookResponse]
    total: int


class ExecutionResponse(BaseModel):
    id: str
    playbook_id: str
    status: str
    trigger_event: dict[str, Any]
    trigger_device_id: str | None
    started_at: str | None
    completed_at: str | None
    action_results: list[dict[str, Any]]
    error_message: str | None
    triggered_by: str | None
    created_at: str

    class Config:
        from_attributes = True


class ExecutionListResponse(BaseModel):
    items: list[ExecutionResponse]
    total: int


class ManualTriggerRequest(BaseModel):
    device_id: UUID | None = None
    event_data: dict[str, Any] = {}


def _playbook_to_response(playbook) -> PlaybookResponse:
    return PlaybookResponse(
        id=str(playbook.id),
        name=playbook.name,
        description=playbook.description,
        status=playbook.status.value,
        trigger_type=playbook.trigger_type.value,
        trigger_conditions=playbook.trigger_conditions,
        actions=playbook.actions,
        cooldown_minutes=playbook.cooldown_minutes,
        max_executions_per_hour=playbook.max_executions_per_hour,
        require_approval=playbook.require_approval,
        created_at=playbook.created_at.isoformat(),
        updated_at=playbook.updated_at.isoformat(),
    )


def _execution_to_response(execution) -> ExecutionResponse:
    return ExecutionResponse(
        id=str(execution.id),
        playbook_id=str(execution.playbook_id),
        status=execution.status.value,
        trigger_event=execution.trigger_event,
        trigger_device_id=str(execution.trigger_device_id) if execution.trigger_device_id else None,
        started_at=execution.started_at.isoformat() if execution.started_at else None,
        completed_at=execution.completed_at.isoformat() if execution.completed_at else None,
        action_results=execution.action_results,
        error_message=execution.error_message,
        triggered_by=str(execution.triggered_by) if execution.triggered_by else None,
        created_at=execution.created_at.isoformat(),
    )


@router.get("", response_model=PlaybookListResponse)
async def list_playbooks(
    _current_user: Annotated[User, Depends(get_current_user)],
    status: PlaybookStatus | None = Query(None),
    trigger_type: PlaybookTriggerType | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> PlaybookListResponse:
    """List all playbooks with optional filtering."""
    engine = get_playbook_engine()
    playbooks = await engine.list_playbooks(
        status=status,
        trigger_type=trigger_type,
        limit=limit,
        offset=offset,
    )

    return PlaybookListResponse(
        items=[_playbook_to_response(p) for p in playbooks],
        total=len(playbooks),
    )


@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: UUID,
    _current_user: Annotated[User, Depends(get_current_user)],
) -> PlaybookResponse:
    """Get a specific playbook."""
    engine = get_playbook_engine()
    playbook = await engine.get_playbook(playbook_id)

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )

    return _playbook_to_response(playbook)


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
async def create_playbook(
    playbook_data: PlaybookCreate,
    admin: Annotated[User, Depends(require_admin)],
) -> PlaybookResponse:
    """Create a new playbook (Admin only)."""
    engine = get_playbook_engine()

    # Convert actions to dict format
    actions = [
        {
            "type": a.type.value,
            "params": a.params,
            "stop_on_failure": a.stop_on_failure,
        }
        for a in playbook_data.actions
    ]

    playbook = await engine.create_playbook(
        name=playbook_data.name,
        description=playbook_data.description,
        trigger_type=playbook_data.trigger_type,
        trigger_conditions=playbook_data.trigger_conditions,
        actions=actions,
        cooldown_minutes=playbook_data.cooldown_minutes,
        max_executions_per_hour=playbook_data.max_executions_per_hour,
        require_approval=playbook_data.require_approval,
        created_by=admin.id,
    )

    return _playbook_to_response(playbook)


@router.patch("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: UUID,
    playbook_data: PlaybookUpdate,
    _admin: Annotated[User, Depends(require_admin)],
) -> PlaybookResponse:
    """Update a playbook (Admin only)."""
    engine = get_playbook_engine()

    updates = playbook_data.model_dump(exclude_unset=True)

    # Convert actions if provided
    if "actions" in updates and updates["actions"]:
        updates["actions"] = [
            {
                "type": a.type.value if hasattr(a.type, "value") else a["type"],
                "params": a.params if hasattr(a, "params") else a.get("params", {}),
                "stop_on_failure": a.stop_on_failure if hasattr(a, "stop_on_failure") else a.get("stop_on_failure", False),
            }
            for a in updates["actions"]
        ]

    playbook = await engine.update_playbook(playbook_id, **updates)

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )

    return _playbook_to_response(playbook)


@router.delete("/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_playbook(
    playbook_id: UUID,
    _admin: Annotated[User, Depends(require_admin)],
) -> None:
    """Delete a playbook (Admin only)."""
    engine = get_playbook_engine()
    success = await engine.delete_playbook(playbook_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )


@router.post("/{playbook_id}/execute", response_model=ExecutionResponse)
async def execute_playbook_manually(
    playbook_id: UUID,
    operator: Annotated[User, Depends(require_operator)],
    trigger_request: ManualTriggerRequest | None = None,
) -> ExecutionResponse:
    """Manually execute a playbook (Operator+)."""
    engine = get_playbook_engine()
    playbook = await engine.get_playbook(playbook_id)

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )

    if playbook.status != PlaybookStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Playbook is not active",
        )

    trigger_event = {
        "type": "manual",
        "description": f"Manually triggered by {operator.username}",
        **(trigger_request.event_data if trigger_request else {}),
    }

    device_id = trigger_request.device_id if trigger_request else None

    execution = await engine.execute_playbook(
        playbook=playbook,
        trigger_event=trigger_event,
        device_id=device_id,
        triggered_by=operator,
    )

    return _execution_to_response(execution)


@router.post("/{playbook_id}/activate", response_model=PlaybookResponse)
async def activate_playbook(
    playbook_id: UUID,
    _admin: Annotated[User, Depends(require_admin)],
) -> PlaybookResponse:
    """Activate a playbook (Admin only)."""
    engine = get_playbook_engine()
    playbook = await engine.update_playbook(
        playbook_id, status=PlaybookStatus.ACTIVE
    )

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )

    return _playbook_to_response(playbook)


@router.post("/{playbook_id}/deactivate", response_model=PlaybookResponse)
async def deactivate_playbook(
    playbook_id: UUID,
    _admin: Annotated[User, Depends(require_admin)],
) -> PlaybookResponse:
    """Deactivate a playbook (Admin only)."""
    engine = get_playbook_engine()
    playbook = await engine.update_playbook(
        playbook_id, status=PlaybookStatus.DISABLED
    )

    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found",
        )

    return _playbook_to_response(playbook)


@router.get("/{playbook_id}/executions", response_model=ExecutionListResponse)
async def list_playbook_executions(
    playbook_id: UUID,
    _current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
    status_filter: ExecutionStatus | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ExecutionListResponse:
    """List executions for a specific playbook."""
    from sqlalchemy import select

    from app.models.playbook import PlaybookExecution

    query = select(PlaybookExecution).where(
        PlaybookExecution.playbook_id == playbook_id
    )

    if status_filter:
        query = query.where(PlaybookExecution.status == status_filter)

    query = query.order_by(PlaybookExecution.created_at.desc())
    query = query.offset(offset).limit(limit)

    result = await session.execute(query)
    executions = result.scalars().all()

    return ExecutionListResponse(
        items=[_execution_to_response(e) for e in executions],
        total=len(executions),
    )


@router.get("/actions/types", response_model=list[dict[str, str]])
async def list_action_types(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, str]]:
    """List available playbook action types."""
    return [
        {
            "type": action.value,
            "name": action.name.replace("_", " ").title(),
            "description": _get_action_description(action),
        }
        for action in PlaybookActionType
    ]


@router.get("/triggers/types", response_model=list[dict[str, str]])
async def list_trigger_types(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, str]]:
    """List available playbook trigger types."""
    return [
        {
            "type": trigger.value,
            "name": trigger.name.replace("_", " ").title(),
            "description": _get_trigger_description(trigger),
        }
        for trigger in PlaybookTriggerType
    ]


def _get_action_description(action: PlaybookActionType) -> str:
    """Get description for an action type."""
    descriptions = {
        PlaybookActionType.QUARANTINE_DEVICE: "Block device from network access",
        PlaybookActionType.RELEASE_DEVICE: "Restore device network access",
        PlaybookActionType.BLOCK_DOMAIN: "Block a domain in DNS filtering",
        PlaybookActionType.UNBLOCK_DOMAIN: "Unblock a domain in DNS filtering",
        PlaybookActionType.SEND_NOTIFICATION: "Send a notification alert",
        PlaybookActionType.CREATE_ALERT: "Create an alert in the system",
        PlaybookActionType.RUN_LLM_ANALYSIS: "Run AI analysis on the event",
        PlaybookActionType.EXECUTE_WEBHOOK: "Send HTTP request to external service",
        PlaybookActionType.LOG_EVENT: "Log event for audit purposes",
        PlaybookActionType.TAG_DEVICE: "Add or remove tags from device",
    }
    return descriptions.get(action, "")


def _get_trigger_description(trigger: PlaybookTriggerType) -> str:
    """Get description for a trigger type."""
    descriptions = {
        PlaybookTriggerType.ANOMALY_DETECTED: "Triggered when anomaly detection finds suspicious behavior",
        PlaybookTriggerType.ALERT_CREATED: "Triggered when a new alert is created",
        PlaybookTriggerType.DEVICE_NEW: "Triggered when a new device is discovered",
        PlaybookTriggerType.DEVICE_STATUS_CHANGE: "Triggered when device status changes",
        PlaybookTriggerType.THRESHOLD_EXCEEDED: "Triggered when a metric exceeds threshold",
        PlaybookTriggerType.SCHEDULE: "Triggered on a schedule (cron-like)",
        PlaybookTriggerType.MANUAL: "Triggered manually by an operator",
    }
    return descriptions.get(trigger, "")
