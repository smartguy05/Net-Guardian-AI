"""Investigation API endpoints."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_operator
from app.config import settings
from app.db.session import get_async_session
from app.models.investigation import (
    InvestigationActionRiskLevel,
    InvestigationActionStatus,
    InvestigationStatus,
    InvestigationStepStatus,
    InvestigationStepType,
    InvestigationTriggerSource,
)
from app.models.user import User
from app.services.investigation import get_investigation_service

router = APIRouter()


# ==================== SCHEMAS ====================


class InvestigationStepResponse(BaseModel):
    """Investigation step response."""

    id: str
    step_number: int
    step_type: str
    status: str
    reasoning: str | None
    findings: dict[str, Any] | None
    confidence_score: float | None
    duration_ms: int | None
    llm_model_used: str | None
    error_message: str | None
    created_at: str


class InvestigationActionResponse(BaseModel):
    """Investigation action response."""

    id: str
    action_type: str
    action_params: dict[str, Any]
    risk_level: str
    justification: str
    status: str
    approved_by: str | None
    approved_at: str | None
    rejected_by: str | None
    rejected_at: str | None
    rejection_reason: str | None
    executed_at: str | None
    execution_result: dict[str, Any] | None
    created_at: str


class InvestigationResponse(BaseModel):
    """Investigation response."""

    id: str
    alert_id: str | None
    anomaly_id: str | None
    device_id: str | None
    status: str
    trigger_source: str
    priority: int
    started_at: str | None
    completed_at: str | None
    summary: str | None
    recommendations: dict[str, Any] | None
    requires_approval: bool
    approved_by: str | None
    created_at: str
    updated_at: str
    steps: list[InvestigationStepResponse] | None = None
    actions: list[InvestigationActionResponse] | None = None


class InvestigationListResponse(BaseModel):
    """List of investigations response."""

    items: list[InvestigationResponse]
    total: int


class CreateInvestigationRequest(BaseModel):
    """Request to create an investigation."""

    alert_id: UUID | None = None
    anomaly_id: UUID | None = None
    device_id: UUID | None = None
    priority: int = Field(default=3, ge=1, le=5)
    auto_run: bool = True


class RejectActionRequest(BaseModel):
    """Request to reject an action."""

    reason: str | None = None


class ExecuteActionsResponse(BaseModel):
    """Response from executing actions."""

    results: list[dict[str, Any]]


# ==================== HELPERS ====================


def _investigation_to_response(
    investigation: Any,
    include_steps: bool = False,
    include_actions: bool = False,
) -> InvestigationResponse:
    """Convert investigation to response model."""
    response = InvestigationResponse(
        id=str(investigation.id),
        alert_id=str(investigation.alert_id) if investigation.alert_id else None,
        anomaly_id=str(investigation.anomaly_id) if investigation.anomaly_id else None,
        device_id=str(investigation.device_id) if investigation.device_id else None,
        status=investigation.status.value,
        trigger_source=investigation.trigger_source.value,
        priority=investigation.priority,
        started_at=investigation.started_at.isoformat() if investigation.started_at else None,
        completed_at=investigation.completed_at.isoformat() if investigation.completed_at else None,
        summary=investigation.summary,
        recommendations=investigation.recommendations,
        requires_approval=investigation.requires_approval,
        approved_by=str(investigation.approved_by) if investigation.approved_by else None,
        created_at=investigation.created_at.isoformat(),
        updated_at=investigation.updated_at.isoformat(),
    )

    if include_steps and hasattr(investigation, "steps") and investigation.steps:
        response.steps = [
            InvestigationStepResponse(
                id=str(step.id),
                step_number=step.step_number,
                step_type=step.step_type.value,
                status=step.status.value,
                reasoning=step.reasoning,
                findings=step.findings,
                confidence_score=step.confidence_score,
                duration_ms=step.duration_ms,
                llm_model_used=step.llm_model_used,
                error_message=step.error_message,
                created_at=step.created_at.isoformat(),
            )
            for step in sorted(investigation.steps, key=lambda s: s.step_number)
        ]

    if include_actions and hasattr(investigation, "actions") and investigation.actions:
        response.actions = [
            InvestigationActionResponse(
                id=str(action.id),
                action_type=action.action_type,
                action_params=action.action_params,
                risk_level=action.risk_level.value,
                justification=action.justification,
                status=action.status.value,
                approved_by=str(action.approved_by) if action.approved_by else None,
                approved_at=action.approved_at.isoformat() if action.approved_at else None,
                rejected_by=str(action.rejected_by) if action.rejected_by else None,
                rejected_at=action.rejected_at.isoformat() if action.rejected_at else None,
                rejection_reason=action.rejection_reason,
                executed_at=action.executed_at.isoformat() if action.executed_at else None,
                execution_result=action.execution_result,
                created_at=action.created_at.isoformat(),
            )
            for action in investigation.actions
        ]

    return response


# ==================== ENDPOINTS ====================


@router.get("", response_model=InvestigationListResponse)
async def list_investigations(
    _current_user: Annotated[User, Depends(get_current_user)],
    status_filter: InvestigationStatus | None = Query(None, alias="status"),
    device_id: UUID | None = None,
    trigger_source: InvestigationTriggerSource | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> InvestigationListResponse:
    """List investigations with filtering."""
    if not settings.investigation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Investigation feature is disabled",
        )

    service = get_investigation_service()
    investigations, total = await service.list_investigations(
        status=status_filter,
        device_id=device_id,
        trigger_source=trigger_source,
        limit=limit,
        offset=offset,
    )

    return InvestigationListResponse(
        items=[_investigation_to_response(inv, include_actions=True) for inv in investigations],
        total=total,
    )


@router.get("/{investigation_id}", response_model=InvestigationResponse)
async def get_investigation(
    investigation_id: UUID,
    _current_user: Annotated[User, Depends(get_current_user)],
    include_steps: bool = Query(True),
    include_actions: bool = Query(True),
) -> InvestigationResponse:
    """Get a specific investigation with steps and actions."""
    if not settings.investigation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Investigation feature is disabled",
        )

    service = get_investigation_service()
    investigation = await service.get_investigation(
        investigation_id,
        include_steps=include_steps,
        include_actions=include_actions,
    )

    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    return _investigation_to_response(
        investigation,
        include_steps=include_steps,
        include_actions=include_actions,
    )


@router.post("", response_model=InvestigationResponse)
async def create_investigation(
    request: CreateInvestigationRequest,
    current_user: Annotated[User, Depends(require_operator)],
) -> InvestigationResponse:
    """Create a new investigation manually."""
    if not settings.investigation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Investigation feature is disabled",
        )

    if not any([request.alert_id, request.anomaly_id, request.device_id]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of alert_id, anomaly_id, or device_id is required",
        )

    service = get_investigation_service()
    investigation = await service.create_investigation(
        trigger_source=InvestigationTriggerSource.MANUAL,
        alert_id=request.alert_id,
        anomaly_id=request.anomaly_id,
        device_id=request.device_id,
        priority=request.priority,
        auto_run=request.auto_run,
    )

    return _investigation_to_response(investigation)


@router.delete("/{investigation_id}", response_model=InvestigationResponse)
async def cancel_investigation(
    investigation_id: UUID,
    current_user: Annotated[User, Depends(require_operator)],
) -> InvestigationResponse:
    """Cancel a pending or running investigation."""
    if not settings.investigation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Investigation feature is disabled",
        )

    service = get_investigation_service()
    investigation = await service.cancel_investigation(investigation_id)

    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found",
        )

    return _investigation_to_response(investigation)


@router.post("/{investigation_id}/approve/{action_id}")
async def approve_action(
    investigation_id: UUID,
    action_id: UUID,
    current_user: Annotated[User, Depends(require_operator)],
) -> InvestigationActionResponse:
    """Approve an investigation action."""
    if not settings.investigation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Investigation feature is disabled",
        )

    service = get_investigation_service()
    action = await service.approve_action(action_id, current_user.id)

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Action not found or not pending",
        )

    return InvestigationActionResponse(
        id=str(action.id),
        action_type=action.action_type,
        action_params=action.action_params,
        risk_level=action.risk_level.value,
        justification=action.justification,
        status=action.status.value,
        approved_by=str(action.approved_by) if action.approved_by else None,
        approved_at=action.approved_at.isoformat() if action.approved_at else None,
        rejected_by=None,
        rejected_at=None,
        rejection_reason=None,
        executed_at=None,
        execution_result=None,
        created_at=action.created_at.isoformat(),
    )


@router.post("/{investigation_id}/reject/{action_id}")
async def reject_action(
    investigation_id: UUID,
    action_id: UUID,
    request: RejectActionRequest,
    current_user: Annotated[User, Depends(require_operator)],
) -> InvestigationActionResponse:
    """Reject an investigation action."""
    if not settings.investigation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Investigation feature is disabled",
        )

    service = get_investigation_service()
    action = await service.reject_action(action_id, current_user.id, request.reason)

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Action not found or not pending",
        )

    return InvestigationActionResponse(
        id=str(action.id),
        action_type=action.action_type,
        action_params=action.action_params,
        risk_level=action.risk_level.value,
        justification=action.justification,
        status=action.status.value,
        approved_by=None,
        approved_at=None,
        rejected_by=str(action.rejected_by) if action.rejected_by else None,
        rejected_at=action.rejected_at.isoformat() if action.rejected_at else None,
        rejection_reason=action.rejection_reason,
        executed_at=None,
        execution_result=None,
        created_at=action.created_at.isoformat(),
    )


@router.post("/{investigation_id}/execute", response_model=ExecuteActionsResponse)
async def execute_approved_actions(
    investigation_id: UUID,
    current_user: Annotated[User, Depends(require_operator)],
) -> ExecuteActionsResponse:
    """Execute all approved actions for an investigation."""
    if not settings.investigation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Investigation feature is disabled",
        )

    service = get_investigation_service()
    results = await service.execute_approved_actions(investigation_id)

    return ExecuteActionsResponse(results=results)


@router.post("/{investigation_id}/run")
async def run_investigation(
    investigation_id: UUID,
    current_user: Annotated[User, Depends(require_operator)],
) -> InvestigationResponse:
    """Run a pending investigation."""
    if not settings.investigation_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Investigation feature is disabled",
        )

    service = get_investigation_service()

    try:
        investigation = await service.run_investigation(investigation_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return _investigation_to_response(investigation, include_steps=True, include_actions=True)
