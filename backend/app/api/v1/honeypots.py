"""Honeypot API endpoints."""

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.v1.auth import get_current_user, require_admin, require_operator
from app.config import settings
from app.models.honeypot import HoneypotStatus, HoneypotType
from app.models.user import User
from app.services.honeypot import get_honeypot_service

router = APIRouter()


# ==================== SCHEMAS ====================


class HoneypotTemplateResponse(BaseModel):
    """Honeypot template response."""

    id: str
    name: str
    honeypot_type: str
    description: str | None
    container_image: str
    exposed_ports: list[int]
    default_timeout_minutes: int
    enabled: bool


class HoneypotInteractionResponse(BaseModel):
    """Honeypot interaction response."""

    id: str
    timestamp: str
    source_ip: str
    source_port: int | None
    interaction_type: str
    raw_data: str | None
    parsed_data: dict[str, Any] | None
    threat_indicators: dict[str, Any] | None
    created_at: str


class HoneypotInstanceResponse(BaseModel):
    """Honeypot instance response."""

    id: str
    template_id: str | None
    container_id: str | None
    container_name: str
    status: str
    host_ip: str | None
    port_mappings: dict[str, int]
    trigger_alert_id: str | None
    trigger_device_id: str | None
    trigger_reason: str | None
    started_at: str | None
    expires_at: str
    stopped_at: str | None
    interaction_count: int
    llm_profile: dict[str, Any] | None
    error_message: str | None
    created_at: str


class HoneypotListResponse(BaseModel):
    """List of honeypots response."""

    items: list[HoneypotInstanceResponse]
    total: int


class AttackerProfileResponse(BaseModel):
    """Attacker profile response."""

    id: str
    source_ip: str
    first_seen: str
    last_seen: str
    total_interactions: int
    honeypots_triggered: int
    attack_patterns: dict[str, Any] | None
    sophistication_level: str | None
    likely_intent: str | None
    llm_analysis: str | None
    recommended_actions: dict[str, Any] | None
    iocs: dict[str, Any] | None


class AttackerListResponse(BaseModel):
    """List of attacker profiles response."""

    items: list[AttackerProfileResponse]
    total: int


class SpawnHoneypotRequest(BaseModel):
    """Request to spawn a honeypot."""

    template_id: str
    trigger_alert_id: UUID | None = None
    trigger_device_id: UUID | None = None
    trigger_reason: str | None = None
    timeout_minutes: int | None = Field(None, ge=5, le=1440)


class HoneypotStatsResponse(BaseModel):
    """Honeypot statistics response."""

    by_status: dict[str, int]
    total_interactions: int
    unique_attackers: int


# ==================== HELPERS ====================


def _instance_to_response(instance: Any) -> HoneypotInstanceResponse:
    """Convert honeypot instance to response model."""
    return HoneypotInstanceResponse(
        id=str(instance.id),
        template_id=instance.template_id,
        container_id=instance.container_id,
        container_name=instance.container_name,
        status=instance.status.value,
        host_ip=instance.host_ip,
        port_mappings=instance.port_mappings,
        trigger_alert_id=str(instance.trigger_alert_id) if instance.trigger_alert_id else None,
        trigger_device_id=str(instance.trigger_device_id) if instance.trigger_device_id else None,
        trigger_reason=instance.trigger_reason,
        started_at=instance.started_at.isoformat() if instance.started_at else None,
        expires_at=instance.expires_at.isoformat(),
        stopped_at=instance.stopped_at.isoformat() if instance.stopped_at else None,
        interaction_count=instance.interaction_count,
        llm_profile=instance.llm_profile,
        error_message=instance.error_message,
        created_at=instance.created_at.isoformat(),
    )


def _profile_to_response(profile: Any) -> AttackerProfileResponse:
    """Convert attacker profile to response model."""
    return AttackerProfileResponse(
        id=str(profile.id),
        source_ip=profile.source_ip,
        first_seen=profile.first_seen.isoformat(),
        last_seen=profile.last_seen.isoformat(),
        total_interactions=profile.total_interactions,
        honeypots_triggered=profile.honeypots_triggered,
        attack_patterns=profile.attack_patterns,
        sophistication_level=profile.sophistication_level.value
        if profile.sophistication_level
        else None,
        likely_intent=profile.likely_intent,
        llm_analysis=profile.llm_analysis,
        recommended_actions=profile.recommended_actions,
        iocs=profile.iocs,
    )


# ==================== TEMPLATE ENDPOINTS ====================


@router.get("/templates", response_model=list[HoneypotTemplateResponse])
async def list_templates(
    _current_user: Annotated[User, Depends(get_current_user)],
    honeypot_type: HoneypotType | None = None,
    enabled_only: bool = Query(True),
) -> list[HoneypotTemplateResponse]:
    """List available honeypot templates."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    templates = await service.get_templates(
        honeypot_type=honeypot_type,
        enabled_only=enabled_only,
    )

    return [
        HoneypotTemplateResponse(
            id=t.id,
            name=t.name,
            honeypot_type=t.honeypot_type.value,
            description=t.description,
            container_image=t.container_image,
            exposed_ports=t.exposed_ports,
            default_timeout_minutes=t.default_timeout_minutes,
            enabled=t.enabled,
        )
        for t in templates
    ]


@router.post("/templates/sync")
async def sync_templates(
    current_user: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Sync honeypot templates to database (admin only)."""
    service = get_honeypot_service()
    count = await service.sync_templates()
    return {"synced": count, "message": f"Synced {count} templates"}


# ==================== HONEYPOT INSTANCE ENDPOINTS ====================


@router.get("", response_model=HoneypotListResponse)
async def list_honeypots(
    _current_user: Annotated[User, Depends(get_current_user)],
    status_filter: HoneypotStatus | None = Query(None, alias="status"),
    template_id: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> HoneypotListResponse:
    """List honeypot instances."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    instances, total = await service.list_honeypots(
        status=status_filter,
        template_id=template_id,
        limit=limit,
        offset=offset,
    )

    return HoneypotListResponse(
        items=[_instance_to_response(i) for i in instances],
        total=total,
    )


@router.get("/stats", response_model=HoneypotStatsResponse)
async def get_stats(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> HoneypotStatsResponse:
    """Get honeypot statistics."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    stats = await service.get_stats()
    return HoneypotStatsResponse(**stats)


@router.get("/{honeypot_id}", response_model=HoneypotInstanceResponse)
async def get_honeypot(
    honeypot_id: UUID,
    _current_user: Annotated[User, Depends(get_current_user)],
) -> HoneypotInstanceResponse:
    """Get a specific honeypot instance."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    instance = await service.get_honeypot(honeypot_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Honeypot not found",
        )

    return _instance_to_response(instance)


@router.post("", response_model=HoneypotInstanceResponse)
async def spawn_honeypot(
    request: SpawnHoneypotRequest,
    current_user: Annotated[User, Depends(require_operator)],
) -> HoneypotInstanceResponse:
    """Spawn a new honeypot instance."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    instance = await service.spawn_honeypot(
        template_id=request.template_id,
        trigger_alert_id=request.trigger_alert_id,
        trigger_device_id=request.trigger_device_id,
        trigger_reason=request.trigger_reason,
        timeout_minutes=request.timeout_minutes,
    )

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to spawn honeypot. Check logs for details.",
        )

    return _instance_to_response(instance)


@router.delete("/{honeypot_id}", response_model=HoneypotInstanceResponse)
async def stop_honeypot(
    honeypot_id: UUID,
    current_user: Annotated[User, Depends(require_operator)],
) -> HoneypotInstanceResponse:
    """Stop and remove a honeypot instance."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    instance = await service.stop_honeypot(honeypot_id)

    if not instance:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Honeypot not found",
        )

    return _instance_to_response(instance)


# ==================== INTERACTION ENDPOINTS ====================


@router.get("/{honeypot_id}/interactions", response_model=list[HoneypotInteractionResponse])
async def get_interactions(
    honeypot_id: UUID,
    _current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[HoneypotInteractionResponse]:
    """Get interactions for a honeypot."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    interactions = await service.get_interactions(
        honeypot_id=honeypot_id,
        limit=limit,
        offset=offset,
    )

    return [
        HoneypotInteractionResponse(
            id=str(i.id),
            timestamp=i.timestamp.isoformat(),
            source_ip=i.source_ip,
            source_port=i.source_port,
            interaction_type=i.interaction_type,
            raw_data=i.raw_data,
            parsed_data=i.parsed_data,
            threat_indicators=i.threat_indicators,
            created_at=i.created_at.isoformat(),
        )
        for i in interactions
    ]


# ==================== ATTACKER PROFILE ENDPOINTS ====================


@router.get("/attackers", response_model=AttackerListResponse)
async def list_attackers(
    _current_user: Annotated[User, Depends(get_current_user)],
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> AttackerListResponse:
    """List attacker profiles."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    profiles, total = await service.get_attacker_profiles(
        limit=limit,
        offset=offset,
    )

    return AttackerListResponse(
        items=[_profile_to_response(p) for p in profiles],
        total=total,
    )


@router.get("/attackers/{source_ip}", response_model=AttackerProfileResponse)
async def get_attacker(
    source_ip: str,
    _current_user: Annotated[User, Depends(get_current_user)],
) -> AttackerProfileResponse:
    """Get a specific attacker profile."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()
    profile = await service.get_attacker_profile(source_ip)

    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attacker profile not found",
        )

    return _profile_to_response(profile)


@router.post("/{honeypot_id}/analyze")
async def trigger_analysis(
    honeypot_id: UUID,
    current_user: Annotated[User, Depends(require_operator)],
) -> dict[str, Any]:
    """Trigger LLM analysis for attackers that interacted with this honeypot."""
    if not settings.honeypot_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Honeypot feature is disabled",
        )

    service = get_honeypot_service()

    # Get unique IPs from this honeypot's interactions
    interactions = await service.get_interactions(honeypot_id, limit=500)
    unique_ips = set(i.source_ip for i in interactions)

    analyzed = 0
    for ip in unique_ips:
        result = await service.analyze_attacker(ip)
        if result:
            analyzed += 1

    return {
        "analyzed": analyzed,
        "total_ips": len(unique_ips),
        "message": f"Analyzed {analyzed} of {len(unique_ips)} attacker profiles",
    }
