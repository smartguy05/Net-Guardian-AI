"""Integration management API endpoints."""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.v1.auth import get_current_user, require_admin
from app.config import settings
from app.models.user import User
from app.services.integrations.adguard import get_adguard_service
from app.services.integrations.pfsense import get_pfsense_service
from app.services.integrations.unifi import get_unifi_service

router = APIRouter()


class IntegrationStatus(BaseModel):
    name: str
    type: str
    enabled: bool
    configured: bool
    connected: bool | None = None
    details: dict[str, Any] = {}


class IntegrationStatusResponse(BaseModel):
    integrations: list[IntegrationStatus]


class TestConnectionResponse(BaseModel):
    success: bool
    message: str
    details: dict[str, Any] = {}
    error: str | None = None


@router.get("/status", response_model=IntegrationStatusResponse)
async def get_integrations_status(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> IntegrationStatusResponse:
    """Get status of all configured integrations."""
    integrations = []

    # AdGuard Home
    adguard = get_adguard_service()
    integrations.append(
        IntegrationStatus(
            name="AdGuard Home",
            type="adguard_home",
            enabled=settings.adguard_enabled,
            configured=adguard.is_configured,
            details={
                "url": settings.adguard_url if settings.adguard_url else None,
            },
        )
    )

    # Router integration (placeholder for future)
    router_configured = bool(
        settings.router_integration_type
        and settings.router_url
        and settings.router_username
    )
    integrations.append(
        IntegrationStatus(
            name="Router",
            type=settings.router_integration_type or "none",
            enabled=bool(settings.router_integration_type),
            configured=router_configured,
            details={
                "type": settings.router_integration_type or "not configured",
                "url": settings.router_url if settings.router_url else None,
            },
        )
    )

    return IntegrationStatusResponse(integrations=integrations)


@router.post("/adguard/test", response_model=TestConnectionResponse)
async def test_adguard_connection(
    _admin: Annotated[User, Depends(require_admin)],
) -> TestConnectionResponse:
    """Test connection to AdGuard Home."""
    adguard = get_adguard_service()

    if not adguard.is_configured:
        return TestConnectionResponse(
            success=False,
            message="AdGuard Home is not configured",
            error="Missing URL, username, or password in configuration",
        )

    result = await adguard.test_connection()

    return TestConnectionResponse(
        success=result.success,
        message=result.message,
        details=result.details or {},
        error=result.error,
    )


@router.get("/adguard/blocked", response_model=list[dict[str, Any]])
async def get_adguard_blocked_devices(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Get list of devices blocked in AdGuard Home."""
    adguard = get_adguard_service()

    if not adguard.is_enabled:
        return []

    return await adguard.get_blocked_devices()


@router.post("/router/test", response_model=TestConnectionResponse)
async def test_router_connection(
    _admin: Annotated[User, Depends(require_admin)],
) -> TestConnectionResponse:
    """Test connection to the configured router (UniFi/pfSense/OPNsense)."""
    router_type = settings.router_integration_type

    if not router_type:
        return TestConnectionResponse(
            success=False,
            message="No router integration configured",
            error="Set ROUTER_INTEGRATION_TYPE to unifi, pfsense, or opnsense",
        )

    # Get the appropriate router service
    if router_type == "unifi":
        router_service = get_unifi_service()
    elif router_type in ("pfsense", "opnsense"):
        router_service = get_pfsense_service()
    else:
        return TestConnectionResponse(
            success=False,
            message=f"Unknown router integration type: {router_type}",
            error="Supported types: unifi, pfsense, opnsense",
        )

    if not router_service.is_configured:
        return TestConnectionResponse(
            success=False,
            message=f"{router_type} is not configured",
            error="Missing URL, username, or password in configuration",
        )

    result = await router_service.test_connection()

    return TestConnectionResponse(
        success=result.success,
        message=result.message,
        details=result.details or {},
        error=result.error,
    )


@router.get("/router/blocked", response_model=list[dict[str, Any]])
async def get_router_blocked_devices(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    """Get list of devices blocked via router integration."""
    router_type = settings.router_integration_type

    if not router_type:
        return []

    # Get the appropriate router service
    if router_type == "unifi":
        router_service = get_unifi_service()
    elif router_type in ("pfsense", "opnsense"):
        router_service = get_pfsense_service()
    else:
        return []

    if not router_service.is_enabled:
        return []

    return await router_service.get_blocked_devices()


@router.post("/sync-quarantine", response_model=dict[str, Any])
async def sync_quarantine_status(
    _admin: Annotated[User, Depends(require_admin)],
) -> dict[str, Any]:
    """Sync quarantine status between database and integrations.

    This ensures devices marked as quarantined in the database
    are actually blocked in the configured integrations.
    """
    from app.services.quarantine_service import get_quarantine_service

    quarantine_service = get_quarantine_service()
    return await quarantine_service.sync_quarantine_status()
