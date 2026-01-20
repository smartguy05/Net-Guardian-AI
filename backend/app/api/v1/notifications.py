"""Notification preferences API endpoints."""

from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user
from app.db.session import get_async_session
from app.models.notification_preferences import NotificationPreferences
from app.models.user import User
from app.services.email_service import get_email_service
from app.services.ntfy_service import get_ntfy_service

router = APIRouter()


class NotificationPreferencesResponse(BaseModel):
    """Response model for notification preferences."""

    id: str
    user_id: str

    # Email settings
    email_enabled: bool
    email_address: Optional[str]
    email_on_critical: bool
    email_on_high: bool
    email_on_medium: bool
    email_on_low: bool
    email_on_anomaly: bool
    email_on_quarantine: bool

    # ntfy settings
    ntfy_enabled: bool
    ntfy_topic: Optional[str]
    ntfy_on_critical: bool
    ntfy_on_high: bool
    ntfy_on_medium: bool
    ntfy_on_low: bool
    ntfy_on_anomaly: bool
    ntfy_on_quarantine: bool

    class Config:
        from_attributes = True


class NotificationPreferencesUpdate(BaseModel):
    """Request model for updating notification preferences."""

    # Email settings
    email_enabled: Optional[bool] = None
    email_address: Optional[str] = None
    email_on_critical: Optional[bool] = None
    email_on_high: Optional[bool] = None
    email_on_medium: Optional[bool] = None
    email_on_low: Optional[bool] = None
    email_on_anomaly: Optional[bool] = None
    email_on_quarantine: Optional[bool] = None

    # ntfy settings
    ntfy_enabled: Optional[bool] = None
    ntfy_topic: Optional[str] = None
    ntfy_on_critical: Optional[bool] = None
    ntfy_on_high: Optional[bool] = None
    ntfy_on_medium: Optional[bool] = None
    ntfy_on_low: Optional[bool] = None
    ntfy_on_anomaly: Optional[bool] = None
    ntfy_on_quarantine: Optional[bool] = None


class NotificationStatusResponse(BaseModel):
    """Response model for notification service status."""

    email_configured: bool
    ntfy_configured: bool
    ntfy_server_url: str


class TestNotificationRequest(BaseModel):
    """Request model for sending test notifications."""

    type: str  # "email" or "ntfy"
    email_address: Optional[str] = None
    ntfy_topic: Optional[str] = None


class TestNotificationResponse(BaseModel):
    """Response model for test notification result."""

    success: bool
    message: Optional[str] = None
    error: Optional[str] = None


def _prefs_to_response(prefs: NotificationPreferences) -> NotificationPreferencesResponse:
    """Convert a NotificationPreferences model to response."""
    return NotificationPreferencesResponse(
        id=str(prefs.id),
        user_id=str(prefs.user_id),
        email_enabled=prefs.email_enabled,
        email_address=prefs.email_address,
        email_on_critical=prefs.email_on_critical,
        email_on_high=prefs.email_on_high,
        email_on_medium=prefs.email_on_medium,
        email_on_low=prefs.email_on_low,
        email_on_anomaly=prefs.email_on_anomaly,
        email_on_quarantine=prefs.email_on_quarantine,
        ntfy_enabled=prefs.ntfy_enabled,
        ntfy_topic=prefs.ntfy_topic,
        ntfy_on_critical=prefs.ntfy_on_critical,
        ntfy_on_high=prefs.ntfy_on_high,
        ntfy_on_medium=prefs.ntfy_on_medium,
        ntfy_on_low=prefs.ntfy_on_low,
        ntfy_on_anomaly=prefs.ntfy_on_anomaly,
        ntfy_on_quarantine=prefs.ntfy_on_quarantine,
    )


@router.get("/status", response_model=NotificationStatusResponse)
async def get_notification_status(
    _current_user: Annotated[User, Depends(get_current_user)],
) -> NotificationStatusResponse:
    """Get notification service configuration status."""
    email_service = get_email_service()
    ntfy_service = get_ntfy_service()

    return NotificationStatusResponse(
        email_configured=email_service.is_configured,
        ntfy_configured=ntfy_service.is_configured,
        ntfy_server_url=ntfy_service.server_url,
    )


@router.get("/preferences", response_model=NotificationPreferencesResponse)
async def get_preferences(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> NotificationPreferencesResponse:
    """Get the current user's notification preferences."""
    result = await session.execute(
        select(NotificationPreferences).where(
            NotificationPreferences.user_id == current_user.id
        )
    )
    prefs = result.scalar_one_or_none()

    if not prefs:
        # Create default preferences if not exists
        prefs = NotificationPreferences(
            user_id=current_user.id,
            email_address=current_user.email,
        )
        session.add(prefs)
        await session.commit()
        await session.refresh(prefs)

    return _prefs_to_response(prefs)


@router.put("/preferences", response_model=NotificationPreferencesResponse)
async def update_preferences(
    update: NotificationPreferencesUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> NotificationPreferencesResponse:
    """Update the current user's notification preferences."""
    result = await session.execute(
        select(NotificationPreferences).where(
            NotificationPreferences.user_id == current_user.id
        )
    )
    prefs = result.scalar_one_or_none()

    if not prefs:
        prefs = NotificationPreferences(
            user_id=current_user.id,
            email_address=current_user.email,
        )
        session.add(prefs)

    # Update fields
    update_data = update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if hasattr(prefs, field):
            setattr(prefs, field, value)

    await session.commit()
    await session.refresh(prefs)

    return _prefs_to_response(prefs)


@router.post("/test", response_model=TestNotificationResponse)
async def send_test_notification(
    request: TestNotificationRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> TestNotificationResponse:
    """Send a test notification to verify configuration."""
    if request.type == "email":
        email_service = get_email_service()

        if not email_service.is_configured:
            return TestNotificationResponse(
                success=False,
                error="Email (SMTP) is not configured",
            )

        email_address = request.email_address or current_user.email
        if not email_address:
            return TestNotificationResponse(
                success=False,
                error="No email address provided",
            )

        success = await email_service.send_alert_notification(
            to_email=email_address,
            alert_title="Test Notification",
            alert_description="This is a test notification from NetGuardian AI. If you receive this, your email notifications are working correctly.",
            severity="low",
        )

        if success:
            return TestNotificationResponse(
                success=True,
                message=f"Test email sent to {email_address}",
            )
        else:
            return TestNotificationResponse(
                success=False,
                error="Failed to send test email. Check server logs for details.",
            )

    elif request.type == "ntfy":
        ntfy_service = get_ntfy_service()

        if not ntfy_service.is_configured:
            return TestNotificationResponse(
                success=False,
                error="ntfy.sh is not configured (no default topic set)",
            )

        result = await ntfy_service.test_connection(topic=request.ntfy_topic)

        return TestNotificationResponse(
            success=result["success"],
            message=result.get("message"),
            error=result.get("error"),
        )

    else:
        return TestNotificationResponse(
            success=False,
            error=f"Unknown notification type: {request.type}",
        )


@router.post("/test/email")
async def test_email_connection(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """Test SMTP connection without sending an email."""
    email_service = get_email_service()
    result = await email_service.test_connection()
    return result


@router.post("/test/ntfy")
async def test_ntfy_connection(
    current_user: Annotated[User, Depends(get_current_user)],
    topic: Optional[str] = None,
) -> dict:
    """Test ntfy.sh connection by sending a test notification."""
    ntfy_service = get_ntfy_service()
    result = await ntfy_service.test_connection(topic=topic)
    return result
