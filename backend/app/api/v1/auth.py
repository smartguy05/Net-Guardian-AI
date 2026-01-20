"""Authentication API endpoints."""

from datetime import datetime, timezone
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.rate_limit import login_rate_limiter
from app.core.security import (
    UserRole,
    create_access_token,
    create_refresh_token,
    create_2fa_pending_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.core.validation import validate_password_strength
from app.db.session import get_async_session
from app.models.user import User
from app.services.totp_service import get_totp_service

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# Pydantic schemas
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: "UserResponse"
    requires_2fa: bool = False
    pending_token: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    must_change_password: bool
    last_login: datetime | None
    totp_enabled: bool = False

    class Config:
        from_attributes = True


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class TwoFactorSetupResponse(BaseModel):
    """Response when initiating 2FA setup."""
    secret: str
    qr_code: str
    backup_codes: List[str]


class TwoFactorVerifyRequest(BaseModel):
    """Request to verify 2FA code during login."""
    pending_token: str
    code: str


class TwoFactorEnableRequest(BaseModel):
    """Request to enable 2FA after setup."""
    code: str


class TwoFactorDisableRequest(BaseModel):
    """Request to disable 2FA."""
    password: str
    code: Optional[str] = None


# Dependency to get current user
async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> User:
    """Validate JWT token and return current user."""
    payload = decode_token(token)

    if payload.get("type") != "access":
        raise AuthenticationError("Invalid token type")

    user_id = payload.get("sub")
    if not user_id:
        raise AuthenticationError("Invalid token")

    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise AuthenticationError("User not found")

    if not user.is_active:
        raise AuthenticationError("User account is disabled")

    return user


async def require_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Require admin role."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def require_operator(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Require operator or admin role."""
    if current_user.role not in (UserRole.ADMIN, UserRole.OPERATOR):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator access required",
        )
    return current_user


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> LoginResponse:
    """Authenticate user and return JWT tokens.

    If 2FA is enabled, returns requires_2fa=True with a pending_token
    that must be used with the /2fa/verify endpoint.
    """
    # Rate limit login attempts to prevent brute force
    login_rate_limiter.check(request)

    # Find user by username
    result = await session.execute(
        select(User).where(User.username == form_data.username.lower())
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )

    # Check if 2FA is enabled
    if user.totp_enabled:
        # Return pending token for 2FA verification
        pending_token = create_2fa_pending_token(str(user.id))
        return LoginResponse(
            access_token="",
            refresh_token="",
            requires_2fa=True,
            pending_token=pending_token,
            user=UserResponse(
                id=str(user.id),
                username=user.username,
                email=user.email,
                role=user.role.value,
                is_active=user.is_active,
                must_change_password=user.must_change_password,
                last_login=user.last_login,
                totp_enabled=user.totp_enabled,
            ),
        )

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await session.commit()

    # Reset rate limit on successful login
    login_rate_limiter.reset(request)

    # Generate tokens
    access_token = create_access_token(str(user.id), user.role)
    refresh_token = create_refresh_token(str(user.id))

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse(
            id=str(user.id),
            username=user.username,
            email=user.email,
            role=user.role.value,
            is_active=user.is_active,
            must_change_password=user.must_change_password,
            last_login=user.last_login,
            totp_enabled=user.totp_enabled,
        ),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> TokenResponse:
    """Refresh access token using refresh token."""
    payload = decode_token(token)

    if payload.get("type") != "refresh":
        raise AuthenticationError("Invalid token type - refresh token required")

    user_id = payload.get("sub")
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise AuthenticationError("User not found or disabled")

    # Generate new tokens
    access_token = create_access_token(str(user.id), user.role)
    new_refresh_token = create_refresh_token(str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UserResponse:
    """Get current user information."""
    return UserResponse(
        id=str(current_user.id),
        username=current_user.username,
        email=current_user.email,
        role=current_user.role.value,
        is_active=current_user.is_active,
        must_change_password=current_user.must_change_password,
        last_login=current_user.last_login,
        totp_enabled=current_user.totp_enabled,
    )


@router.patch("/password")
async def change_password(
    request: PasswordChangeRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> dict:
    """Change current user's password."""
    # Verify current password
    if not verify_password(request.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Validate new password strength
    is_valid, errors = validate_password_strength(request.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"message": "Password does not meet requirements", "errors": errors},
        )

    # Check new password is different from current
    if verify_password(request.new_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    # Update password
    current_user.password_hash = hash_password(request.new_password)
    current_user.must_change_password = False
    await session.commit()

    return {"message": "Password changed successfully"}


@router.post("/logout")
async def logout(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """Logout current user.

    Note: Since we're using stateless JWTs, this endpoint is mostly symbolic.
    The client should discard the tokens.
    """
    return {"message": "Logged out successfully"}


# ============================================================================
# Two-Factor Authentication Endpoints
# ============================================================================


@router.post("/2fa/verify", response_model=LoginResponse)
async def verify_2fa(
    request: Request,
    body: TwoFactorVerifyRequest,
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> LoginResponse:
    """Verify 2FA code and complete login.

    Takes the pending_token from the login response and the TOTP/backup code.
    """
    # Decode the pending token
    try:
        payload = decode_token(body.pending_token)
    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired 2FA session",
        )

    if payload.get("type") != "2fa_pending":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    # Get user
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
        )

    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled for this user",
        )

    totp_service = get_totp_service()
    code = body.code.replace(" ", "").strip()

    # Try TOTP code first
    if totp_service.verify_totp(user.totp_secret, code):
        pass  # Valid TOTP
    else:
        # Try backup code
        if user.backup_codes:
            is_valid, code_index = totp_service.verify_backup_code(
                code, user.backup_codes
            )
            if is_valid and code_index is not None:
                # Remove used backup code
                user.backup_codes = [
                    c for i, c in enumerate(user.backup_codes) if i != code_index
                ]
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid 2FA code",
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code",
            )

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await session.commit()

    # Reset rate limit
    login_rate_limiter.reset(request)

    # Generate tokens
    access_token = create_access_token(str(user.id), user.role)
    refresh_token = create_refresh_token(str(user.id))

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse(
            id=str(user.id),
            username=user.username,
            email=user.email,
            role=user.role.value,
            is_active=user.is_active,
            must_change_password=user.must_change_password,
            last_login=user.last_login,
            totp_enabled=user.totp_enabled,
        ),
    )


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> TwoFactorSetupResponse:
    """Initiate 2FA setup by generating a new secret and QR code.

    This does NOT enable 2FA - the user must verify the code first.
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled. Disable it first to set up again.",
        )

    totp_service = get_totp_service()

    # Generate new secret and backup codes
    secret = totp_service.generate_secret()
    backup_codes = totp_service.generate_backup_codes()
    qr_code = totp_service.generate_qr_code(secret, current_user.username)

    # Store the secret temporarily (not enabled yet)
    current_user.totp_secret = secret
    current_user.backup_codes = backup_codes
    await session.commit()

    return TwoFactorSetupResponse(
        secret=secret,
        qr_code=qr_code,
        backup_codes=backup_codes,
    )


@router.post("/2fa/enable")
async def enable_2fa(
    body: TwoFactorEnableRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> dict:
    """Enable 2FA after verifying the code from setup.

    The user must have called /2fa/setup first and verify the code
    from their authenticator app.
    """
    if current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled",
        )

    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No 2FA setup in progress. Call /2fa/setup first.",
        )

    totp_service = get_totp_service()

    # Verify the code
    if not totp_service.verify_totp(current_user.totp_secret, body.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    # Enable 2FA
    current_user.totp_enabled = True
    await session.commit()

    return {"message": "Two-factor authentication enabled successfully"}


@router.post("/2fa/disable")
async def disable_2fa(
    body: TwoFactorDisableRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> dict:
    """Disable 2FA for the current user.

    Requires password verification and optionally 2FA code.
    """
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled",
        )

    # Verify password
    if not verify_password(body.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password",
        )

    # Verify 2FA code if provided
    if body.code:
        totp_service = get_totp_service()
        if not totp_service.verify_totp(current_user.totp_secret, body.code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid 2FA code",
            )

    # Disable 2FA
    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.backup_codes = None
    await session.commit()

    return {"message": "Two-factor authentication disabled"}


@router.post("/2fa/backup-codes", response_model=List[str])
async def regenerate_backup_codes(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_async_session)],
) -> List[str]:
    """Regenerate backup codes.

    This invalidates all existing backup codes.
    """
    if not current_user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA must be enabled to regenerate backup codes",
        )

    totp_service = get_totp_service()
    backup_codes = totp_service.generate_backup_codes()

    current_user.backup_codes = backup_codes
    await session.commit()

    return backup_codes


@router.get("/2fa/status")
async def get_2fa_status(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """Get current 2FA status for the user."""
    return {
        "enabled": current_user.totp_enabled,
        "backup_codes_remaining": len(current_user.backup_codes or []),
    }
