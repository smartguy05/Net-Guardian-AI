"""Authentication API endpoints."""

from datetime import datetime, timezone
from typing import Annotated

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
    decode_token,
    hash_password,
    verify_password,
)
from app.core.validation import validate_password_strength
from app.db.session import get_async_session
from app.models.user import User

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


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    must_change_password: bool
    last_login: datetime | None

    class Config:
        from_attributes = True


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


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
    """Authenticate user and return JWT tokens."""
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
