"""User management API endpoints (Admin only)."""

from typing import Annotated, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin
from app.core.security import UserRole, generate_secure_password, hash_password
from app.db.session import get_async_session
from app.models.user import User

router = APIRouter()


# Pydantic schemas
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    role: UserRole = UserRole.VIEWER


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    must_change_password: bool
    created_at: str

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    items: List[UserResponse]
    total: int


class PasswordResetResponse(BaseModel):
    temporary_password: str
    message: str


@router.get("", response_model=UserListResponse)
async def list_users(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> UserListResponse:
    """List all users (Admin only)."""
    # Count total
    count_result = await session.execute(select(User))
    total = len(count_result.scalars().all())

    # Get paginated results
    offset = (page - 1) * page_size
    result = await session.execute(
        select(User).offset(offset).limit(page_size).order_by(User.created_at.desc())
    )
    users = result.scalars().all()

    return UserListResponse(
        items=[
            UserResponse(
                id=str(u.id),
                username=u.username,
                email=u.email,
                role=u.role.value,
                is_active=u.is_active,
                must_change_password=u.must_change_password,
                created_at=u.created_at.isoformat(),
            )
            for u in users
        ],
        total=total,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> UserResponse:
    """Create a new user (Admin only)."""
    # Check for existing username/email
    existing = await session.execute(
        select(User).where(
            (User.username == user_data.username.lower())
            | (User.email == user_data.email.lower())
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists",
        )

    # Generate temporary password
    temp_password = generate_secure_password(16)

    # Create user
    user = User(
        username=user_data.username.lower(),
        email=user_data.email.lower(),
        password_hash=hash_password(temp_password),
        role=user_data.role,
        is_active=True,
        must_change_password=True,
        created_by=admin.id,
    )

    session.add(user)
    await session.commit()
    await session.refresh(user)

    # Note: In production, you'd email the temp password to the user
    # For now, it's returned in the response (not ideal for production)
    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        role=user.role.value,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        created_at=user.created_at.isoformat(),
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> UserResponse:
    """Get user details (Admin only)."""
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        role=user.role.value,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        created_at=user.created_at.isoformat(),
    )


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_data: UserUpdate,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> UserResponse:
    """Update user (Admin only)."""
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user_data.email is not None:
        user.email = user_data.email.lower()
    if user_data.role is not None:
        user.role = user_data.role
    if user_data.is_active is not None:
        user.is_active = user_data.is_active

    await session.commit()
    await session.refresh(user)

    return UserResponse(
        id=str(user.id),
        username=user.username,
        email=user.email,
        role=user.role.value,
        is_active=user.is_active,
        must_change_password=user.must_change_password,
        created_at=user.created_at.isoformat(),
    )


@router.delete("/{user_id}")
async def deactivate_user(
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    admin: Annotated[User, Depends(require_admin)],
) -> dict:
    """Deactivate user (Admin only)."""
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )

    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    user.is_active = False
    await session.commit()

    return {"message": "User deactivated successfully"}


@router.post("/{user_id}/reset-password", response_model=PasswordResetResponse)
async def reset_user_password(
    user_id: UUID,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _admin: Annotated[User, Depends(require_admin)],
) -> PasswordResetResponse:
    """Reset user password (Admin only)."""
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Generate new temporary password
    temp_password = generate_secure_password(16)
    user.password_hash = hash_password(temp_password)
    user.must_change_password = True

    await session.commit()

    return PasswordResetResponse(
        temporary_password=temp_password,
        message="Password reset successfully. User must change password on next login.",
    )
