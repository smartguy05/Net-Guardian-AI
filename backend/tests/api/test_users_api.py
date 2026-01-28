"""Tests for user management API endpoints.

Tests cover:
- List users (pagination)
- Create user (admin only)
- Get user by ID
- Update user
- Deactivate user
- Reset user password
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException, status

from app.core.security import UserRole


class TestListUsers:
    """Tests for the list users endpoint."""

    @pytest.mark.asyncio
    async def test_list_users_returns_paginated_results(self, mock_db_session, mock_current_user_admin):
        """Should return paginated list of users."""
        # Create mock users
        users = [
            MagicMock(
                id=uuid4(),
                username="user1",
                email="user1@example.com",
                role=UserRole.OPERATOR,
                is_active=True,
                must_change_password=False,
                created_at=datetime.now(UTC),
            ),
            MagicMock(
                id=uuid4(),
                username="user2",
                email="user2@example.com",
                role=UserRole.VIEWER,
                is_active=True,
                must_change_password=False,
                created_at=datetime.now(UTC),
            ),
        ]

        # Mock count query
        count_result = MagicMock()
        count_result.scalars.return_value.all.return_value = users

        # Mock paginated query
        paginated_result = MagicMock()
        paginated_result.scalars.return_value.all.return_value = users

        mock_db_session.execute.side_effect = [count_result, paginated_result]

        from app.api.v1.users import list_users

        response = await list_users(
            session=mock_db_session,
            _admin=mock_current_user_admin,
            page=1,
            page_size=50,
        )

        assert response.total == 2
        assert len(response.items) == 2
        assert response.items[0].username == "user1"
        assert response.items[1].username == "user2"

    @pytest.mark.asyncio
    async def test_list_users_empty_result(self, mock_db_session, mock_current_user_admin):
        """Should handle empty user list."""
        count_result = MagicMock()
        count_result.scalars.return_value.all.return_value = []

        paginated_result = MagicMock()
        paginated_result.scalars.return_value.all.return_value = []

        mock_db_session.execute.side_effect = [count_result, paginated_result]

        from app.api.v1.users import list_users

        response = await list_users(
            session=mock_db_session,
            _admin=mock_current_user_admin,
            page=1,
            page_size=50,
        )

        assert response.total == 0
        assert len(response.items) == 0


class TestCreateUser:
    """Tests for the create user endpoint."""

    @pytest.mark.asyncio
    async def test_create_user_success(self, mock_db_session, mock_current_user_admin):
        """Should create a new user with temporary password."""
        # Mock no existing user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        # Make refresh set the expected attributes on the added user
        def refresh_side_effect(user):
            user.id = uuid4()
            user.created_at = datetime.now(UTC)

        mock_db_session.refresh = AsyncMock(side_effect=refresh_side_effect)

        from app.api.v1.users import UserCreate, create_user

        user_data = UserCreate(
            username="newuser",
            email="newuser@example.com",
            role=UserRole.OPERATOR,
        )

        response = await create_user(
            user_data=user_data,
            session=mock_db_session,
            admin=mock_current_user_admin,
        )

        assert response.username == "newuser"
        assert response.email == "newuser@example.com"
        assert response.role == "operator"
        assert response.is_active is True
        assert response.must_change_password is True
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()

        # Verify the user object passed to add() has correct values
        added_user = mock_db_session.add.call_args[0][0]
        assert added_user.username == "newuser"
        assert added_user.email == "newuser@example.com"
        assert added_user.role == UserRole.OPERATOR
        assert added_user.is_active is True
        assert added_user.must_change_password is True
        assert added_user.created_by == mock_current_user_admin.id

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, mock_db_session, mock_current_user_admin):
        """Should reject duplicate username."""
        existing_user = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import UserCreate, create_user

        user_data = UserCreate(
            username="existing",
            email="new@example.com",
            role=UserRole.VIEWER,
        )

        with pytest.raises(HTTPException) as exc_info:
            await create_user(
                user_data=user_data,
                session=mock_db_session,
                admin=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_create_user_default_role_is_viewer(self, mock_db_session, mock_current_user_admin):
        """Should default to viewer role if not specified."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        # Make refresh set the expected attributes on the added user
        def refresh_side_effect(user):
            user.id = uuid4()
            user.created_at = datetime.now(UTC)

        mock_db_session.refresh = AsyncMock(side_effect=refresh_side_effect)

        from app.api.v1.users import UserCreate, create_user

        user_data = UserCreate(
            username="newviewer",
            email="viewer@example.com",
            # role not specified - should default to VIEWER
        )

        response = await create_user(
            user_data=user_data,
            session=mock_db_session,
            admin=mock_current_user_admin,
        )

        assert response.role == "viewer"


class TestGetUser:
    """Tests for the get user endpoint."""

    @pytest.mark.asyncio
    async def test_get_user_success(self, mock_db_session, mock_current_user_admin):
        """Should return user details."""
        user_id = uuid4()
        mock_user = MagicMock(
            id=user_id,
            username="testuser",
            email="test@example.com",
            role=UserRole.OPERATOR,
            is_active=True,
            must_change_password=False,
            created_at=datetime.now(UTC),
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import get_user

        response = await get_user(
            user_id=user_id,
            session=mock_db_session,
            _admin=mock_current_user_admin,
        )

        assert response.id == str(user_id)
        assert response.username == "testuser"
        assert response.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, mock_db_session, mock_current_user_admin):
        """Should return 404 for non-existent user."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import get_user

        with pytest.raises(HTTPException) as exc_info:
            await get_user(
                user_id=uuid4(),
                session=mock_db_session,
                _admin=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestUpdateUser:
    """Tests for the update user endpoint."""

    @pytest.mark.asyncio
    async def test_update_user_email(self, mock_db_session, mock_current_user_admin):
        """Should update user email."""
        user_id = uuid4()
        mock_user = MagicMock(
            id=user_id,
            username="testuser",
            email="old@example.com",
            role=UserRole.OPERATOR,
            is_active=True,
            must_change_password=False,
            created_at=datetime.now(UTC),
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import UserUpdate, update_user

        update_data = UserUpdate(email="new@example.com")

        response = await update_user(
            user_id=user_id,
            user_data=update_data,
            session=mock_db_session,
            _admin=mock_current_user_admin,
        )

        assert mock_user.email == "new@example.com"
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_user_role(self, mock_db_session, mock_current_user_admin):
        """Should update user role."""
        user_id = uuid4()
        mock_user = MagicMock(
            id=user_id,
            username="testuser",
            email="test@example.com",
            role=UserRole.VIEWER,
            is_active=True,
            must_change_password=False,
            created_at=datetime.now(UTC),
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import UserUpdate, update_user

        update_data = UserUpdate(role=UserRole.OPERATOR)

        await update_user(
            user_id=user_id,
            user_data=update_data,
            session=mock_db_session,
            _admin=mock_current_user_admin,
        )

        assert mock_user.role == UserRole.OPERATOR

    @pytest.mark.asyncio
    async def test_update_user_deactivate(self, mock_db_session, mock_current_user_admin):
        """Should deactivate user via update."""
        user_id = uuid4()
        mock_user = MagicMock(
            id=user_id,
            username="testuser",
            email="test@example.com",
            role=UserRole.VIEWER,
            is_active=True,
            must_change_password=False,
            created_at=datetime.now(UTC),
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import UserUpdate, update_user

        update_data = UserUpdate(is_active=False)

        await update_user(
            user_id=user_id,
            user_data=update_data,
            session=mock_db_session,
            _admin=mock_current_user_admin,
        )

        assert mock_user.is_active is False

    @pytest.mark.asyncio
    async def test_update_user_not_found(self, mock_db_session, mock_current_user_admin):
        """Should return 404 for non-existent user."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import UserUpdate, update_user

        with pytest.raises(HTTPException) as exc_info:
            await update_user(
                user_id=uuid4(),
                user_data=UserUpdate(email="test@example.com"),
                session=mock_db_session,
                _admin=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestDeactivateUser:
    """Tests for the deactivate user endpoint."""

    @pytest.mark.asyncio
    async def test_deactivate_user_success(self, mock_db_session, mock_current_user_admin):
        """Should deactivate user."""
        user_id = uuid4()
        mock_user = MagicMock(
            id=user_id,
            username="targetuser",
            is_active=True,
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import deactivate_user

        response = await deactivate_user(
            user_id=user_id,
            session=mock_db_session,
            admin=mock_current_user_admin,
        )

        assert mock_user.is_active is False
        assert "deactivated" in response["message"].lower()
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_deactivate_own_account_rejected(self, mock_db_session, mock_current_user_admin):
        """Should reject self-deactivation."""
        from app.api.v1.users import deactivate_user

        with pytest.raises(HTTPException) as exc_info:
            await deactivate_user(
                user_id=mock_current_user_admin.id,
                session=mock_db_session,
                admin=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "own account" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_deactivate_user_not_found(self, mock_db_session, mock_current_user_admin):
        """Should return 404 for non-existent user."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import deactivate_user

        with pytest.raises(HTTPException) as exc_info:
            await deactivate_user(
                user_id=uuid4(),
                session=mock_db_session,
                admin=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestResetUserPassword:
    """Tests for the password reset endpoint."""

    @pytest.mark.asyncio
    async def test_reset_password_success(self, mock_db_session, mock_current_user_admin):
        """Should reset password and return temporary password."""
        user_id = uuid4()
        mock_user = MagicMock(
            id=user_id,
            username="targetuser",
            password_hash="old_hash",
            must_change_password=False,
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import reset_user_password

        response = await reset_user_password(
            user_id=user_id,
            session=mock_db_session,
            _admin=mock_current_user_admin,
        )

        assert response.temporary_password != ""
        assert len(response.temporary_password) >= 16
        assert mock_user.must_change_password is True
        assert "reset" in response.message.lower()
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_reset_password_user_not_found(self, mock_db_session, mock_current_user_admin):
        """Should return 404 for non-existent user."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.users import reset_user_password

        with pytest.raises(HTTPException) as exc_info:
            await reset_user_password(
                user_id=uuid4(),
                session=mock_db_session,
                _admin=mock_current_user_admin,
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND


class TestUserResponseSerialization:
    """Tests for UserResponse model serialization."""

    def test_user_response_serializes_correctly(self):
        """Should serialize user response with correct fields."""
        from app.api.v1.users import UserResponse

        response = UserResponse(
            id="test-uuid",
            username="testuser",
            email="test@example.com",
            role="operator",
            is_active=True,
            must_change_password=False,
            created_at="2024-01-01T00:00:00",
        )

        assert response.id == "test-uuid"
        assert response.username == "testuser"
        assert response.role == "operator"

    def test_user_list_response_structure(self):
        """Should create list response with items and total."""
        from app.api.v1.users import UserListResponse, UserResponse

        items = [
            UserResponse(
                id="1",
                username="user1",
                email="u1@example.com",
                role="admin",
                is_active=True,
                must_change_password=False,
                created_at="2024-01-01T00:00:00",
            ),
        ]

        response = UserListResponse(items=items, total=1)

        assert response.total == 1
        assert len(response.items) == 1


class TestUserCreate:
    """Tests for UserCreate schema validation."""

    def test_user_create_with_required_fields(self):
        """Should create with required fields."""
        from app.api.v1.users import UserCreate

        data = UserCreate(
            username="newuser",
            email="new@example.com",
        )

        assert data.username == "newuser"
        assert data.role == UserRole.VIEWER  # Default

    def test_user_create_with_all_fields(self):
        """Should create with all fields specified."""
        from app.api.v1.users import UserCreate

        data = UserCreate(
            username="admin_user",
            email="admin@example.com",
            role=UserRole.ADMIN,
        )

        assert data.username == "admin_user"
        assert data.role == UserRole.ADMIN


class TestUserUpdate:
    """Tests for UserUpdate schema."""

    def test_user_update_partial(self):
        """Should allow partial updates."""
        from app.api.v1.users import UserUpdate

        data = UserUpdate(email="updated@example.com")

        assert data.email == "updated@example.com"
        assert data.role is None
        assert data.is_active is None

    def test_user_update_all_fields(self):
        """Should accept all optional fields."""
        from app.api.v1.users import UserUpdate

        data = UserUpdate(
            email="new@example.com",
            role=UserRole.ADMIN,
            is_active=False,
        )

        assert data.email == "new@example.com"
        assert data.role == UserRole.ADMIN
        assert data.is_active is False
