"""Tests for authentication API endpoints.

Tests cover:
- Login with valid/invalid credentials
- Login rate limiting
- Token refresh
- Logout
- Password change
- 2FA setup and verification
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from app.core.security import UserRole, hash_password, create_access_token, create_refresh_token


class TestLogin:
    """Tests for the login endpoint."""

    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock()
        user.id = uuid4()
        user.username = "testuser"
        user.email = "test@example.com"
        user.password_hash = hash_password("validpassword")
        user.role = UserRole.OPERATOR
        user.is_active = True
        user.must_change_password = False
        user.last_login = None
        user.totp_enabled = False
        user.totp_secret = None
        return user

    @pytest.mark.asyncio
    async def test_login_valid_credentials(self, mock_user, mock_db_session):
        """Should return tokens for valid credentials."""
        # Setup mock
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.auth import login
        from fastapi import Request

        # Create mock request
        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        # Create mock form data
        form_data = MagicMock()
        form_data.username = "testuser"
        form_data.password = "validpassword"

        with patch("app.api.v1.auth.login_rate_limiter"):
            response = await login(request, form_data, mock_db_session)

        assert response.access_token != ""
        assert response.refresh_token != ""
        assert response.token_type == "bearer"
        assert response.user.username == "testuser"
        assert response.requires_2fa is False

    @pytest.mark.asyncio
    async def test_login_invalid_password(self, mock_user, mock_db_session):
        """Should reject invalid password."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.auth import login
        from fastapi import HTTPException, Request

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        form_data = MagicMock()
        form_data.username = "testuser"
        form_data.password = "wrongpassword"

        with patch("app.api.v1.auth.login_rate_limiter"):
            with pytest.raises(HTTPException) as exc_info:
                await login(request, form_data, mock_db_session)

        assert exc_info.value.status_code == 401
        assert "Invalid username or password" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_login_user_not_found(self, mock_db_session):
        """Should reject login for non-existent user."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.auth import login
        from fastapi import HTTPException, Request

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        form_data = MagicMock()
        form_data.username = "nonexistent"
        form_data.password = "anypassword"

        with patch("app.api.v1.auth.login_rate_limiter"):
            with pytest.raises(HTTPException) as exc_info:
                await login(request, form_data, mock_db_session)

        assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_login_disabled_user(self, mock_user, mock_db_session):
        """Should reject login for disabled user."""
        mock_user.is_active = False
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.auth import login
        from fastapi import HTTPException, Request

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        form_data = MagicMock()
        form_data.username = "testuser"
        form_data.password = "validpassword"

        with patch("app.api.v1.auth.login_rate_limiter"):
            with pytest.raises(HTTPException) as exc_info:
                await login(request, form_data, mock_db_session)

        assert exc_info.value.status_code == 401
        assert "disabled" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_login_with_2fa_enabled(self, mock_user, mock_db_session):
        """Should return pending token when 2FA is enabled."""
        mock_user.totp_enabled = True
        mock_user.totp_secret = "testsecret"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        from app.api.v1.auth import login
        from fastapi import Request

        request = MagicMock(spec=Request)
        request.client = MagicMock()
        request.client.host = "127.0.0.1"

        form_data = MagicMock()
        form_data.username = "testuser"
        form_data.password = "validpassword"

        with patch("app.api.v1.auth.login_rate_limiter"):
            response = await login(request, form_data, mock_db_session)

        assert response.requires_2fa is True
        assert response.pending_token is not None
        assert response.access_token == ""  # No access token until 2FA verified


class TestTokenRefresh:
    """Tests for the token refresh endpoint."""

    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock()
        user.id = uuid4()
        user.role = UserRole.OPERATOR
        user.is_active = True
        return user

    @pytest.mark.asyncio
    async def test_refresh_with_valid_token(self, mock_user, mock_db_session):
        """Should return new tokens with valid refresh token."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        refresh_token = create_refresh_token(str(mock_user.id))

        from app.api.v1.auth import refresh_token as refresh_endpoint

        response = await refresh_endpoint(refresh_token, mock_db_session)

        assert response.access_token != ""
        assert response.refresh_token != ""
        assert response.token_type == "bearer"

    @pytest.mark.asyncio
    async def test_refresh_with_access_token_fails(self, mock_user, mock_db_session):
        """Should reject access token used as refresh token."""
        access_token = create_access_token(str(mock_user.id), mock_user.role)

        from app.api.v1.auth import refresh_token as refresh_endpoint
        from app.core.exceptions import AuthenticationError

        with pytest.raises(AuthenticationError) as exc_info:
            await refresh_endpoint(access_token, mock_db_session)

        assert "refresh token required" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_refresh_with_disabled_user(self, mock_user, mock_db_session):
        """Should reject refresh for disabled user."""
        mock_user.is_active = False
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        refresh_token = create_refresh_token(str(mock_user.id))

        from app.api.v1.auth import refresh_token as refresh_endpoint
        from app.core.exceptions import AuthenticationError

        with pytest.raises(AuthenticationError):
            await refresh_endpoint(refresh_token, mock_db_session)


class TestGetCurrentUserInfo:
    """Tests for the /me endpoint."""

    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock()
        user.id = uuid4()
        user.username = "testuser"
        user.email = "test@example.com"
        user.role = UserRole.OPERATOR
        user.is_active = True
        user.must_change_password = False
        user.last_login = datetime.now(timezone.utc)
        user.totp_enabled = False
        return user

    @pytest.mark.asyncio
    async def test_get_current_user_info(self, mock_user):
        """Should return current user information."""
        from app.api.v1.auth import get_current_user_info

        response = await get_current_user_info(mock_user)

        assert response.username == "testuser"
        assert response.email == "test@example.com"
        assert response.role == "operator"
        assert response.is_active is True


class TestPasswordChange:
    """Tests for the password change endpoint."""

    @pytest.fixture
    def mock_user(self):
        """Create a mock user for testing."""
        user = MagicMock()
        user.id = uuid4()
        user.password_hash = hash_password("currentpassword")
        user.must_change_password = False
        return user

    @pytest.mark.asyncio
    async def test_change_password_success(self, mock_user, mock_db_session):
        """Should change password with valid current password."""
        from app.api.v1.auth import change_password, PasswordChangeRequest

        request = PasswordChangeRequest(
            current_password="currentpassword",
            new_password="NewSecurePassword123!",
        )

        response = await change_password(request, mock_user, mock_db_session)

        assert "success" in response["message"].lower()
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, mock_user, mock_db_session):
        """Should reject if current password is wrong."""
        from app.api.v1.auth import change_password, PasswordChangeRequest
        from fastapi import HTTPException

        request = PasswordChangeRequest(
            current_password="wrongpassword",
            new_password="NewSecurePassword123!",
        )

        with pytest.raises(HTTPException) as exc_info:
            await change_password(request, mock_user, mock_db_session)

        assert exc_info.value.status_code == 400
        assert "incorrect" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_change_password_same_as_current(self, mock_user, mock_db_session):
        """Should reject if new password is same as current."""
        from app.api.v1.auth import change_password, PasswordChangeRequest
        from fastapi import HTTPException

        request = PasswordChangeRequest(
            current_password="currentpassword",
            new_password="currentpassword",  # Same as current
        )

        with pytest.raises(HTTPException) as exc_info:
            await change_password(request, mock_user, mock_db_session)

        assert exc_info.value.status_code == 400


class TestLogout:
    """Tests for the logout endpoint."""

    @pytest.mark.asyncio
    async def test_logout(self, mock_current_user_operator):
        """Should return success message on logout."""
        from app.api.v1.auth import logout

        response = await logout(mock_current_user_operator)

        assert "success" in response["message"].lower()


class TestTwoFactorSetup:
    """Tests for 2FA setup endpoints."""

    @pytest.fixture
    def mock_user(self):
        """Create a mock user without 2FA."""
        user = MagicMock()
        user.id = uuid4()
        user.username = "testuser"
        user.totp_enabled = False
        user.totp_secret = None
        user.backup_codes = None
        return user

    @pytest.mark.asyncio
    async def test_setup_2fa(self, mock_user, mock_db_session):
        """Should generate secret and QR code for 2FA setup."""
        from app.api.v1.auth import setup_2fa

        with patch("app.api.v1.auth.get_totp_service") as mock_totp:
            mock_service = MagicMock()
            mock_service.generate_secret.return_value = "TESTSECRET123"
            mock_service.generate_backup_codes.return_value = ["code1", "code2"]
            mock_service.generate_qr_code.return_value = "data:image/png;base64,..."
            mock_totp.return_value = mock_service

            response = await setup_2fa(mock_user, mock_db_session)

        assert response.secret == "TESTSECRET123"
        assert len(response.backup_codes) == 2
        assert response.qr_code.startswith("data:image")

    @pytest.mark.asyncio
    async def test_setup_2fa_already_enabled(self, mock_user, mock_db_session):
        """Should reject setup if 2FA is already enabled."""
        mock_user.totp_enabled = True

        from app.api.v1.auth import setup_2fa
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await setup_2fa(mock_user, mock_db_session)

        assert exc_info.value.status_code == 400
        assert "already enabled" in exc_info.value.detail.lower()


class TestTwoFactorVerification:
    """Tests for 2FA verification during login."""

    @pytest.fixture
    def mock_user(self):
        """Create a mock user with 2FA enabled."""
        user = MagicMock()
        user.id = uuid4()
        user.username = "testuser"
        user.email = "test@example.com"
        user.role = UserRole.OPERATOR
        user.is_active = True
        user.must_change_password = False
        user.last_login = None
        user.totp_enabled = True
        user.totp_secret = "TESTSECRET"
        user.backup_codes = ["backup1", "backup2"]
        return user

    @pytest.mark.asyncio
    async def test_verify_2fa_with_valid_code(self, mock_user, mock_db_session):
        """Should complete login with valid TOTP code."""
        from app.api.v1.auth import verify_2fa, TwoFactorVerifyRequest
        from app.core.security import create_2fa_pending_token
        from fastapi import Request

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        request = MagicMock(spec=Request)
        pending_token = create_2fa_pending_token(str(mock_user.id))

        body = TwoFactorVerifyRequest(
            pending_token=pending_token,
            code="123456",
        )

        with patch("app.api.v1.auth.get_totp_service") as mock_totp:
            mock_service = MagicMock()
            mock_service.verify_totp.return_value = True
            mock_totp.return_value = mock_service

            with patch("app.api.v1.auth.login_rate_limiter"):
                response = await verify_2fa(request, body, mock_db_session)

        assert response.access_token != ""
        assert response.refresh_token != ""
        assert response.requires_2fa is False

    @pytest.mark.asyncio
    async def test_verify_2fa_with_invalid_code(self, mock_user, mock_db_session):
        """Should reject invalid TOTP code."""
        from app.api.v1.auth import verify_2fa, TwoFactorVerifyRequest
        from app.core.security import create_2fa_pending_token
        from fastapi import HTTPException, Request

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        request = MagicMock(spec=Request)
        pending_token = create_2fa_pending_token(str(mock_user.id))

        body = TwoFactorVerifyRequest(
            pending_token=pending_token,
            code="000000",  # Invalid code
        )

        with patch("app.api.v1.auth.get_totp_service") as mock_totp:
            mock_service = MagicMock()
            mock_service.verify_totp.return_value = False
            mock_service.verify_backup_code.return_value = (False, None)
            mock_totp.return_value = mock_service

            with pytest.raises(HTTPException) as exc_info:
                await verify_2fa(request, body, mock_db_session)

        assert exc_info.value.status_code == 401
        assert "invalid" in exc_info.value.detail.lower()


class TestGetCurrentUser:
    """Tests for the get_current_user dependency."""

    @pytest.mark.asyncio
    async def test_get_current_user_valid_token(self, mock_db_session):
        """Should return user for valid access token."""
        user_id = uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.is_active = True

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db_session.execute.return_value = mock_result

        access_token = create_access_token(str(user_id), UserRole.OPERATOR)

        from app.api.v1.auth import get_current_user

        user = await get_current_user(access_token, mock_db_session)

        assert user == mock_user

    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, mock_db_session):
        """Should raise error for invalid token."""
        from app.api.v1.auth import get_current_user
        from app.core.exceptions import AuthenticationError

        with pytest.raises(AuthenticationError):
            await get_current_user("invalid-token", mock_db_session)

    @pytest.mark.asyncio
    async def test_get_current_user_refresh_token_rejected(self, mock_db_session):
        """Should reject refresh token used as access token."""
        user_id = uuid4()
        refresh_token = create_refresh_token(str(user_id))

        from app.api.v1.auth import get_current_user
        from app.core.exceptions import AuthenticationError

        with pytest.raises(AuthenticationError) as exc_info:
            await get_current_user(refresh_token, mock_db_session)

        assert "invalid token type" in str(exc_info.value).lower()


class TestRoleRequirements:
    """Tests for role requirement dependencies."""

    @pytest.mark.asyncio
    async def test_require_admin_with_admin(self, mock_current_user_admin):
        """Should allow admin user."""
        from app.api.v1.auth import require_admin

        user = await require_admin(mock_current_user_admin)
        assert user == mock_current_user_admin

    @pytest.mark.asyncio
    async def test_require_admin_with_operator(self, mock_current_user_operator):
        """Should reject operator user."""
        from app.api.v1.auth import require_admin
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await require_admin(mock_current_user_operator)

        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_require_operator_with_operator(self, mock_current_user_operator):
        """Should allow operator user."""
        from app.api.v1.auth import require_operator

        user = await require_operator(mock_current_user_operator)
        assert user == mock_current_user_operator

    @pytest.mark.asyncio
    async def test_require_operator_with_viewer(self, mock_current_user_viewer):
        """Should reject viewer user."""
        from app.api.v1.auth import require_operator
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            await require_operator(mock_current_user_viewer)

        assert exc_info.value.status_code == 403
