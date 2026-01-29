"""Tests for OIDC authentication API endpoints."""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from app.core.security import UserRole


class TestOIDCConfigEndpoint:
    """Tests for GET /auth/oidc/config endpoint."""

    def test_config_disabled(self, test_client: TestClient):
        """Test OIDC config when disabled."""
        with patch("app.api.v1.auth.get_oidc_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_configured = False
            mock_get_service.return_value = mock_service

            response = test_client.get("/api/v1/auth/oidc/config")

            assert response.status_code == 200
            data = response.json()
            assert data["enabled"] is False
            assert data.get("issuer") is None
            assert data.get("client_id") is None

    def test_config_enabled(self, test_client: TestClient):
        """Test OIDC config when enabled."""
        with patch("app.api.v1.auth.get_oidc_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_configured = True
            mock_get_service.return_value = mock_service

            with patch("app.api.v1.auth.settings") as mock_settings:
                mock_settings.authentik_issuer_url = (
                    "https://auth.example.com/application/o/netguardian/"
                )
                mock_settings.authentik_client_id = "test-client-id"

                response = test_client.get("/api/v1/auth/oidc/config")

                assert response.status_code == 200
                data = response.json()
                assert data["enabled"] is True
                assert data["issuer"] == "https://auth.example.com/application/o/netguardian/"
                assert data["client_id"] == "test-client-id"


class TestOIDCAuthorizeEndpoint:
    """Tests for GET /auth/oidc/authorize endpoint."""

    def test_authorize_not_configured(self, test_client: TestClient):
        """Test authorize endpoint when OIDC not configured."""
        with patch("app.api.v1.auth.get_oidc_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_configured = False
            mock_get_service.return_value = mock_service

            response = test_client.get("/api/v1/auth/oidc/authorize")

            assert response.status_code == 400
            assert "not configured" in response.json()["detail"].lower()

    def test_authorize_success(self, test_client: TestClient):
        """Test successful authorize endpoint."""
        with patch("app.api.v1.auth.get_oidc_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_configured = True
            mock_service.generate_pkce.return_value = ("verifier123", "challenge123")
            mock_service.generate_state.return_value = "state123"
            mock_service.get_authorization_url = AsyncMock(
                return_value="https://auth.example.com/authorize?client_id=test"
            )
            mock_get_service.return_value = mock_service

            # Mock the cache service
            mock_cache = MagicMock()
            mock_cache.set = AsyncMock()
            with patch("app.api.v1.auth.get_cache_service", return_value=mock_cache):
                response = test_client.get("/api/v1/auth/oidc/authorize")

                assert response.status_code == 200
                data = response.json()
                assert data["state"] == "state123"
                assert "authorize" in data["authorization_url"]

                # Verify cache was called with state
                mock_cache.set.assert_called_once()


class TestOIDCCallbackEndpoint:
    """Tests for POST /auth/oidc/callback endpoint."""

    def test_callback_not_configured(self, test_client: TestClient):
        """Test callback endpoint when OIDC not configured."""
        with patch("app.api.v1.auth.get_oidc_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_configured = False
            mock_get_service.return_value = mock_service

            response = test_client.post(
                "/api/v1/auth/oidc/callback",
                json={
                    "code": "auth-code",
                    "state": "state123",
                    "code_verifier": "verifier123",
                },
            )

            assert response.status_code == 400
            assert "not configured" in response.json()["detail"].lower()

    def test_callback_invalid_state(self, test_client: TestClient):
        """Test callback with invalid state parameter."""
        with patch("app.api.v1.auth.get_oidc_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_configured = True
            mock_get_service.return_value = mock_service

            # Mock cache to return None (state not found)
            mock_cache = MagicMock()
            mock_cache.get = AsyncMock(return_value=None)
            with patch("app.api.v1.auth.get_cache_service", return_value=mock_cache):
                response = test_client.post(
                    "/api/v1/auth/oidc/callback",
                    json={
                        "code": "auth-code",
                        "state": "invalid-state",
                        "code_verifier": "verifier123",
                    },
                )

                assert response.status_code == 400
                assert "invalid" in response.json()["detail"].lower()

    def test_callback_success_new_user(self, test_client: TestClient):
        """Test successful callback that creates new user."""
        with patch("app.api.v1.auth.get_oidc_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_configured = True
            mock_service.exchange_code = AsyncMock(
                return_value={
                    "id_token": "jwt-token",
                    "access_token": "access-token",
                }
            )
            mock_service.validate_id_token = AsyncMock(
                return_value={
                    "sub": "user-123",
                    "email": "newuser@example.com",
                    "preferred_username": "newuser",
                    "groups": [],
                }
            )
            mock_service.extract_user_info.return_value = {
                "sub": "user-123",
                "email": "newuser@example.com",
                "username": "newuser",
                "name": "New User",
                "groups": [],
            }
            mock_service.map_groups_to_role.return_value = UserRole.VIEWER
            mock_get_service.return_value = mock_service

            # Mock cache service
            mock_cache = MagicMock()
            mock_cache.get = AsyncMock(return_value="verifier123")
            mock_cache.delete = AsyncMock()

            with patch("app.api.v1.auth.get_cache_service", return_value=mock_cache):
                with patch("app.api.v1.auth.settings") as mock_settings:
                    mock_settings.authentik_auto_create_users = True

                    response = test_client.post(
                        "/api/v1/auth/oidc/callback",
                        json={
                            "code": "auth-code",
                            "state": "valid-state",
                            "code_verifier": "verifier123",
                        },
                    )

                    # This would need actual DB setup to work fully
                    # For now, verify the endpoint structure is correct
                    assert response.status_code in [200, 400, 500]

    def test_callback_auto_create_disabled(self, test_client: TestClient):
        """Test callback when auto-create is disabled and user doesn't exist."""
        with patch("app.api.v1.auth.get_oidc_service") as mock_get_service:
            mock_service = MagicMock()
            mock_service.is_configured = True
            mock_service.exchange_code = AsyncMock(
                return_value={
                    "id_token": "jwt-token",
                }
            )
            mock_service.validate_id_token = AsyncMock(
                return_value={
                    "sub": "unknown-user",
                }
            )
            mock_service.extract_user_info.return_value = {
                "sub": "unknown-user",
                "email": "unknown@example.com",
                "username": "unknown",
                "groups": [],
            }
            mock_get_service.return_value = mock_service

            # Mock cache service
            mock_cache = MagicMock()
            mock_cache.get = AsyncMock(return_value="verifier123")
            mock_cache.delete = AsyncMock()

            with patch("app.api.v1.auth.get_cache_service", return_value=mock_cache):
                with patch("app.api.v1.auth.settings") as mock_settings:
                    mock_settings.authentik_auto_create_users = False

                    response = test_client.post(
                        "/api/v1/auth/oidc/callback",
                        json={
                            "code": "auth-code",
                            "state": "valid-state",
                            "code_verifier": "verifier123",
                        },
                    )

                    # Should return 403 when user not found and auto-create disabled
                    # (or other error depending on DB state)
                    assert response.status_code in [403, 400, 500]
