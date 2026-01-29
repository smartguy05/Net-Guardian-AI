"""Tests for OIDC authentication service."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.security import UserRole
from app.services.oidc_service import (
    OIDCConfigError,
    OIDCService,
    get_oidc_service,
)


class TestOIDCService:
    """Tests for OIDCService class."""

    @pytest.fixture
    def oidc_service(self):
        """Create a fresh OIDCService instance."""
        return OIDCService()

    @pytest.fixture
    def mock_settings(self):
        """Mock settings with OIDC configuration."""
        with patch("app.services.oidc_service.settings") as mock:
            mock.authentik_enabled = True
            mock.authentik_issuer_url = "https://auth.example.com/application/o/netguardian/"
            mock.authentik_client_id = "test-client-id"
            mock.authentik_client_secret = "test-client-secret"
            mock.authentik_redirect_uri = "http://localhost:8000/api/v1/auth/oidc/callback"
            mock.authentik_scopes = "openid profile email groups"
            mock.authentik_group_mappings = (
                '{"netguardian-admins": "admin", "netguardian-operators": "operator"}'
            )
            mock.authentik_auto_create_users = True
            mock.authentik_default_role = "viewer"
            yield mock

    def test_is_configured_true(self, oidc_service, mock_settings):
        """Test is_configured returns True when all required settings are present."""
        assert oidc_service.is_configured is True

    def test_is_configured_false_not_enabled(self, oidc_service, mock_settings):
        """Test is_configured returns False when disabled."""
        mock_settings.authentik_enabled = False
        assert oidc_service.is_configured is False

    def test_is_configured_false_missing_issuer(self, oidc_service, mock_settings):
        """Test is_configured returns False when issuer is missing."""
        mock_settings.authentik_issuer_url = ""
        assert oidc_service.is_configured is False

    def test_is_configured_false_missing_client_id(self, oidc_service, mock_settings):
        """Test is_configured returns False when client_id is missing."""
        mock_settings.authentik_client_id = ""
        assert oidc_service.is_configured is False

    def test_generate_pkce(self, oidc_service):
        """Test PKCE code verifier and challenge generation."""
        verifier, challenge = oidc_service.generate_pkce()

        # Verifier should be URL-safe base64
        assert len(verifier) > 32
        assert all(
            c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            for c in verifier
        )

        # Challenge should be different from verifier (it's hashed)
        assert challenge != verifier
        assert len(challenge) > 20

    def test_generate_state(self, oidc_service):
        """Test state generation for CSRF protection."""
        state1 = oidc_service.generate_state()
        state2 = oidc_service.generate_state()

        # States should be unique
        assert state1 != state2
        assert len(state1) > 32

    @pytest.mark.asyncio
    async def test_get_oidc_config(self, oidc_service, mock_settings):
        """Test fetching OIDC discovery document."""
        mock_config = {
            "issuer": "https://auth.example.com/application/o/netguardian/",
            "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
            "token_endpoint": "https://auth.example.com/application/o/token/",
            "jwks_uri": "https://auth.example.com/application/o/netguardian/jwks/",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_config
            mock_response.raise_for_status = MagicMock()

            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )

            config = await oidc_service.get_oidc_config()

            assert config["issuer"] == mock_config["issuer"]
            assert config["authorization_endpoint"] == mock_config["authorization_endpoint"]

    @pytest.mark.asyncio
    async def test_get_oidc_config_caching(self, oidc_service, mock_settings):
        """Test that OIDC config is cached."""
        mock_config = {
            "issuer": "https://auth.example.com/application/o/netguardian/",
            "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
        }

        with patch("httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_config
            mock_response.raise_for_status = MagicMock()

            mock_get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value.get = mock_get

            # First call should fetch
            await oidc_service.get_oidc_config()

            # Second call should use cache
            await oidc_service.get_oidc_config()

            # Should only have made one HTTP request
            assert mock_get.call_count == 1

    @pytest.mark.asyncio
    async def test_get_oidc_config_not_configured(self, oidc_service, mock_settings):
        """Test error when OIDC is not configured."""
        mock_settings.authentik_enabled = False

        with pytest.raises(OIDCConfigError, match="not configured"):
            await oidc_service.get_oidc_config()

    @pytest.mark.asyncio
    async def test_get_authorization_url(self, oidc_service, mock_settings):
        """Test generating authorization URL."""
        mock_config = {
            "authorization_endpoint": "https://auth.example.com/application/o/authorize/",
        }

        oidc_service._oidc_config_cache = mock_config
        oidc_service._oidc_config_expiry = None  # Will be set in get_oidc_config

        with patch.object(oidc_service, "get_oidc_config", return_value=mock_config):
            url = await oidc_service.get_authorization_url("test-state", "test-challenge")

            assert "authorization_endpoint" not in url  # Should be the full URL
            assert "client_id=test-client-id" in url
            assert "state=test-state" in url
            assert "code_challenge=test-challenge" in url
            assert "code_challenge_method=S256" in url

    def test_map_groups_to_role_admin(self, oidc_service, mock_settings):
        """Test group to role mapping - admin."""
        groups = ["netguardian-admins", "other-group"]
        role = oidc_service.map_groups_to_role(groups)
        assert role == UserRole.ADMIN

    def test_map_groups_to_role_operator(self, oidc_service, mock_settings):
        """Test group to role mapping - operator."""
        groups = ["netguardian-operators", "other-group"]
        role = oidc_service.map_groups_to_role(groups)
        assert role == UserRole.OPERATOR

    def test_map_groups_to_role_priority(self, oidc_service, mock_settings):
        """Test group to role mapping respects priority (admin > operator)."""
        groups = ["netguardian-operators", "netguardian-admins"]
        role = oidc_service.map_groups_to_role(groups)
        assert role == UserRole.ADMIN

    def test_map_groups_to_role_default(self, oidc_service, mock_settings):
        """Test group to role mapping falls back to default."""
        groups = ["unknown-group"]
        role = oidc_service.map_groups_to_role(groups)
        assert role == UserRole.VIEWER

    def test_map_groups_to_role_invalid_json(self, oidc_service, mock_settings):
        """Test group to role mapping handles invalid JSON."""
        mock_settings.authentik_group_mappings = "not-valid-json"
        groups = ["netguardian-admins"]
        role = oidc_service.map_groups_to_role(groups)
        assert role == UserRole.VIEWER  # Falls back to default

    def test_extract_user_info(self, oidc_service):
        """Test extracting user info from ID token claims."""
        claims = {
            "sub": "user-123",
            "email": "user@example.com",
            "preferred_username": "testuser",
            "name": "Test User",
            "groups": ["group1", "group2"],
        }

        user_info = oidc_service.extract_user_info(claims)

        assert user_info["sub"] == "user-123"
        assert user_info["email"] == "user@example.com"
        assert user_info["username"] == "testuser"
        assert user_info["name"] == "Test User"
        assert user_info["groups"] == ["group1", "group2"]

    def test_extract_user_info_fallback_username(self, oidc_service):
        """Test extracting username from email when preferred_username missing."""
        claims = {
            "sub": "user-123",
            "email": "user@example.com",
            "groups": [],
        }

        user_info = oidc_service.extract_user_info(claims)

        assert user_info["username"] == "user"

    def test_extract_user_info_groups_as_string(self, oidc_service):
        """Test extracting groups when provided as string."""
        claims = {
            "sub": "user-123",
            "email": "user@example.com",
            "groups": "single-group",
        }

        user_info = oidc_service.extract_user_info(claims)

        assert user_info["groups"] == ["single-group"]


class TestGetOIDCService:
    """Tests for get_oidc_service singleton."""

    def test_returns_same_instance(self):
        """Test that get_oidc_service returns the same instance."""
        # Reset singleton
        import app.services.oidc_service

        app.services.oidc_service._oidc_service = None

        service1 = get_oidc_service()
        service2 = get_oidc_service()

        assert service1 is service2

    def test_returns_oidc_service_instance(self):
        """Test that get_oidc_service returns OIDCService instance."""
        import app.services.oidc_service

        app.services.oidc_service._oidc_service = None

        service = get_oidc_service()

        assert isinstance(service, OIDCService)
