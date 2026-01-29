"""OIDC authentication service for Authentik integration."""

import hashlib
import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlencode

import httpx
import structlog
from jose import jwt
from jose.exceptions import JWTError

from app.config import settings
from app.core.security import UserRole

logger = structlog.get_logger()


class OIDCError(Exception):
    """Base exception for OIDC errors."""
    pass


class OIDCConfigError(OIDCError):
    """OIDC configuration error."""
    pass


class OIDCTokenError(OIDCError):
    """Token validation or exchange error."""
    pass


class OIDCService:
    """Service for handling OIDC authentication with Authentik."""

    def __init__(self) -> None:
        self._oidc_config_cache: dict[str, Any] | None = None
        self._oidc_config_expiry: datetime | None = None
        self._jwks_cache: dict[str, Any] | None = None
        self._jwks_expiry: datetime | None = None

    @property
    def is_configured(self) -> bool:
        """Check if OIDC is properly configured."""
        return bool(
            settings.authentik_enabled
            and settings.authentik_issuer_url
            and settings.authentik_client_id
            and settings.authentik_client_secret
        )

    def _get_issuer_base_url(self) -> str:
        """Get the base issuer URL (without trailing slash)."""
        return settings.authentik_issuer_url.rstrip('/')

    async def get_oidc_config(self) -> dict[str, Any]:
        """Fetch OIDC discovery document from issuer.

        Caches the configuration for 1 hour.
        """
        if not self.is_configured:
            raise OIDCConfigError("OIDC is not configured")

        now = datetime.now(UTC)

        # Return cached config if still valid
        if self._oidc_config_cache and self._oidc_config_expiry and now < self._oidc_config_expiry:
            return self._oidc_config_cache

        issuer_url = self._get_issuer_base_url()
        discovery_url = f"{issuer_url}/.well-known/openid-configuration"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(discovery_url)
                response.raise_for_status()
                config = response.json()

            # Cache for 1 hour
            self._oidc_config_cache = config
            self._oidc_config_expiry = now + timedelta(hours=1)

            logger.info("oidc_config_fetched", issuer=issuer_url)
            return cast(dict[str, Any], config)

        except httpx.HTTPError as e:
            logger.error("oidc_config_fetch_failed", error=str(e), url=discovery_url)
            raise OIDCConfigError(f"Failed to fetch OIDC configuration: {e}")

    async def _get_jwks(self) -> dict[str, Any]:
        """Fetch JWKS (JSON Web Key Set) for token validation.

        Caches the JWKS for 1 hour.
        """
        now = datetime.now(UTC)

        # Return cached JWKS if still valid
        if self._jwks_cache and self._jwks_expiry and now < self._jwks_expiry:
            return self._jwks_cache

        oidc_config = await self.get_oidc_config()
        jwks_uri = oidc_config.get("jwks_uri")

        if not jwks_uri:
            raise OIDCConfigError("JWKS URI not found in OIDC configuration")

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(jwks_uri)
                response.raise_for_status()
                jwks = response.json()

            # Cache for 1 hour
            self._jwks_cache = jwks
            self._jwks_expiry = now + timedelta(hours=1)

            logger.info("jwks_fetched", uri=jwks_uri)
            return cast(dict[str, Any], jwks)

        except httpx.HTTPError as e:
            logger.error("jwks_fetch_failed", error=str(e), url=jwks_uri)
            raise OIDCConfigError(f"Failed to fetch JWKS: {e}")

    def generate_pkce(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate a random code verifier (43-128 characters)
        code_verifier = secrets.token_urlsafe(32)

        # Create code challenge using SHA256
        code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
        # Base64url encode without padding
        import base64
        code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).decode().rstrip('=')

        return code_verifier, code_challenge

    def generate_state(self) -> str:
        """Generate a random state parameter for CSRF protection."""
        return secrets.token_urlsafe(32)

    async def get_authorization_url(self, state: str, code_challenge: str) -> str:
        """Generate the authorization URL for initiating OIDC flow.

        Args:
            state: Random state for CSRF protection
            code_challenge: PKCE code challenge

        Returns:
            Full authorization URL to redirect user to
        """
        oidc_config = await self.get_oidc_config()
        authorization_endpoint = oidc_config.get("authorization_endpoint")

        if not authorization_endpoint:
            raise OIDCConfigError("Authorization endpoint not found in OIDC configuration")

        params = {
            "client_id": settings.authentik_client_id,
            "response_type": "code",
            "scope": settings.authentik_scopes,
            "redirect_uri": settings.authentik_redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        return f"{authorization_endpoint}?{urlencode(params)}"

    async def exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        """Exchange authorization code for tokens.

        Args:
            code: Authorization code from callback
            code_verifier: PKCE code verifier

        Returns:
            Token response containing access_token, id_token, etc.
        """
        oidc_config = await self.get_oidc_config()
        token_endpoint = oidc_config.get("token_endpoint")

        if not token_endpoint:
            raise OIDCConfigError("Token endpoint not found in OIDC configuration")

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.authentik_redirect_uri,
            "client_id": settings.authentik_client_id,
            "client_secret": settings.authentik_client_secret,
            "code_verifier": code_verifier,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    token_endpoint,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code != 200:
                    error_data = response.json() if response.text else {}
                    error_msg = error_data.get("error_description", error_data.get("error", "Unknown error"))
                    logger.error(
                        "oidc_token_exchange_failed",
                        status=response.status_code,
                        error=error_msg,
                    )
                    raise OIDCTokenError(f"Token exchange failed: {error_msg}")

                return cast(dict[str, Any], response.json())

        except httpx.HTTPError as e:
            logger.error("oidc_token_exchange_http_error", error=str(e))
            raise OIDCTokenError(f"Token exchange HTTP error: {e}")

    async def validate_id_token(self, id_token: str) -> dict[str, Any]:
        """Validate ID token signature and claims.

        Args:
            id_token: JWT ID token from Authentik

        Returns:
            Validated token claims
        """
        jwks = await self._get_jwks()

        try:
            # Decode without verification first to get the header
            unverified_header = jwt.get_unverified_header(id_token)
            kid = unverified_header.get("kid")

            # Find the matching key
            key = None
            for k in jwks.get("keys", []):
                if k.get("kid") == kid:
                    key = k
                    break

            if not key:
                raise OIDCTokenError("No matching key found in JWKS")

            # Verify and decode the token
            claims = jwt.decode(
                id_token,
                key,
                algorithms=["RS256", "ES256"],
                audience=settings.authentik_client_id,
                issuer=self._get_issuer_base_url(),
            )

            logger.info("id_token_validated", sub=claims.get("sub"))
            return cast(dict[str, Any], claims)

        except JWTError as e:
            logger.error("id_token_validation_failed", error=str(e))
            raise OIDCTokenError(f"ID token validation failed: {e}")

    def map_groups_to_role(self, groups: list[str]) -> UserRole:
        """Map Authentik groups to NetGuardian role.

        Args:
            groups: List of group names from Authentik

        Returns:
            Mapped UserRole (defaults to configured default role)
        """
        try:
            group_mappings = json.loads(settings.authentik_group_mappings)
        except json.JSONDecodeError:
            logger.warning("invalid_group_mappings_json", raw=settings.authentik_group_mappings)
            group_mappings = {}

        # Check groups in priority order (admin > operator > viewer)
        role_priority = ["admin", "operator", "viewer"]

        for role in role_priority:
            for group_name, mapped_role in group_mappings.items():
                if mapped_role == role and group_name in groups:
                    try:
                        return UserRole(role)
                    except ValueError:
                        continue

        # Return default role
        try:
            return UserRole(settings.authentik_default_role)
        except ValueError:
            return UserRole.VIEWER

    def extract_user_info(self, claims: dict[str, Any]) -> dict[str, Any]:
        """Extract user information from ID token claims.

        Args:
            claims: Validated ID token claims

        Returns:
            User info dict with sub, email, username, groups
        """
        # Try different claim names for groups (Authentik uses 'groups')
        groups = claims.get("groups", claims.get("group", []))
        if isinstance(groups, str):
            groups = [groups]

        return {
            "sub": claims.get("sub"),
            "email": claims.get("email"),
            "username": claims.get("preferred_username", claims.get("email", "").split("@")[0]),
            "name": claims.get("name"),
            "groups": groups,
        }


# Singleton instance
_oidc_service: OIDCService | None = None


def get_oidc_service() -> OIDCService:
    """Get the OIDC service singleton."""
    global _oidc_service
    if _oidc_service is None:
        _oidc_service = OIDCService()
    return _oidc_service
