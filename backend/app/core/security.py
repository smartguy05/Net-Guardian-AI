"""Security utilities for authentication and authorization."""

import secrets
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, cast

import bcrypt
from jose import JWTError, jwt

from app.config import settings
from app.core.exceptions import AuthenticationError, AuthorizationError


class UserRole(str, Enum):
    """User roles for RBAC."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


# Role hierarchy: higher roles include lower role permissions
ROLE_HIERARCHY = {
    UserRole.ADMIN: {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},
    UserRole.OPERATOR: {UserRole.OPERATOR, UserRole.VIEWER},
    UserRole.VIEWER: {UserRole.VIEWER},
}

# Permissions by role
PERMISSIONS = {
    # View permissions (all roles)
    "view:dashboard": {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},
    "view:devices": {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},
    "view:events": {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},
    "view:alerts": {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},
    "view:stats": {UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER},
    # Operator permissions
    "action:acknowledge_alert": {UserRole.ADMIN, UserRole.OPERATOR},
    "action:quarantine_device": {UserRole.ADMIN, UserRole.OPERATOR},
    "action:release_device": {UserRole.ADMIN, UserRole.OPERATOR},
    "action:modify_device": {UserRole.ADMIN, UserRole.OPERATOR},
    # Admin permissions
    "manage:users": {UserRole.ADMIN},
    "manage:sources": {UserRole.ADMIN},
    "manage:rules": {UserRole.ADMIN},
    "manage:system": {UserRole.ADMIN},
}


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Args:
        password: Plain text password.

    Returns:
        Bcrypt hashed password string.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.

    Args:
        plain_password: Plain text password to verify.
        hashed_password: Bcrypt hashed password to compare against.

    Returns:
        True if password matches, False otherwise.
    """
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Length of the password to generate.

    Returns:
        Random password string.
    """
    return secrets.token_urlsafe(length)


def create_access_token(
    subject: str,
    role: UserRole,
    expires_delta: timedelta | None = None,
    additional_claims: dict[str, Any] | None = None,
) -> str:
    """Create a JWT access token.

    Args:
        subject: The subject (user ID) for the token.
        role: The user's role.
        expires_delta: Optional custom expiration time.
        additional_claims: Optional additional JWT claims.

    Returns:
        Encoded JWT token string.
    """
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_access_token_expire_minutes)

    to_encode = {
        "sub": subject,
        "role": role.value,
        "exp": expire,
        "type": "access",
        "iat": datetime.now(UTC),
    }

    if additional_claims:
        to_encode.update(additional_claims)

    return cast(str, jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm))


def create_refresh_token(
    subject: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a JWT refresh token.

    Args:
        subject: The subject (user ID) for the token.
        expires_delta: Optional custom expiration time.

    Returns:
        Encoded JWT refresh token string.
    """
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)

    to_encode = {
        "sub": subject,
        "exp": expire,
        "type": "refresh",
        "iat": datetime.now(UTC),
        "jti": secrets.token_urlsafe(16),  # Unique token ID for revocation
    }

    return cast(str, jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm))


def create_2fa_pending_token(
    subject: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a temporary token for 2FA verification.

    This token is issued after password verification but before 2FA completion.
    It has a short expiration and can only be used for 2FA verification.

    Args:
        subject: The subject (user ID) for the token.
        expires_delta: Optional custom expiration time (default: 5 minutes).

    Returns:
        Encoded JWT token string.
    """
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=5)

    to_encode = {
        "sub": subject,
        "exp": expire,
        "type": "2fa_pending",
        "iat": datetime.now(UTC),
    }

    return cast(str, jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm))


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token.

    Args:
        token: JWT token string to decode.

    Returns:
        Decoded token payload.

    Raises:
        AuthenticationError: If token is invalid or expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return cast(dict[str, Any], payload)
    except JWTError as e:
        raise AuthenticationError(
            message="Invalid or expired token",
            details={"error": str(e)},
        )


def check_permission(user_role: UserRole, permission: str) -> bool:
    """Check if a role has a specific permission.

    Args:
        user_role: The user's role.
        permission: The permission to check.

    Returns:
        True if the role has the permission, False otherwise.
    """
    allowed_roles = PERMISSIONS.get(permission, set())
    return user_role in allowed_roles


def require_permission(user_role: UserRole, permission: str) -> None:
    """Require a specific permission, raising an error if not met.

    Args:
        user_role: The user's role.
        permission: The required permission.

    Raises:
        AuthorizationError: If the user lacks the required permission.
    """
    if not check_permission(user_role, permission):
        raise AuthorizationError(
            message=f"Permission denied: {permission}",
            details={"required_permission": permission, "user_role": user_role.value},
        )


def require_role(user_role: UserRole, required_role: UserRole) -> None:
    """Require a minimum role level.

    Args:
        user_role: The user's actual role.
        required_role: The minimum required role.

    Raises:
        AuthorizationError: If the user's role is insufficient.
    """
    allowed_roles = ROLE_HIERARCHY.get(user_role, set())
    if required_role not in allowed_roles:
        raise AuthorizationError(
            message=f"Role {required_role.value} or higher required",
            details={"user_role": user_role.value, "required_role": required_role.value},
        )
