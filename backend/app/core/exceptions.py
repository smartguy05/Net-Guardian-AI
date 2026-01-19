"""Custom exceptions for NetGuardian AI."""

from typing import Any, Dict, Optional


class NetGuardianException(Exception):
    """Base exception for all NetGuardian errors."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 500,
    ) -> None:
        self.message = message
        self.details = details or {}
        self.status_code = status_code
        super().__init__(self.message)


class AuthenticationError(NetGuardianException):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication failed",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details, status_code=401)


class AuthorizationError(NetGuardianException):
    """Raised when user lacks required permissions."""

    def __init__(
        self,
        message: str = "Insufficient permissions",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details, status_code=403)


class NotFoundError(NetGuardianException):
    """Raised when a requested resource is not found."""

    def __init__(
        self,
        message: str = "Resource not found",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details, status_code=404)


class ValidationError(NetGuardianException):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str = "Validation failed",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details, status_code=422)


class DatabaseError(NetGuardianException):
    """Raised when a database operation fails."""

    def __init__(
        self,
        message: str = "Database operation failed",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details, status_code=500)


class ExternalServiceError(NetGuardianException):
    """Raised when an external service call fails."""

    def __init__(
        self,
        message: str = "External service error",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details, status_code=502)


class RateLimitError(NetGuardianException):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message, details, status_code=429)
