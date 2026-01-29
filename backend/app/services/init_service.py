"""Application initialization service."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.logging import get_logger
from app.core.security import UserRole, generate_secure_password, hash_password
from app.db.session import AsyncSessionLocal
from app.models.user import User

logger = get_logger(__name__)


def _check_security_configuration() -> None:
    """Check for insecure configuration and log warnings.

    This helps operators identify security issues in their deployment.
    """
    warnings = []

    # Check for default/weak secret key
    if settings.secret_key == "change-this-to-a-secure-secret-key":
        warnings.append(
            "SECRET_KEY is using the default value. "
            "Generate a secure key with: openssl rand -hex 32"
        )
    elif len(settings.secret_key) < 32:
        warnings.append(
            f"SECRET_KEY is only {len(settings.secret_key)} characters. "
            "Use at least 32 characters for production."
        )

    # Check for debug mode in production
    if settings.debug:
        warnings.append("DEBUG mode is enabled. Disable in production (DEBUG=false).")

    # Check CORS configuration
    if "*" in settings.cors_origins:
        warnings.append(
            "CORS is configured to allow all origins (*). "
            "Restrict to specific origins in production."
        )

    # Check for default database password
    if "password" in settings.database_url.lower() and "localhost" not in settings.database_url:
        warnings.append(
            "Database URL may contain a weak password. Use strong passwords in production."
        )

    # Check JWT expiration settings
    if settings.jwt_access_token_expire_minutes > 60:
        warnings.append(
            f"JWT access token expiration is {settings.jwt_access_token_expire_minutes} minutes. "
            "Consider shorter expiration (15-30 min) for better security."
        )

    # Check Anthropic API key
    if settings.llm_enabled and not settings.anthropic_api_key:
        warnings.append(
            "LLM is enabled but ANTHROPIC_API_KEY is not set. LLM features will not work."
        )

    # Log warnings
    if warnings:
        logger.warning("=" * 60)
        logger.warning("SECURITY CONFIGURATION WARNINGS")
        logger.warning("=" * 60)
        for i, warning in enumerate(warnings, 1):
            logger.warning(f"  [{i}] {warning}")
        logger.warning("=" * 60)
    else:
        logger.info("Security configuration check passed")


async def initialize_application() -> None:
    """Initialize the application on startup.

    This includes:
    - Security configuration validation
    - Creating the default admin user if no users exist
    - Any other first-run initialization tasks
    """
    # Run security checks
    _check_security_configuration()

    async with AsyncSessionLocal() as session:
        await _ensure_admin_user(session)


async def _ensure_admin_user(session: AsyncSession) -> None:
    """Create default admin user if no users exist.

    The admin password is randomly generated and printed to logs.
    The admin must change their password on first login.
    """
    # Check if any users exist
    result = await session.execute(select(User).limit(1))
    existing_user = result.scalar_one_or_none()

    if existing_user is not None:
        logger.debug("Users already exist, skipping admin creation")
        return

    # Generate a secure random password
    initial_password = generate_secure_password(20)

    # Create the admin user
    admin_user = User(
        username="admin",
        email="admin@localhost",
        password_hash=hash_password(initial_password),
        role=UserRole.ADMIN,
        is_active=True,
        must_change_password=True,
    )

    session.add(admin_user)
    await session.commit()

    # Log the initial password - IMPORTANT: This is the only time it's shown
    logger.warning(
        "=" * 60,
    )
    logger.warning(
        "INITIAL ADMIN USER CREATED",
    )
    logger.warning(
        "=" * 60,
    )
    logger.warning(
        "Username: admin",
    )
    logger.warning(
        f"Password: {initial_password}",
    )
    logger.warning(
        "IMPORTANT: Change this password immediately after first login!",
    )
    logger.warning(
        "=" * 60,
    )
