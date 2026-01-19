"""Database session management."""

from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Create async engine with configurable connection pooling
engine = create_async_engine(
    settings.async_database_url,
    echo=settings.debug,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_timeout=settings.db_pool_timeout,
    pool_recycle=settings.db_pool_recycle,
    pool_pre_ping=True,  # Verify connections before using them
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an async database session.

    Yields:
        AsyncSession: Database session for use in request handlers.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database connection."""
    logger.info("Initializing database connection", url=settings.async_database_url.split("@")[-1])
    # Test connection
    async with engine.begin() as conn:
        await conn.execute(text("SELECT 1"))
    logger.info("Database connection established")


async def close_db() -> None:
    """Close database connection pool."""
    logger.info("Closing database connection pool")
    await engine.dispose()
    logger.info("Database connection pool closed")
