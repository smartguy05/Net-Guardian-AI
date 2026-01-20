"""FastAPI application entry point for NetGuardian AI."""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import __version__
from app.api.v1.router import api_router
from app.config import settings
from app.core.exceptions import NetGuardianException
from app.core.logging import get_logger, setup_logging
from app.core.cache import CacheService, set_cache_service
from app.core.http_client import close_http_client_pool
from app.core.middleware import MetricsMiddleware, RequestLoggingMiddleware
from app.core.rate_limiter import RateLimitMiddleware
from app.db.session import close_db, init_db
from app.events.bus import close_event_bus, get_event_bus
from app.services.init_service import initialize_application

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager.

    Handles startup and shutdown events.
    """
    # Startup
    setup_logging()
    logger.info(
        "Starting NetGuardian AI",
        version=__version__,
        debug=settings.debug,
    )

    await init_db()

    # Initialize event bus
    event_bus = await get_event_bus()
    logger.info("Event bus connected")

    # Initialize cache service using Redis from event bus
    if event_bus._redis:
        cache_service = CacheService(event_bus._redis)
        set_cache_service(cache_service)
        logger.info("Cache service initialized")

    # Initialize application (create admin user if needed, etc.)
    await initialize_application()

    logger.info("NetGuardian AI started successfully")

    yield

    # Shutdown
    logger.info("Shutting down NetGuardian AI")
    await close_http_client_pool()
    logger.info("HTTP client pool closed")
    await close_event_bus()
    logger.info("Event bus disconnected")
    await close_db()
    logger.info("NetGuardian AI shutdown complete")


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        description="AI-Powered Home Network Security Monitoring System",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add metrics middleware for Prometheus
    app.add_middleware(MetricsMiddleware)

    # Add rate limiting middleware
    app.add_middleware(
        RateLimitMiddleware,
        enabled=settings.rate_limit_enabled,
    )

    # Add request logging middleware (after metrics so it logs after metrics are recorded)
    if settings.debug:
        app.add_middleware(RequestLoggingMiddleware)

    # Exception handlers
    @app.exception_handler(NetGuardianException)
    async def netguardian_exception_handler(
        request: Request, exc: NetGuardianException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.__class__.__name__,
                "message": exc.message,
                "details": exc.details,
            },
        )

    # Include API routes
    app.include_router(api_router, prefix="/api/v1")

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Health check endpoint for container orchestration."""
        return {
            "status": "healthy",
            "version": __version__,
            "service": "netguardian-backend",
        }

    return app


# Create the application instance
app = create_application()
