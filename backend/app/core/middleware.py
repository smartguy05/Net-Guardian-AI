"""Custom middleware for the application."""

import time
import re
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import structlog

from app.services.metrics_service import (
    record_http_request,
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_IN_PROGRESS,
)

logger = structlog.get_logger()


# Patterns to normalize dynamic path segments
PATH_PATTERNS = [
    (re.compile(r"/devices/[a-f0-9-]{36}"), "/devices/{id}"),
    (re.compile(r"/events/[a-f0-9-]{36}"), "/events/{id}"),
    (re.compile(r"/alerts/[a-f0-9-]{36}"), "/alerts/{id}"),
    (re.compile(r"/users/[a-f0-9-]{36}"), "/users/{id}"),
    (re.compile(r"/sources/[a-zA-Z0-9_-]+"), "/sources/{id}"),
    (re.compile(r"/baselines/[a-f0-9-]{36}"), "/baselines/{id}"),
    (re.compile(r"/anomalies/[a-f0-9-]{36}"), "/anomalies/{id}"),
    (re.compile(r"/playbooks/[a-f0-9-]{36}"), "/playbooks/{id}"),
    (re.compile(r"/rules/[a-zA-Z0-9_-]+"), "/rules/{id}"),
    (re.compile(r"/threat-intel/feeds/[a-f0-9-]{36}"), "/threat-intel/feeds/{id}"),
    (re.compile(r"/retention/policies/[a-f0-9-]{36}"), "/retention/policies/{id}"),
]


def normalize_path(path: str) -> str:
    """Normalize path by replacing dynamic segments with placeholders."""
    for pattern, replacement in PATH_PATTERNS:
        path = pattern.sub(replacement, path)
    return path


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to collect Prometheus metrics for HTTP requests."""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip metrics endpoint to avoid recursion
        if request.url.path.endswith("/metrics"):
            return await call_next(request)

        method = request.method
        path = normalize_path(request.url.path)

        # Track in-progress requests
        HTTP_REQUESTS_IN_PROGRESS.labels(method=method, endpoint=path).inc()

        start_time = time.time()
        status_code = 500  # Default in case of unhandled exception

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            raise
        finally:
            # Record metrics
            duration = time.time() - start_time
            HTTP_REQUEST_DURATION_SECONDS.labels(method=method, endpoint=path).observe(duration)
            HTTP_REQUESTS_IN_PROGRESS.labels(method=method, endpoint=path).dec()
            record_http_request(method, path, status_code)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging."""

    def __init__(self, app: ASGIApp, log_request_body: bool = False, log_response_body: bool = False):
        super().__init__(app)
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip health check and metrics endpoints for cleaner logs
        if request.url.path in ["/health", "/api/v1/metrics"]:
            return await call_next(request)

        request_id = request.headers.get("X-Request-ID", "-")
        client_ip = request.client.host if request.client else "-"

        # Log request
        log_data = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.query_params) if request.query_params else None,
            "client_ip": client_ip,
            "user_agent": request.headers.get("User-Agent", "-"),
        }

        logger.info("Request received", **log_data)

        start_time = time.time()

        try:
            response = await call_next(request)
            duration = time.time() - start_time

            # Log response
            logger.info(
                "Response sent",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration * 1000, 2),
            )

            return response

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "Request failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                error=str(e),
                duration_ms=round(duration * 1000, 2),
            )
            raise
