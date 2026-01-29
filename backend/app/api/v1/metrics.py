"""Prometheus metrics endpoint."""

from fastapi import APIRouter, Response
from fastapi.responses import PlainTextResponse

from app.services.metrics_service import get_metrics, get_metrics_content_type

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("", response_class=PlainTextResponse)
async def metrics() -> Response:
    """
    Expose Prometheus metrics.

    This endpoint returns application metrics in Prometheus format.
    It can be scraped by Prometheus or compatible monitoring systems.

    Metrics include:
    - HTTP request counts and latencies
    - WebSocket connection counts
    - Event processing statistics
    - Alert and anomaly counts
    - Device counts by status
    - Collector run statistics
    - Threat intelligence statistics
    - LLM usage statistics
    - Database connection pool stats
    """
    metrics_data = get_metrics()
    return Response(
        content=metrics_data,
        media_type=get_metrics_content_type(),
    )
