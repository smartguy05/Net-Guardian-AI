"""Prometheus metrics service for application monitoring."""

import os
import time
from collections.abc import Callable
from functools import wraps
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    Info,
    generate_latest,
    multiprocess,
)


# Check if we're in multiprocess mode
def _is_multiprocess() -> bool:
    return "prometheus_multiproc_dir" in os.environ


# Use default registry or multiprocess registry
if _is_multiprocess():
    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry)  # type: ignore[no-untyped-call]
else:
    registry = REGISTRY


# Application info
APP_INFO = Info(
    "netguardian",
    "NetGuardian AI application information",
    registry=registry if _is_multiprocess() else REGISTRY,
)
APP_INFO.info({
    "version": "0.1.0",
    "name": "NetGuardian AI",
})

# HTTP metrics
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
    registry=registry if _is_multiprocess() else REGISTRY,
)

HTTP_REQUESTS_IN_PROGRESS = Gauge(
    "http_requests_in_progress",
    "Number of HTTP requests currently in progress",
    ["method", "endpoint"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# WebSocket metrics
WEBSOCKET_CONNECTIONS = Gauge(
    "websocket_connections_active",
    "Number of active WebSocket connections",
    registry=registry if _is_multiprocess() else REGISTRY,
)

WEBSOCKET_MESSAGES_SENT = Counter(
    "websocket_messages_sent_total",
    "Total WebSocket messages sent",
    ["message_type"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# Event metrics
EVENTS_PROCESSED_TOTAL = Counter(
    "events_processed_total",
    "Total events processed",
    ["event_type", "source_id"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

EVENTS_PARSE_ERRORS = Counter(
    "events_parse_errors_total",
    "Total event parsing errors",
    ["parser_type"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# Alert metrics
ALERTS_CREATED_TOTAL = Counter(
    "alerts_created_total",
    "Total alerts created",
    ["severity"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

ALERTS_ACTIVE = Gauge(
    "alerts_active",
    "Number of active (unresolved) alerts",
    ["severity"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# Anomaly metrics
ANOMALIES_DETECTED_TOTAL = Counter(
    "anomalies_detected_total",
    "Total anomalies detected",
    ["anomaly_type", "severity"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# Device metrics
DEVICES_TOTAL = Gauge(
    "devices_total",
    "Total number of devices",
    ["status"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

DEVICES_QUARANTINED = Gauge(
    "devices_quarantined",
    "Number of quarantined devices",
    registry=registry if _is_multiprocess() else REGISTRY,
)

# Collector metrics
COLLECTOR_RUNS_TOTAL = Counter(
    "collector_runs_total",
    "Total collector runs",
    ["collector_type", "status"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

COLLECTOR_LAST_RUN = Gauge(
    "collector_last_run_timestamp",
    "Timestamp of last collector run",
    ["collector_type"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

COLLECTOR_ERRORS_TOTAL = Counter(
    "collector_errors_total",
    "Total collector errors",
    ["source_id", "error_type"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

COLLECTOR_RETRIES_TOTAL = Counter(
    "collector_retries_total",
    "Total collector retries",
    ["source_id"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

COLLECTOR_CIRCUIT_STATE = Gauge(
    "collector_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=half_open, 2=open)",
    ["source_id"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# Threat intelligence metrics
THREAT_INTEL_FEEDS = Gauge(
    "threat_intel_feeds_total",
    "Total threat intelligence feeds",
    ["status"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

THREAT_INTEL_INDICATORS = Gauge(
    "threat_intel_indicators_total",
    "Total threat indicators",
    ["indicator_type"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

THREAT_INTEL_HITS = Counter(
    "threat_intel_hits_total",
    "Total threat intelligence hits",
    ["indicator_type", "severity"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# Database metrics
DB_CONNECTIONS_ACTIVE = Gauge(
    "db_connections_active",
    "Number of active database connections",
    registry=registry if _is_multiprocess() else REGISTRY,
)

DB_QUERY_DURATION_SECONDS = Histogram(
    "db_query_duration_seconds",
    "Database query duration in seconds",
    ["operation"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# LLM metrics
LLM_REQUESTS_TOTAL = Counter(
    "llm_requests_total",
    "Total LLM API requests",
    ["model", "operation"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

LLM_REQUEST_DURATION_SECONDS = Histogram(
    "llm_request_duration_seconds",
    "LLM API request duration in seconds",
    ["model"],
    buckets=[0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
    registry=registry if _is_multiprocess() else REGISTRY,
)

LLM_TOKENS_USED = Counter(
    "llm_tokens_used_total",
    "Total LLM tokens used",
    ["model", "token_type"],
    registry=registry if _is_multiprocess() else REGISTRY,
)

# Playbook metrics
PLAYBOOK_EXECUTIONS_TOTAL = Counter(
    "playbook_executions_total",
    "Total playbook executions",
    ["playbook_id", "status"],
    registry=registry if _is_multiprocess() else REGISTRY,
)


def get_metrics() -> bytes:
    """Generate metrics in Prometheus format."""
    if _is_multiprocess():
        return generate_latest(registry)
    return generate_latest(REGISTRY)


def get_metrics_content_type() -> str:
    """Get the content type for metrics response."""
    return CONTENT_TYPE_LATEST


def track_request_duration(method: str, endpoint: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to track HTTP request duration."""
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            HTTP_REQUESTS_IN_PROGRESS.labels(method=method, endpoint=endpoint).inc()
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                HTTP_REQUEST_DURATION_SECONDS.labels(method=method, endpoint=endpoint).observe(duration)
                HTTP_REQUESTS_IN_PROGRESS.labels(method=method, endpoint=endpoint).dec()
        return wrapper
    return decorator


# Helper functions for updating metrics
def record_http_request(method: str, endpoint: str, status_code: int) -> None:
    """Record an HTTP request."""
    HTTP_REQUESTS_TOTAL.labels(method=method, endpoint=endpoint, status_code=str(status_code)).inc()


def record_event_processed(event_type: str, source_id: str) -> None:
    """Record a processed event."""
    EVENTS_PROCESSED_TOTAL.labels(event_type=event_type, source_id=source_id).inc()


def record_parse_error(parser_type: str) -> None:
    """Record a parsing error."""
    EVENTS_PARSE_ERRORS.labels(parser_type=parser_type).inc()


def record_alert_created(severity: str) -> None:
    """Record an alert creation."""
    ALERTS_CREATED_TOTAL.labels(severity=severity).inc()


def record_anomaly_detected(anomaly_type: str, severity: str) -> None:
    """Record an anomaly detection."""
    ANOMALIES_DETECTED_TOTAL.labels(anomaly_type=anomaly_type, severity=severity).inc()


def record_collector_run(collector_type: str, status: str) -> None:
    """Record a collector run."""
    COLLECTOR_RUNS_TOTAL.labels(collector_type=collector_type, status=status).inc()
    COLLECTOR_LAST_RUN.labels(collector_type=collector_type).set(time.time())


def record_threat_intel_hit(indicator_type: str, severity: str) -> None:
    """Record a threat intelligence hit."""
    THREAT_INTEL_HITS.labels(indicator_type=indicator_type, severity=severity).inc()


def record_llm_request(model: str, operation: str, duration: float, input_tokens: int, output_tokens: int) -> None:
    """Record an LLM API request."""
    LLM_REQUESTS_TOTAL.labels(model=model, operation=operation).inc()
    LLM_REQUEST_DURATION_SECONDS.labels(model=model).observe(duration)
    LLM_TOKENS_USED.labels(model=model, token_type="input").inc(input_tokens)
    LLM_TOKENS_USED.labels(model=model, token_type="output").inc(output_tokens)


def record_playbook_execution(playbook_id: str, status: str) -> None:
    """Record a playbook execution."""
    PLAYBOOK_EXECUTIONS_TOTAL.labels(playbook_id=playbook_id, status=status).inc()


def update_websocket_connections(count: int) -> None:
    """Update active WebSocket connection count."""
    WEBSOCKET_CONNECTIONS.set(count)


def record_websocket_message(message_type: str) -> None:
    """Record a WebSocket message sent."""
    WEBSOCKET_MESSAGES_SENT.labels(message_type=message_type).inc()


def update_device_counts(active: int, inactive: int, quarantined: int, unknown: int) -> None:
    """Update device counts by status."""
    DEVICES_TOTAL.labels(status="active").set(active)
    DEVICES_TOTAL.labels(status="inactive").set(inactive)
    DEVICES_TOTAL.labels(status="quarantined").set(quarantined)
    DEVICES_TOTAL.labels(status="unknown").set(unknown)
    DEVICES_QUARANTINED.set(quarantined)


def update_alert_counts(new: int, acknowledged: int, critical: int, high: int, medium: int, low: int) -> None:
    """Update active alert counts."""
    ALERTS_ACTIVE.labels(severity="critical").set(critical)
    ALERTS_ACTIVE.labels(severity="high").set(high)
    ALERTS_ACTIVE.labels(severity="medium").set(medium)
    ALERTS_ACTIVE.labels(severity="low").set(low)


def update_threat_intel_counts(enabled_feeds: int, disabled_feeds: int, indicators_by_type: dict[str, int]) -> None:
    """Update threat intelligence counts."""
    THREAT_INTEL_FEEDS.labels(status="enabled").set(enabled_feeds)
    THREAT_INTEL_FEEDS.labels(status="disabled").set(disabled_feeds)
    for ind_type, count in indicators_by_type.items():
        THREAT_INTEL_INDICATORS.labels(indicator_type=ind_type).set(count)


def update_db_connections(active: int) -> None:
    """Update database connection count."""
    DB_CONNECTIONS_ACTIVE.set(active)
