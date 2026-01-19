"""Main API router aggregating all v1 endpoints."""

from fastapi import APIRouter

from app.api.v1 import (
    auth,
    users,
    devices,
    events,
    stats,
    alerts,
    sources,
    logs,
    baselines,
    anomalies,
    chat,
    audit,
    integrations,
    playbooks,
    ollama,
)

api_router = APIRouter()

# Authentication endpoints
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# User management endpoints
api_router.include_router(users.router, prefix="/users", tags=["Users"])

# Device management endpoints
api_router.include_router(devices.router, prefix="/devices", tags=["Devices"])

# Event query endpoints
api_router.include_router(events.router, prefix="/events", tags=["Events"])

# Statistics endpoints
api_router.include_router(stats.router, prefix="/stats", tags=["Statistics"])

# Alert management endpoints
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])

# Log source management endpoints
api_router.include_router(sources.router, prefix="/sources", tags=["Log Sources"])

# Log ingestion endpoints
api_router.include_router(logs.router, prefix="/logs", tags=["Log Ingestion"])

# Device baseline endpoints
api_router.include_router(baselines.router, prefix="/baselines", tags=["Baselines"])

# Anomaly detection endpoints
api_router.include_router(anomalies.router, prefix="/anomalies", tags=["Anomalies"])

# LLM chat and query endpoints
api_router.include_router(chat.router, prefix="/chat", tags=["AI Chat"])

# Audit log endpoints
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Logs"])

# Integration management endpoints
api_router.include_router(integrations.router, prefix="/integrations", tags=["Integrations"])

# Playbook management endpoints
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["Playbooks"])

# Ollama LLM monitoring endpoints
api_router.include_router(ollama.router, prefix="/ollama", tags=["Ollama Monitoring"])
