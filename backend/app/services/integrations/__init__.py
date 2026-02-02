"""Integration services for external systems."""

from app.services.integrations.adguard import AdGuardHomeService, get_adguard_service
from app.services.integrations.base import (
    ActionType,
    IntegrationResult,
    IntegrationService,
    IntegrationType,
)
from app.services.integrations.c4000xg import C4000XGService, get_c4000xg_service
from app.services.integrations.pfsense import PfSenseService, get_pfsense_service
from app.services.integrations.unifi import UniFiService, get_unifi_service

__all__ = [
    "ActionType",
    "IntegrationResult",
    "IntegrationService",
    "IntegrationType",
    "AdGuardHomeService",
    "get_adguard_service",
    "C4000XGService",
    "get_c4000xg_service",
    "UniFiService",
    "get_unifi_service",
    "PfSenseService",
    "get_pfsense_service",
]
