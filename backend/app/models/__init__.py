"""SQLAlchemy models for NetGuardian AI."""

from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.anomaly import AnomalyDetection, AnomalyStatus, AnomalyType
from app.models.audit_log import AuditAction, AuditLog
from app.models.base import Base, TimestampMixin
from app.models.detection_rule import DetectionRule
from app.models.device import Device, DeviceStatus, DeviceType
from app.models.device_baseline import BaselineStatus, BaselineType, DeviceBaseline
from app.models.log_source import LogSource, ParserType, SourceType
from app.models.playbook import (
    ExecutionStatus,
    Playbook,
    PlaybookActionType,
    PlaybookExecution,
    PlaybookStatus,
    PlaybookTriggerType,
)
from app.models.raw_event import EventSeverity, EventType, RawEvent
from app.models.semantic_analysis import (
    AnalysisRunStatus,
    IrregularLog,
    LLMProvider,
    LogPattern,
    SemanticAnalysisConfig,
    SemanticAnalysisRun,
    SuggestedRule,
    SuggestedRuleHistory,
    SuggestedRuleStatus,
    SuggestedRuleType,
)
from app.models.user import User

__all__ = [
    "Base",
    "TimestampMixin",
    "User",
    "Device",
    "DeviceType",
    "DeviceStatus",
    "LogSource",
    "SourceType",
    "ParserType",
    "RawEvent",
    "EventType",
    "EventSeverity",
    "Alert",
    "AlertSeverity",
    "AlertStatus",
    "DetectionRule",
    "DeviceBaseline",
    "BaselineType",
    "BaselineStatus",
    "AnomalyDetection",
    "AnomalyType",
    "AnomalyStatus",
    "AuditLog",
    "AuditAction",
    "Playbook",
    "PlaybookExecution",
    "PlaybookTriggerType",
    "PlaybookActionType",
    "PlaybookStatus",
    "ExecutionStatus",
    # Semantic Analysis
    "LogPattern",
    "SemanticAnalysisConfig",
    "IrregularLog",
    "SemanticAnalysisRun",
    "SuggestedRule",
    "SuggestedRuleHistory",
    "LLMProvider",
    "AnalysisRunStatus",
    "SuggestedRuleStatus",
    "SuggestedRuleType",
]
