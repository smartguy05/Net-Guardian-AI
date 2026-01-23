"""SQLAlchemy models for NetGuardian AI."""

from app.models.base import Base, TimestampMixin
from app.models.user import User
from app.models.device import Device, DeviceType, DeviceStatus
from app.models.log_source import LogSource, SourceType, ParserType
from app.models.raw_event import RawEvent, EventType, EventSeverity
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.detection_rule import DetectionRule
from app.models.device_baseline import DeviceBaseline, BaselineType, BaselineStatus
from app.models.anomaly import AnomalyDetection, AnomalyType, AnomalyStatus
from app.models.audit_log import AuditLog, AuditAction
from app.models.playbook import (
    Playbook,
    PlaybookExecution,
    PlaybookTriggerType,
    PlaybookActionType,
    PlaybookStatus,
    ExecutionStatus,
)
from app.models.semantic_analysis import (
    LogPattern,
    SemanticAnalysisConfig,
    IrregularLog,
    SemanticAnalysisRun,
    SuggestedRule,
    SuggestedRuleHistory,
    LLMProvider,
    AnalysisRunStatus,
    SuggestedRuleStatus,
    SuggestedRuleType,
)

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
