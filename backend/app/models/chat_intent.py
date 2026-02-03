"""Chat intent classification models for AI chat feature."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ChatIntent(str, Enum):
    """Types of user intents in the AI chat."""

    APP_HELP = "app_help"  # Questions about how to use the application
    SETUP_CONFIG = "setup_config"  # Configuration and setup questions
    TROUBLESHOOTING = "troubleshooting"  # Something isn't working
    LOG_ANALYSIS = "log_analysis"  # Network/security analysis
    VULNERABILITY_RESEARCH = "vulnerability_research"  # CVE lookups, threat research
    GENERAL_CHAT = "general_chat"  # Greetings, off-topic


# Intent properties - which intents need network context
INTENTS_NEEDING_NETWORK_CONTEXT = {
    ChatIntent.LOG_ANALYSIS,
    ChatIntent.TROUBLESHOOTING,
}


@dataclass
class IntentClassification:
    """Result of classifying a user's message intent."""

    intent: ChatIntent
    confidence: float  # 0.0 to 1.0
    keywords: list[str] = field(default_factory=list)
    relevant_pages: list[str] = field(default_factory=list)
    flags: dict[str, bool] = field(default_factory=dict)

    @property
    def needs_network_context(self) -> bool:
        """Whether this intent requires network data for context."""
        return self.intent in INTENTS_NEEDING_NETWORK_CONTEXT


@dataclass
class ChatContext:
    """Context to inject into the LLM chat."""

    system_prompt: str
    context_text: str = ""
    network_data: dict[str, Any] | None = None
    intent: ChatIntent | None = None
    classification: IntentClassification | None = None
