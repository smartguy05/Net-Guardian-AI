"""Chat context service for intent classification and context building."""

import json
from typing import Any

import structlog
from anthropic import AsyncAnthropic

from app.config import settings
from app.models.chat_intent import (
    ChatContext,
    ChatIntent,
    IntentClassification,
)
from app.services.doc_loader import get_doc_loader

logger = structlog.get_logger()


# Intent-specific system prompts
SYSTEM_PROMPTS: dict[ChatIntent, str] = {
    ChatIntent.APP_HELP: """You are a helpful assistant for NetGuardian AI, a home network security monitoring application. Your role is to help users understand how to use the application's features.

## Your Expertise
- NetGuardian AI user interface and navigation
- Device management and monitoring
- Alert and anomaly review workflows
- Detection rule creation and management
- Log source configuration
- User and access management
- Quarantine and security actions

## Guidelines
- Reference actual UI elements, buttons, and page names from the help content
- Provide step-by-step instructions when explaining how to do something
- Include helpful tips from the documentation
- If unsure about a specific feature, say so and suggest checking the relevant page
- Be friendly and encouraging

## Context
You have access to the application's help documentation below.""",
    ChatIntent.SETUP_CONFIG: """You are a technical configuration specialist for NetGuardian AI, a home network security monitoring system. Your role is to help users configure and set up the application.

## Your Expertise
- Environment variables and configuration options
- Integration setup (AdGuard Home, routers, Authentik SSO)
- LLM configuration (Anthropic Claude, Ollama)
- Database and Redis configuration
- SMTP and notification setup
- Docker/Podman deployment

## Guidelines
- Provide specific environment variable names and example values
- Explain what each setting does and when to change it
- Include security best practices (e.g., using strong SECRET_KEY)
- Reference the configuration documentation
- Warn about common pitfalls (e.g., WSL IP changes, SSL verification)

## Context
You have access to the configuration documentation below.""",
    ChatIntent.TROUBLESHOOTING: """You are a troubleshooting specialist for NetGuardian AI, a home network security monitoring system. Your role is to help users diagnose and fix issues.

## Your Expertise
- Log source collection issues
- Database and Redis connectivity
- Authentication and SSO problems
- Integration failures (AdGuard, routers)
- API errors and rate limiting
- Common configuration mistakes

## Guidelines
- Ask clarifying questions to understand the exact issue
- Provide step-by-step diagnostic instructions
- Suggest checking specific logs or status endpoints
- Reference configuration options that might be relevant
- Consider common causes first before edge cases

## Diagnostic Approach
1. Understand the symptom clearly
2. Identify when it started (recent changes?)
3. Check configuration and connectivity
4. Review relevant logs
5. Suggest specific fixes

## Context
You have access to configuration and help documentation below.""",
    ChatIntent.LOG_ANALYSIS: """You are a network security analyst for NetGuardian AI, a home network security monitoring system. Your role is to analyze security events, alerts, and anomalies to provide actionable assessments for home network administrators.

## Your Expertise
- Network traffic analysis and behavioral baselines
- DNS security (DGA detection, exfiltration, tunneling)
- IoT device security and typical behavior patterns
- LLM-malware indicators (Ollama API abuse, model enumeration)
- Home network threat landscape

## Analysis Guidelines
When analyzing security events:
1. Consider device type and expected behavior (IoT vs PC vs mobile)
2. Evaluate against established behavioral baselines
3. Look for indicators of compromise (IOCs)
4. Assess false positive likelihood based on context
5. Consider time-of-day patterns and user behavior

## Response Format
Always provide structured, actionable analysis:
- Clear threat assessment with confidence level
- Plain-language explanation for non-experts
- Specific recommended actions
- Context about why this matters

## Important Notes
- This is a HOME network, not enterprise - adjust severity accordingly
- Prioritize user privacy - don't over-collect or over-alert
- Consider that some "anomalies" may be legitimate new behavior
- Be helpful and educational, not alarmist

## Log Data Instructions
When log query results are provided in the context:
- Reference specific events by timestamp and details
- Cite exact counts and patterns you observe
- If the query returned fewer events than the total, note you're analyzing a sample
- If no events matched, explain what was searched and suggest broadening the search
- Summarize patterns (e.g., "15 DNS queries to ring.com, 3 to amazonaws.com")
- Highlight anything unusual or noteworthy

## Context
You have access to the current network state below.""",
    ChatIntent.VULNERABILITY_RESEARCH: """You are a security researcher helping users understand vulnerabilities and threats. Your role is to provide accurate, educational information about security vulnerabilities.

## Your Expertise
- CVE analysis and understanding
- Threat actor techniques and tactics
- Malware families and indicators
- Security advisories and patches
- Home network attack vectors

## Guidelines
- Be accurate and cite official sources when possible (NVD, MITRE, vendor advisories)
- Explain the vulnerability in plain language
- Describe potential impact for home networks specifically
- Recommend checking if affected and how to patch/mitigate
- Avoid FUD (Fear, Uncertainty, Doubt) - be factual

## Important Notes
- Always recommend consulting official sources for the latest information
- Explain that vulnerability databases like NVD are the authoritative source
- If you don't have specific details about a CVE, say so
- Focus on defensive measures and detection

## Context
The user is asking about vulnerabilities. Provide educational information.""",
    ChatIntent.GENERAL_CHAT: """You are the AI assistant for NetGuardian AI, a home network security monitoring system. You help users understand their network security status and answer questions about devices, events, and alerts.

## Your Capabilities
- Explain network security concepts in plain language
- Analyze device behavior and traffic patterns
- Interpret alerts and anomalies
- Provide security recommendations
- Answer questions about the network's current state

## Guidelines
- Be conversational and helpful
- Explain technical concepts simply
- Provide specific, actionable advice
- Acknowledge uncertainty when appropriate
- Focus on what matters for home network security
- Guide users toward relevant features when appropriate

## Context
You're having a general conversation with a NetGuardian AI user.""",
}


# Intent classification prompt for Haiku
INTENT_CLASSIFICATION_PROMPT = """You are an intent classifier for NetGuardian AI, a home network security monitoring application. Classify the user's message into exactly ONE of these intents:

1. **app_help** - Questions about how to use the application
   Examples: "How do I quarantine a device?", "Where can I see my alerts?", "How do I create a detection rule?"

2. **setup_config** - Configuration and setup questions
   Examples: "How do I configure Authentik?", "What environment variables do I need?", "How do I set up AdGuard integration?"

3. **troubleshooting** - Something isn't working, error investigation
   Examples: "Why isn't my log source working?", "I'm getting authentication errors", "Events aren't appearing"

4. **log_analysis** - Network security analysis, device behavior, alerts
   Examples: "What is this device doing?", "Show me devices with anomalies", "Analyze this alert", "What's the security status?"

5. **vulnerability_research** - CVE lookups, threat research, vulnerability questions
   Examples: "What is CVE-2024-1234?", "Tell me about Log4Shell", "What is a DGA attack?"

6. **general_chat** - Greetings, thanks, off-topic, or unclear
   Examples: "Hello", "Thanks!", "What's the weather?", "Tell me a joke"

Respond with ONLY a JSON object (no markdown, no explanation):
{"intent": "<intent_name>", "confidence": <0.0-1.0>, "keywords": ["<relevant>", "<keywords>"], "relevant_pages": ["<page_paths>"]}

User message to classify:
"""


class ChatContextService:
    """Service for classifying user intent and building chat context."""

    def __init__(self) -> None:
        self._client: AsyncAnthropic | None = None
        self._doc_loader = get_doc_loader()

    @property
    def client(self) -> AsyncAnthropic:
        """Get or create the Anthropic client."""
        if self._client is None:
            if not settings.anthropic_api_key:
                raise ValueError("Anthropic API key not configured")
            self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        return self._client

    async def classify_intent(self, message: str) -> IntentClassification:
        """Classify the intent of a user message using Haiku.

        Args:
            message: The user's message to classify.

        Returns:
            IntentClassification with the detected intent and metadata.
        """
        # Use quick heuristics for obvious cases first (no API call needed)
        quick_result = self._quick_classify(message)
        if quick_result:
            logger.debug(
                "quick_classification",
                intent=quick_result.intent.value,
                confidence=quick_result.confidence,
            )
            return quick_result

        # Fallback to log_analysis if no API key for LLM classification
        if not settings.anthropic_api_key:
            logger.warning("no_api_key_for_classification")
            return IntentClassification(
                intent=ChatIntent.LOG_ANALYSIS,
                confidence=0.5,
                keywords=[],
                relevant_pages=[],
            )

        try:
            response = await self.client.messages.create(
                model=settings.llm_model_fast,  # Use Haiku for fast classification
                max_tokens=200,
                temperature=0.0,  # Deterministic classification
                messages=[
                    {
                        "role": "user",
                        "content": f"{INTENT_CLASSIFICATION_PROMPT}{message}",
                    }
                ],
            )

            # Parse the response
            response_text = response.content[0].text.strip()  # type: ignore[union-attr]

            # Handle potential markdown code blocks
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]
                response_text = response_text.strip()

            result = json.loads(response_text)

            intent = ChatIntent(result.get("intent", "general_chat"))
            classification = IntentClassification(
                intent=intent,
                confidence=float(result.get("confidence", 0.8)),
                keywords=result.get("keywords", []),
                relevant_pages=result.get("relevant_pages", []),
            )

            logger.info(
                "intent_classified",
                intent=intent.value,
                confidence=classification.confidence,
                keywords=classification.keywords,
            )

            return classification

        except json.JSONDecodeError as e:
            logger.error("intent_classification_json_error", error=str(e))
            return IntentClassification(
                intent=ChatIntent.GENERAL_CHAT,
                confidence=0.5,
                keywords=[],
            )
        except Exception as e:
            logger.error("intent_classification_error", error=str(e))
            # Fallback to log_analysis for network-related keywords
            if any(
                kw in message.lower()
                for kw in ["device", "alert", "anomaly", "network", "traffic", "dns"]
            ):
                return IntentClassification(
                    intent=ChatIntent.LOG_ANALYSIS,
                    confidence=0.6,
                    keywords=[],
                )
            return IntentClassification(
                intent=ChatIntent.GENERAL_CHAT,
                confidence=0.5,
                keywords=[],
            )

    def _quick_classify(self, message: str) -> IntentClassification | None:
        """Quick heuristic classification for obvious cases.

        Returns:
            IntentClassification if a quick match is found, None otherwise.
        """
        msg_lower = message.lower().strip()

        # Greetings and thanks
        greetings = ["hello", "hi", "hey", "thanks", "thank you", "bye", "goodbye"]
        if any(msg_lower.startswith(g) or msg_lower == g for g in greetings):
            return IntentClassification(
                intent=ChatIntent.GENERAL_CHAT,
                confidence=0.95,
                keywords=["greeting"],
            )

        # CVE mentions
        if "cve-" in msg_lower or "cve " in msg_lower:
            return IntentClassification(
                intent=ChatIntent.VULNERABILITY_RESEARCH,
                confidence=0.95,
                keywords=["cve"],
            )

        # Configuration keywords
        config_keywords = [
            "configure",
            "configuration",
            "environment variable",
            "env var",
            ".env",
            "set up",
            "setup",
            "install",
            "deploy",
        ]
        if any(kw in msg_lower for kw in config_keywords):
            # Check if it's about a specific integration
            integrations = ["authentik", "adguard", "router", "smtp", "ollama", "docker"]
            if any(i in msg_lower for i in integrations):
                return IntentClassification(
                    intent=ChatIntent.SETUP_CONFIG,
                    confidence=0.9,
                    keywords=["configuration"],
                )

        # Troubleshooting keywords
        trouble_keywords = [
            "not working",
            "doesn't work",
            "error",
            "failed",
            "failing",
            "broken",
            "issue",
            "problem",
            "can't",
            "cannot",
            "won't",
        ]
        if any(kw in msg_lower for kw in trouble_keywords):
            return IntentClassification(
                intent=ChatIntent.TROUBLESHOOTING,
                confidence=0.85,
                keywords=["troubleshooting"],
            )

        # App help keywords
        help_keywords = [
            "how do i",
            "how to",
            "where can i",
            "where is",
            "what button",
            "which page",
            "how can i",
        ]
        if any(kw in msg_lower for kw in help_keywords):
            # Check if it's about using the app vs configuration
            app_terms = [
                "quarantine",
                "alert",
                "device",
                "rule",
                "anomaly",
                "event",
                "export",
                "filter",
            ]
            if any(term in msg_lower for term in app_terms):
                return IntentClassification(
                    intent=ChatIntent.APP_HELP,
                    confidence=0.85,
                    keywords=["app_usage"],
                )

        return None

    def build_context(
        self,
        classification: IntentClassification,
        network_context: dict[str, Any] | None = None,
        message: str = "",
        log_query_result: Any | None = None,
    ) -> ChatContext:
        """Build the full context for a chat response.

        Args:
            classification: The classified intent.
            network_context: Network data (devices, alerts, etc.) if available.
            message: The user's original message for keyword extraction.
            log_query_result: LogQueryResult when log data was fetched.

        Returns:
            ChatContext with system prompt and relevant documentation.
        """
        intent = classification.intent
        system_prompt = SYSTEM_PROMPTS.get(intent, SYSTEM_PROMPTS[ChatIntent.GENERAL_CHAT])

        context_text = ""

        if intent == ChatIntent.APP_HELP:
            # Include relevant help pages
            pages = classification.relevant_pages or self._infer_pages_from_message(message)
            if pages:
                context_text = self._doc_loader.get_help_for_pages(pages)
            else:
                # Include all help content for general app questions
                context_text = self._doc_loader.get_all_help_content()

        elif intent == ChatIntent.SETUP_CONFIG:
            # Include configuration documentation
            context_text = self._doc_loader.get_configuration_doc()
            # Also include deployment guide if relevant
            if any(kw in message.lower() for kw in ["docker", "deploy", "install", "production"]):
                context_text += "\n\n" + self._doc_loader.get_deployment_guide()

        elif intent == ChatIntent.TROUBLESHOOTING:
            # Extract issue keywords and get relevant docs
            keywords = classification.keywords or message.lower().split()
            context_text = self._doc_loader.get_troubleshooting_context(keywords)
            # Always include some config context for troubleshooting
            if not context_text:
                context_text = self._doc_loader.get_configuration_doc()

        elif intent == ChatIntent.LOG_ANALYSIS:
            # Network context is provided separately
            if network_context:
                context_text = self._format_network_context(network_context)
            if log_query_result:
                from app.services.log_query_service import LogQueryService

                context_text += "\n\n" + LogQueryService.format_events_for_context(log_query_result)

        elif intent == ChatIntent.VULNERABILITY_RESEARCH:
            # Minimal context - the LLM should use its training knowledge
            context_text = """Note: For the most accurate and up-to-date vulnerability information, users should check:
- NVD (National Vulnerability Database): nvd.nist.gov
- MITRE CVE: cve.mitre.org
- Vendor security advisories

Provide educational information based on your training, but recommend official sources."""

        # General chat needs minimal context
        # context_text remains empty for GENERAL_CHAT

        return ChatContext(
            system_prompt=system_prompt,
            context_text=context_text,
            network_data=network_context if classification.needs_network_context else None,
            intent=intent,
            classification=classification,
            log_query_result=log_query_result,
        )

    def _infer_pages_from_message(self, message: str) -> list[str]:
        """Infer relevant help pages from the message content."""
        msg_lower = message.lower()
        pages: list[str] = []

        page_keywords = {
            "/dashboard/devices": ["device", "mac", "ip address", "hostname", "quarantine"],
            "/dashboard/alerts": ["alert", "acknowledge", "resolve", "false positive"],
            "/dashboard/anomalies": ["anomaly", "anomalies", "baseline", "behavior"],
            "/dashboard/rules": ["rule", "detection", "condition", "trigger"],
            "/dashboard/events": ["event", "log", "dns", "traffic"],
            "/dashboard/sources": ["source", "log source", "collection", "parser"],
            "/dashboard/users": ["user", "account", "permission", "role", "sso"],
            "/dashboard/settings": ["setting", "notification", "2fa", "retention"],
            "/dashboard/quarantine": ["quarantine", "block", "isolate"],
            "/dashboard/threat-intel": ["threat", "feed", "indicator", "ioc"],
            "/dashboard/topology": ["topology", "network map", "visualization"],
            "/dashboard/patterns": ["pattern", "semantic"],
            "/dashboard/chat": ["chat", "ai", "assistant"],
        }

        for page, keywords in page_keywords.items():
            if any(kw in msg_lower for kw in keywords):
                pages.append(page)

        return pages[:3]  # Limit to top 3 relevant pages

    def _format_network_context(self, context: dict[str, Any]) -> str:
        """Format network context for inclusion in the prompt."""
        parts = ["## Current Network Context\n"]

        if "stats" in context:
            stats = context["stats"]
            parts.append("### Network Overview")
            parts.append(f"- Active devices: {stats.get('active_devices', 'Unknown')}")
            parts.append(f"- Total events (24h): {stats.get('total_events_24h', 'Unknown')}")
            parts.append(f"- Active alerts: {stats.get('active_alerts', 'Unknown')}")
            parts.append(f"- DNS queries (24h): {stats.get('dns_queries_24h', 'Unknown')}")
            parts.append(f"- Blocked queries (24h): {stats.get('blocked_queries_24h', 'Unknown')}")
            parts.append("")

        if "devices" in context:
            parts.append("### Devices")
            for device in context["devices"][:20]:
                name = device.get("hostname") or device.get("mac_address", "Unknown")
                device_type = device.get("device_type", "unknown")
                status = device.get("status", "unknown")
                parts.append(f"- {name} ({device_type}) - {status}")
            parts.append("")

        if "alerts" in context:
            parts.append("### Recent Alerts")
            for alert in context["alerts"][:10]:
                parts.append(
                    f"- [{alert.get('severity', 'unknown')}] {alert.get('title', 'Unknown')}"
                )
            parts.append("")

        if "anomalies" in context:
            parts.append("### Recent Anomalies")
            for anomaly in context["anomalies"][:10]:
                parts.append(
                    f"- [{anomaly.get('severity', 'unknown')}] {anomaly.get('description', 'Unknown')}"
                )
            parts.append("")

        return "\n".join(parts)


# Global service instance
_chat_context_service: ChatContextService | None = None


def get_chat_context_service() -> ChatContextService:
    """Get the global ChatContextService instance."""
    global _chat_context_service
    if _chat_context_service is None:
        _chat_context_service = ChatContextService()
    return _chat_context_service
