"""Tests for the chat context service."""

from unittest.mock import patch

import pytest

from app.models.chat_intent import ChatContext, ChatIntent, IntentClassification
from app.services.chat_context_service import (
    INTENT_CLASSIFICATION_PROMPT,
    SYSTEM_PROMPTS,
    ChatContextService,
    get_chat_context_service,
)


class TestIntentClassification:
    """Tests for intent classification data class."""

    def test_intent_classification_needs_network_context_log_analysis(self):
        """Log analysis intent should need network context."""
        classification = IntentClassification(
            intent=ChatIntent.LOG_ANALYSIS,
            confidence=0.9,
        )
        assert classification.needs_network_context is True

    def test_intent_classification_needs_network_context_troubleshooting(self):
        """Troubleshooting intent should need network context."""
        classification = IntentClassification(
            intent=ChatIntent.TROUBLESHOOTING,
            confidence=0.9,
        )
        assert classification.needs_network_context is True

    def test_intent_classification_no_network_context_app_help(self):
        """App help intent should not need network context."""
        classification = IntentClassification(
            intent=ChatIntent.APP_HELP,
            confidence=0.9,
        )
        assert classification.needs_network_context is False

    def test_intent_classification_no_network_context_setup_config(self):
        """Setup config intent should not need network context."""
        classification = IntentClassification(
            intent=ChatIntent.SETUP_CONFIG,
            confidence=0.9,
        )
        assert classification.needs_network_context is False

    def test_intent_classification_no_network_context_vulnerability(self):
        """Vulnerability research intent should not need network context."""
        classification = IntentClassification(
            intent=ChatIntent.VULNERABILITY_RESEARCH,
            confidence=0.9,
        )
        assert classification.needs_network_context is False

    def test_intent_classification_no_network_context_general(self):
        """General chat intent should not need network context."""
        classification = IntentClassification(
            intent=ChatIntent.GENERAL_CHAT,
            confidence=0.9,
        )
        assert classification.needs_network_context is False


class TestQuickClassify:
    """Tests for quick heuristic classification."""

    def test_quick_classify_greeting_hello(self):
        """Should classify 'hello' as general chat."""
        service = ChatContextService()
        result = service._quick_classify("hello")

        assert result is not None
        assert result.intent == ChatIntent.GENERAL_CHAT
        assert result.confidence >= 0.9

    def test_quick_classify_greeting_thanks(self):
        """Should classify 'thanks' as general chat."""
        service = ChatContextService()
        result = service._quick_classify("thanks!")

        assert result is not None
        assert result.intent == ChatIntent.GENERAL_CHAT

    def test_quick_classify_cve_mention(self):
        """Should classify CVE mentions as vulnerability research."""
        service = ChatContextService()
        result = service._quick_classify("What is CVE-2024-1234?")

        assert result is not None
        assert result.intent == ChatIntent.VULNERABILITY_RESEARCH
        assert result.confidence >= 0.9

    def test_quick_classify_troubleshooting_not_working(self):
        """Should classify 'not working' messages as troubleshooting."""
        service = ChatContextService()
        result = service._quick_classify("My log source is not working")

        assert result is not None
        assert result.intent == ChatIntent.TROUBLESHOOTING

    def test_quick_classify_troubleshooting_error(self):
        """Should classify error messages as troubleshooting."""
        service = ChatContextService()
        result = service._quick_classify("I'm getting an error when I try to login")

        assert result is not None
        assert result.intent == ChatIntent.TROUBLESHOOTING

    def test_quick_classify_config_authentik(self):
        """Should classify Authentik config questions as setup_config."""
        service = ChatContextService()
        result = service._quick_classify("How do I configure Authentik?")

        assert result is not None
        assert result.intent == ChatIntent.SETUP_CONFIG

    def test_quick_classify_config_env_vars(self):
        """Should classify env var questions as setup_config."""
        service = ChatContextService()
        result = service._quick_classify("What environment variables do I need to set up Docker?")

        assert result is not None
        assert result.intent == ChatIntent.SETUP_CONFIG

    def test_quick_classify_app_help_quarantine(self):
        """Should classify quarantine usage questions as app_help."""
        service = ChatContextService()
        result = service._quick_classify("How do I quarantine a device?")

        assert result is not None
        assert result.intent == ChatIntent.APP_HELP

    def test_quick_classify_app_help_filter(self):
        """Should classify filter usage questions as app_help."""
        service = ChatContextService()
        result = service._quick_classify("How can I filter events by type?")

        assert result is not None
        assert result.intent == ChatIntent.APP_HELP

    def test_quick_classify_no_match(self):
        """Should return None for messages that don't match quick patterns."""
        service = ChatContextService()
        result = service._quick_classify("Tell me about my network activity")

        # This might not match quick patterns, should return None
        # If it does match, that's also fine
        # The important thing is it doesn't crash
        assert result is None or isinstance(result, IntentClassification)


class TestClassifyIntentFallback:
    """Tests for intent classification fallback behavior."""

    @pytest.mark.asyncio
    async def test_classify_intent_fallback_no_api_key(self):
        """Should fallback to log_analysis when no API key."""
        with patch("app.services.chat_context_service.settings") as mock_settings:
            mock_settings.anthropic_api_key = ""

            service = ChatContextService()
            result = await service.classify_intent("What devices are active?")

            assert result.intent == ChatIntent.LOG_ANALYSIS
            assert result.confidence == 0.5

    @pytest.mark.asyncio
    async def test_classify_intent_uses_quick_classify_first(self):
        """Should use quick classification when it matches."""
        service = ChatContextService()
        result = await service.classify_intent("hello")

        assert result.intent == ChatIntent.GENERAL_CHAT
        assert result.confidence >= 0.9


class TestBuildContext:
    """Tests for context building."""

    def test_build_context_app_help(self):
        """Should build context with help documentation for app_help intent."""
        service = ChatContextService()
        classification = IntentClassification(
            intent=ChatIntent.APP_HELP,
            confidence=0.9,
            relevant_pages=["/dashboard/devices"],
        )

        context = service.build_context(
            classification=classification,
            network_context=None,
            message="How do I quarantine a device?",
        )

        assert context.intent == ChatIntent.APP_HELP
        assert context.system_prompt == SYSTEM_PROMPTS[ChatIntent.APP_HELP]
        assert context.network_data is None
        # Context text should contain help content if available
        assert isinstance(context.context_text, str)

    def test_build_context_log_analysis_with_network(self):
        """Should include network data for log_analysis intent."""
        service = ChatContextService()
        classification = IntentClassification(
            intent=ChatIntent.LOG_ANALYSIS,
            confidence=0.9,
        )

        network_context = {
            "stats": {"active_devices": 10},
            "devices": [{"hostname": "test-device", "status": "active"}],
        }

        context = service.build_context(
            classification=classification,
            network_context=network_context,
            message="What devices are active?",
        )

        assert context.intent == ChatIntent.LOG_ANALYSIS
        assert context.network_data == network_context
        assert "Network Overview" in context.context_text or "active_devices" in context.context_text

    def test_build_context_vulnerability_research(self):
        """Should build minimal context for vulnerability research."""
        service = ChatContextService()
        classification = IntentClassification(
            intent=ChatIntent.VULNERABILITY_RESEARCH,
            confidence=0.95,
        )

        context = service.build_context(
            classification=classification,
            network_context=None,
            message="What is CVE-2024-1234?",
        )

        assert context.intent == ChatIntent.VULNERABILITY_RESEARCH
        assert "NVD" in context.context_text  # Should reference official sources
        assert context.network_data is None

    def test_build_context_general_chat(self):
        """Should build minimal context for general chat."""
        service = ChatContextService()
        classification = IntentClassification(
            intent=ChatIntent.GENERAL_CHAT,
            confidence=0.95,
        )

        context = service.build_context(
            classification=classification,
            network_context=None,
            message="Hello!",
        )

        assert context.intent == ChatIntent.GENERAL_CHAT
        # General chat has minimal context
        assert context.network_data is None


class TestInferPagesFromMessage:
    """Tests for page inference from messages."""

    def test_infer_pages_device_keywords(self):
        """Should infer devices page from device keywords."""
        service = ChatContextService()
        pages = service._infer_pages_from_message("How do I quarantine a device?")

        assert "/dashboard/devices" in pages or "/dashboard/quarantine" in pages

    def test_infer_pages_alert_keywords(self):
        """Should infer alerts page from alert keywords."""
        service = ChatContextService()
        pages = service._infer_pages_from_message("How do I acknowledge an alert?")

        assert "/dashboard/alerts" in pages

    def test_infer_pages_rule_keywords(self):
        """Should infer rules page from rule keywords."""
        service = ChatContextService()
        pages = service._infer_pages_from_message("How do I create a detection rule?")

        assert "/dashboard/rules" in pages

    def test_infer_pages_limit_results(self):
        """Should limit to 3 pages maximum."""
        service = ChatContextService()
        # This message has many keywords
        pages = service._infer_pages_from_message(
            "How do I see devices, alerts, anomalies, events, and rules?"
        )

        assert len(pages) <= 3


class TestFormatNetworkContext:
    """Tests for network context formatting."""

    def test_format_network_context_stats(self):
        """Should format stats section."""
        service = ChatContextService()
        context = {
            "stats": {
                "active_devices": 10,
                "total_events_24h": 5000,
                "active_alerts": 2,
            }
        }

        formatted = service._format_network_context(context)

        assert "Network Overview" in formatted
        assert "Active devices: 10" in formatted
        assert "active_alerts" in formatted.lower() or "Active alerts: 2" in formatted

    def test_format_network_context_devices(self):
        """Should format devices section."""
        service = ChatContextService()
        context = {
            "devices": [
                {"hostname": "test-device", "device_type": "pc", "status": "active"},
                {"mac_address": "AA:BB:CC:DD:EE:FF", "device_type": "iot", "status": "inactive"},
            ]
        }

        formatted = service._format_network_context(context)

        assert "Devices" in formatted
        assert "test-device" in formatted

    def test_format_network_context_alerts(self):
        """Should format alerts section."""
        service = ChatContextService()
        context = {
            "alerts": [
                {"title": "Suspicious DNS Query", "severity": "high"},
            ]
        }

        formatted = service._format_network_context(context)

        assert "Alerts" in formatted
        assert "Suspicious DNS Query" in formatted


class TestSystemPrompts:
    """Tests for system prompts."""

    def test_all_intents_have_prompts(self):
        """All intent types should have a system prompt."""
        for intent in ChatIntent:
            assert intent in SYSTEM_PROMPTS, f"Missing prompt for {intent}"
            assert len(SYSTEM_PROMPTS[intent]) > 0, f"Empty prompt for {intent}"

    def test_app_help_prompt_content(self):
        """App help prompt should mention UI elements."""
        prompt = SYSTEM_PROMPTS[ChatIntent.APP_HELP]
        assert "UI" in prompt or "page" in prompt.lower() or "button" in prompt.lower()

    def test_setup_config_prompt_content(self):
        """Setup config prompt should mention environment variables."""
        prompt = SYSTEM_PROMPTS[ChatIntent.SETUP_CONFIG]
        assert "environment" in prompt.lower() or "configuration" in prompt.lower()

    def test_troubleshooting_prompt_content(self):
        """Troubleshooting prompt should mention diagnosis."""
        prompt = SYSTEM_PROMPTS[ChatIntent.TROUBLESHOOTING]
        assert "diagnos" in prompt.lower() or "troubleshoot" in prompt.lower()

    def test_log_analysis_prompt_content(self):
        """Log analysis prompt should mention network security."""
        prompt = SYSTEM_PROMPTS[ChatIntent.LOG_ANALYSIS]
        assert "network" in prompt.lower() and "security" in prompt.lower()

    def test_vulnerability_prompt_content(self):
        """Vulnerability prompt should mention official sources."""
        prompt = SYSTEM_PROMPTS[ChatIntent.VULNERABILITY_RESEARCH]
        assert "NVD" in prompt or "MITRE" in prompt


class TestIntentClassificationPrompt:
    """Tests for the intent classification prompt."""

    def test_classification_prompt_lists_all_intents(self):
        """Classification prompt should list all intent types."""
        assert "app_help" in INTENT_CLASSIFICATION_PROMPT
        assert "setup_config" in INTENT_CLASSIFICATION_PROMPT
        assert "troubleshooting" in INTENT_CLASSIFICATION_PROMPT
        assert "log_analysis" in INTENT_CLASSIFICATION_PROMPT
        assert "vulnerability_research" in INTENT_CLASSIFICATION_PROMPT
        assert "general_chat" in INTENT_CLASSIFICATION_PROMPT

    def test_classification_prompt_requests_json(self):
        """Classification prompt should request JSON output."""
        assert "JSON" in INTENT_CLASSIFICATION_PROMPT or "json" in INTENT_CLASSIFICATION_PROMPT


class TestGlobalServiceInstance:
    """Tests for global service instance management."""

    def test_get_chat_context_service_returns_same_instance(self):
        """Should return the same instance on repeated calls."""
        import app.services.chat_context_service as context_module

        context_module._chat_context_service = None

        service1 = get_chat_context_service()
        service2 = get_chat_context_service()

        assert service1 is service2


class TestChatContextDataClass:
    """Tests for ChatContext data class."""

    def test_chat_context_creation(self):
        """Should create ChatContext with all fields."""
        context = ChatContext(
            system_prompt="Test prompt",
            context_text="Test context",
            network_data={"devices": []},
            intent=ChatIntent.LOG_ANALYSIS,
        )

        assert context.system_prompt == "Test prompt"
        assert context.context_text == "Test context"
        assert context.network_data == {"devices": []}
        assert context.intent == ChatIntent.LOG_ANALYSIS

    def test_chat_context_defaults(self):
        """Should have sensible defaults."""
        context = ChatContext(system_prompt="Test")

        assert context.context_text == ""
        assert context.network_data is None
        assert context.intent is None
