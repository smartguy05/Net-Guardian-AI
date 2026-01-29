"""Tests for the LLM service."""

from unittest.mock import patch

import pytest

from app.services.llm_service import (
    SYSTEM_PROMPT_CHAT_ASSISTANT,
    SYSTEM_PROMPT_SECURITY_ANALYST,
    LLMModel,
    LLMService,
    get_llm_service,
)


class TestLLMServiceInit:
    """Tests for LLM service initialization."""

    def test_service_disabled_when_no_api_key(self):
        """Service should be disabled when API key is not set."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = ""

            service = LLMService()
            assert not service.is_enabled

    def test_service_disabled_when_llm_disabled(self):
        """Service should be disabled when LLM is disabled in settings."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = False
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()
            assert not service.is_enabled

    def test_service_enabled_when_configured(self):
        """Service should be enabled when API key is set and LLM is enabled."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()
            assert service.is_enabled


class TestLLMModelSelection:
    """Tests for model selection."""

    def test_get_model_fast(self):
        """Should return fast model for FAST type."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"
            mock_settings.llm_model_fast = "claude-haiku"
            mock_settings.llm_model_default = "claude-sonnet"
            mock_settings.llm_model_deep = "claude-opus"

            service = LLMService()
            assert service._get_model(LLMModel.FAST) == "claude-haiku"

    def test_get_model_default(self):
        """Should return default model for DEFAULT type."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"
            mock_settings.llm_model_fast = "claude-haiku"
            mock_settings.llm_model_default = "claude-sonnet"
            mock_settings.llm_model_deep = "claude-opus"

            service = LLMService()
            assert service._get_model(LLMModel.DEFAULT) == "claude-sonnet"

    def test_get_model_deep(self):
        """Should return deep model for DEEP type."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"
            mock_settings.llm_model_fast = "claude-haiku"
            mock_settings.llm_model_default = "claude-sonnet"
            mock_settings.llm_model_deep = "claude-opus"

            service = LLMService()
            assert service._get_model(LLMModel.DEEP) == "claude-opus"


class TestPromptBuilding:
    """Tests for prompt building."""

    def test_build_alert_analysis_prompt_basic(self):
        """Should build basic alert analysis prompt."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()

            alert_data = {
                "id": "test-alert-1",
                "title": "Suspicious DNS Query",
                "description": "Device queried suspicious domain",
                "severity": "high",
                "rule_id": "dns_suspicious",
                "timestamp": "2025-01-19T10:00:00Z",
            }

            prompt = service._build_alert_analysis_prompt(
                alert_data=alert_data,
                device_data=None,
                baseline_data=None,
                recent_events=None,
            )

            assert "test-alert-1" in prompt
            assert "Suspicious DNS Query" in prompt
            assert "dns_suspicious" in prompt
            assert "Analysis Request" in prompt
            assert "json" in prompt

    def test_build_alert_analysis_prompt_with_device(self):
        """Should include device context in prompt."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()

            alert_data = {
                "id": "test-alert-1",
                "title": "Test Alert",
                "description": "Test description",
                "severity": "medium",
                "rule_id": "test",
                "timestamp": "2025-01-19T10:00:00Z",
            }

            device_data = {
                "hostname": "my-laptop",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "device_type": "pc",
                "manufacturer": "Dell",
                "status": "active",
                "ip_addresses": ["192.168.1.100"],
                "profile_tags": ["trusted"],
            }

            prompt = service._build_alert_analysis_prompt(
                alert_data=alert_data,
                device_data=device_data,
                baseline_data=None,
                recent_events=None,
            )

            assert "my-laptop" in prompt
            assert "Dell" in prompt
            assert "192.168.1.100" in prompt
            assert "trusted" in prompt

    def test_build_alert_analysis_prompt_with_baseline(self):
        """Should include baseline context in prompt."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()

            alert_data = {
                "id": "test-alert-1",
                "title": "Test Alert",
                "description": "Test",
                "severity": "low",
                "rule_id": "test",
                "timestamp": "2025-01-19T10:00:00Z",
            }

            baseline_data = {
                "dns": {
                    "status": "ready",
                    "sample_count": 1000,
                    "total_queries_daily_avg": 500,
                }
            }

            prompt = service._build_alert_analysis_prompt(
                alert_data=alert_data,
                device_data=None,
                baseline_data=baseline_data,
                recent_events=None,
            )

            assert "Baseline" in prompt
            assert "Dns" in prompt  # Title cased

    def test_build_query_prompt_basic(self):
        """Should build basic query prompt."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()

            context = {
                "stats": {
                    "active_devices": 10,
                    "total_events_24h": 5000,
                    "active_alerts": 2,
                }
            }

            prompt = service._build_query_prompt(
                query="What devices are most active?",
                context=context,
            )

            assert "What devices are most active?" in prompt
            assert "Network Overview" in prompt
            assert "Active devices: 10" in prompt


class TestResponseParsing:
    """Tests for response parsing."""

    def test_parse_analysis_response_json_block(self):
        """Should parse JSON from markdown code block."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()

            response = """Here is my analysis:

```json
{
    "confidence": 85,
    "summary": "This appears to be a benign query",
    "risk_level": "low"
}
```

Additional notes here."""

            result = service._parse_analysis_response(response)

            assert result["confidence"] == 85
            assert result["summary"] == "This appears to be a benign query"
            assert result["risk_level"] == "low"

    def test_parse_analysis_response_raw_json(self):
        """Should parse raw JSON without code block."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()

            response = '{"confidence": 75, "summary": "Test", "risk_level": "medium"}'

            result = service._parse_analysis_response(response)

            assert result["confidence"] == 75
            assert result["risk_level"] == "medium"

    def test_parse_analysis_response_invalid_json(self):
        """Should fallback to unstructured response for invalid JSON."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()

            response = "This is a plain text analysis without JSON formatting."

            result = service._parse_analysis_response(response)

            assert result["confidence"] == 50  # Default confidence
            assert result["structured"] is False
            assert "analysis" in result

    def test_parse_incident_summary_json_block(self):
        """Should parse incident summary from JSON block."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service = LLMService()

            response = """
```json
{
    "title": "DNS Exfiltration Attempt",
    "executive_summary": "Multiple suspicious DNS queries detected",
    "severity": "high",
    "confidence": 90
}
```
"""

            result = service._parse_incident_summary(response)

            assert result["title"] == "DNS Exfiltration Attempt"
            assert result["severity"] == "high"
            assert result["confidence"] == 90


class TestAnalyzeAlertDisabled:
    """Tests for analyze_alert when service is disabled."""

    @pytest.mark.asyncio
    async def test_analyze_alert_returns_error_when_disabled(self):
        """Should return error response when LLM is disabled."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = False
            mock_settings.anthropic_api_key = ""

            service = LLMService()

            result = await service.analyze_alert(
                alert_data={"id": "test", "title": "Test"},
            )

            assert "error" in result
            assert result["confidence"] == 0
            assert "unavailable" in result["analysis"].lower()


class TestQueryNetworkDisabled:
    """Tests for query_network when service is disabled."""

    @pytest.mark.asyncio
    async def test_query_network_returns_error_when_disabled(self):
        """Should return error message when LLM is disabled."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = False
            mock_settings.anthropic_api_key = ""

            service = LLMService()

            result = await service.query_network(
                query="What is happening?",
                context={},
            )

            assert "not enabled" in result.lower()


class TestSummarizeIncidentDisabled:
    """Tests for summarize_incident when service is disabled."""

    @pytest.mark.asyncio
    async def test_summarize_incident_returns_error_when_disabled(self):
        """Should return error response when LLM is disabled."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = False
            mock_settings.anthropic_api_key = ""

            service = LLMService()

            result = await service.summarize_incident(
                alerts=[],
                anomalies=[],
                events=[],
            )

            assert "error" in result


class TestStreamChatDisabled:
    """Tests for stream_chat when service is disabled."""

    @pytest.mark.asyncio
    async def test_stream_chat_yields_error_when_disabled(self):
        """Should yield error message when LLM is disabled."""
        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = False
            mock_settings.anthropic_api_key = ""

            service = LLMService()

            chunks = []
            async for chunk in service.stream_chat(
                messages=[{"role": "user", "content": "Hello"}],
                context={},
            ):
                chunks.append(chunk)

            assert len(chunks) == 1
            assert "not enabled" in chunks[0].lower()


class TestGlobalServiceInstance:
    """Tests for global service instance management."""

    def test_get_llm_service_returns_same_instance(self):
        """Should return the same instance on repeated calls."""
        # Reset the global instance
        import app.services.llm_service as llm_module

        llm_module._llm_service = None

        with patch("app.services.llm_service.settings") as mock_settings:
            mock_settings.llm_enabled = True
            mock_settings.anthropic_api_key = "sk-test"

            service1 = get_llm_service()
            service2 = get_llm_service()

            assert service1 is service2


class TestSystemPrompts:
    """Tests for system prompts."""

    def test_security_analyst_prompt_exists(self):
        """Security analyst system prompt should exist and contain key content."""
        assert SYSTEM_PROMPT_SECURITY_ANALYST
        assert "network security analyst" in SYSTEM_PROMPT_SECURITY_ANALYST.lower()
        assert "home network" in SYSTEM_PROMPT_SECURITY_ANALYST.lower()

    def test_chat_assistant_prompt_exists(self):
        """Chat assistant system prompt should exist and contain key content."""
        assert SYSTEM_PROMPT_CHAT_ASSISTANT
        assert "assistant" in SYSTEM_PROMPT_CHAT_ASSISTANT.lower()
        assert "network" in SYSTEM_PROMPT_CHAT_ASSISTANT.lower()


class TestLLMModelEnum:
    """Tests for LLM model enum."""

    def test_model_values(self):
        """Should have expected model type values."""
        assert LLMModel.FAST.value == "fast"
        assert LLMModel.DEFAULT.value == "default"
        assert LLMModel.DEEP.value == "deep"
