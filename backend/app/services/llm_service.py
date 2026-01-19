"""LLM service for Claude API integration with prompt caching."""

import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, AsyncGenerator
from uuid import UUID

import structlog
from anthropic import AsyncAnthropic, APIError

from app.config import settings

logger = structlog.get_logger()


class LLMModel(str, Enum):
    """Available LLM models."""

    FAST = "fast"  # Haiku - quick triage
    DEFAULT = "default"  # Sonnet - balanced
    DEEP = "deep"  # Sonnet/Opus - detailed analysis


# System prompts with cache-optimized structure
# Static content comes first for prompt caching
SYSTEM_PROMPT_SECURITY_ANALYST = """You are a network security analyst for NetGuardian AI, a home network security monitoring system. Your role is to analyze security events, alerts, and anomalies to provide actionable assessments for home network administrators.

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
- Be helpful and educational, not alarmist"""


SYSTEM_PROMPT_CHAT_ASSISTANT = """You are the AI assistant for NetGuardian AI, a home network security monitoring system. You help users understand their network security status and answer questions about devices, events, and alerts.

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

## Context
You have access to:
- Device inventory with behavioral baselines
- Recent network events (DNS queries, connections)
- Detected anomalies and alerts
- Historical patterns for each device"""


class LLMService:
    """Service for interacting with Claude API."""

    def __init__(self):
        self._client: Optional[AsyncAnthropic] = None
        self._enabled = settings.llm_enabled and bool(settings.anthropic_api_key)

    @property
    def client(self) -> AsyncAnthropic:
        """Get or create the Anthropic client."""
        if self._client is None:
            if not settings.anthropic_api_key:
                raise ValueError("Anthropic API key not configured")
            self._client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        return self._client

    @property
    def is_enabled(self) -> bool:
        """Check if LLM service is enabled and configured."""
        return self._enabled

    def _get_model(self, model_type: LLMModel) -> str:
        """Get the model ID for a model type."""
        if model_type == LLMModel.FAST:
            return settings.llm_model_fast
        elif model_type == LLMModel.DEEP:
            return settings.llm_model_deep
        return settings.llm_model_default

    async def analyze_alert(
        self,
        alert_data: Dict[str, Any],
        device_data: Optional[Dict[str, Any]] = None,
        baseline_data: Optional[Dict[str, Any]] = None,
        recent_events: Optional[List[Dict[str, Any]]] = None,
        model_type: LLMModel = LLMModel.DEFAULT,
    ) -> Dict[str, Any]:
        """Analyze an alert using Claude.

        Args:
            alert_data: Alert information.
            device_data: Associated device information.
            baseline_data: Device behavioral baseline.
            recent_events: Recent events for context.
            model_type: Which model to use.

        Returns:
            Analysis results as structured data.
        """
        if not self.is_enabled:
            return {
                "error": "LLM service not enabled",
                "confidence": 0,
                "analysis": "LLM analysis unavailable - API key not configured",
            }

        # Build the analysis prompt
        prompt = self._build_alert_analysis_prompt(
            alert_data, device_data, baseline_data, recent_events
        )

        try:
            # Use prompt caching for the system prompt
            messages = [{"role": "user", "content": prompt}]

            response = await self.client.messages.create(
                model=self._get_model(model_type),
                max_tokens=settings.llm_max_tokens,
                temperature=settings.llm_temperature,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT_SECURITY_ANALYST,
                        "cache_control": {"type": "ephemeral"} if settings.llm_cache_enabled else None,
                    }
                ] if settings.llm_cache_enabled else SYSTEM_PROMPT_SECURITY_ANALYST,
                messages=messages,
            )

            # Parse the response
            analysis_text = response.content[0].text

            # Try to extract structured data if JSON is present
            analysis_result = self._parse_analysis_response(analysis_text)

            # Log cache performance
            if hasattr(response, 'usage'):
                logger.debug(
                    "llm_request_complete",
                    model=self._get_model(model_type),
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    cache_read_tokens=getattr(response.usage, 'cache_read_input_tokens', 0),
                    cache_creation_tokens=getattr(response.usage, 'cache_creation_input_tokens', 0),
                )

            return analysis_result

        except APIError as e:
            logger.error("llm_api_error", error=str(e))
            return {
                "error": str(e),
                "confidence": 0,
                "analysis": f"LLM analysis failed: {e}",
            }
        except Exception as e:
            logger.error("llm_error", error=str(e))
            return {
                "error": str(e),
                "confidence": 0,
                "analysis": f"Analysis error: {e}",
            }

    def _build_alert_analysis_prompt(
        self,
        alert_data: Dict[str, Any],
        device_data: Optional[Dict[str, Any]],
        baseline_data: Optional[Dict[str, Any]],
        recent_events: Optional[List[Dict[str, Any]]],
    ) -> str:
        """Build the alert analysis prompt."""
        prompt_parts = ["## Alert to Analyze\n"]

        # Alert details
        prompt_parts.append(f"**Alert ID:** {alert_data.get('id', 'Unknown')}")
        prompt_parts.append(f"**Title:** {alert_data.get('title', 'Unknown')}")
        prompt_parts.append(f"**Severity:** {alert_data.get('severity', 'Unknown')}")
        prompt_parts.append(f"**Rule:** {alert_data.get('rule_id', 'Unknown')}")
        prompt_parts.append(f"**Timestamp:** {alert_data.get('timestamp', 'Unknown')}")
        prompt_parts.append(f"**Description:** {alert_data.get('description', 'No description')}")
        prompt_parts.append("")

        # Device context
        if device_data:
            prompt_parts.append("## Device Information")
            prompt_parts.append(f"**Device:** {device_data.get('hostname') or device_data.get('mac_address', 'Unknown')}")
            prompt_parts.append(f"**Type:** {device_data.get('device_type', 'Unknown')}")
            prompt_parts.append(f"**Manufacturer:** {device_data.get('manufacturer', 'Unknown')}")
            prompt_parts.append(f"**Status:** {device_data.get('status', 'Unknown')}")
            prompt_parts.append(f"**IP Addresses:** {', '.join(device_data.get('ip_addresses', []))}")
            if device_data.get('profile_tags'):
                prompt_parts.append(f"**Tags:** {', '.join(device_data['profile_tags'])}")
            prompt_parts.append("")

        # Baseline context
        if baseline_data:
            prompt_parts.append("## Device Baseline (Normal Behavior)")
            for baseline_type, metrics in baseline_data.items():
                prompt_parts.append(f"\n### {baseline_type.title()} Baseline")
                if isinstance(metrics, dict):
                    for key, value in metrics.items():
                        if key not in ['unique_domains', 'unique_destinations']:  # Skip large lists
                            prompt_parts.append(f"- {key}: {value}")
            prompt_parts.append("")

        # Recent events for context
        if recent_events:
            prompt_parts.append("## Recent Activity (Last 24 hours)")
            for event in recent_events[:10]:  # Limit to 10 events
                event_time = event.get('timestamp', 'Unknown')
                event_type = event.get('event_type', 'Unknown')
                domain = event.get('domain', '')
                action = event.get('action', '')
                prompt_parts.append(f"- [{event_time}] {event_type}: {domain or event.get('target_ip', 'N/A')} ({action})")
            prompt_parts.append("")

        # Analysis request
        prompt_parts.append("""## Analysis Request

Please analyze this alert and provide:

1. **Threat Assessment** (0-100 confidence score)
2. **Summary** - What happened in plain language
3. **Risk Level** - Low/Medium/High/Critical with justification
4. **Likely Cause** - Most probable explanation
5. **Recommended Actions** - Specific steps to take
6. **False Positive Likelihood** - Low/Medium/High with reasoning

Format your response as JSON:
```json
{
    "confidence": <0-100>,
    "summary": "<plain language summary>",
    "risk_level": "<low|medium|high|critical>",
    "risk_justification": "<why this risk level>",
    "likely_cause": "<most probable explanation>",
    "recommended_actions": ["<action 1>", "<action 2>"],
    "false_positive_likelihood": "<low|medium|high>",
    "false_positive_reasoning": "<why>",
    "additional_context": "<any other relevant observations>"
}
```""")

        return "\n".join(prompt_parts)

    def _parse_analysis_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the analysis response, extracting JSON if present."""
        # Try to extract JSON from the response
        try:
            # Look for JSON block
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                json_str = response_text[json_start:json_end].strip()
                return json.loads(json_str)
            elif "{" in response_text and "}" in response_text:
                # Try to find JSON object
                json_start = response_text.find("{")
                json_end = response_text.rfind("}") + 1
                json_str = response_text[json_start:json_end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # Fallback: return as unstructured analysis
        return {
            "confidence": 50,
            "summary": response_text[:500],
            "analysis": response_text,
            "structured": False,
        }

    async def query_network(
        self,
        query: str,
        context: Dict[str, Any],
        model_type: LLMModel = LLMModel.DEFAULT,
    ) -> str:
        """Process a natural language query about the network.

        Args:
            query: User's natural language question.
            context: Network context (devices, events, stats).
            model_type: Which model to use.

        Returns:
            Natural language response.
        """
        if not self.is_enabled:
            return "LLM service is not enabled. Please configure your Anthropic API key."

        # Build context prompt
        prompt = self._build_query_prompt(query, context)

        try:
            response = await self.client.messages.create(
                model=self._get_model(model_type),
                max_tokens=settings.llm_max_tokens,
                temperature=settings.llm_temperature,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT_CHAT_ASSISTANT,
                        "cache_control": {"type": "ephemeral"} if settings.llm_cache_enabled else None,
                    }
                ] if settings.llm_cache_enabled else SYSTEM_PROMPT_CHAT_ASSISTANT,
                messages=[{"role": "user", "content": prompt}],
            )

            return response.content[0].text

        except APIError as e:
            logger.error("llm_query_error", error=str(e))
            return f"I encountered an error processing your query: {e}"
        except Exception as e:
            logger.error("llm_query_error", error=str(e))
            return f"Sorry, I couldn't process your query: {e}"

    def _build_query_prompt(self, query: str, context: Dict[str, Any]) -> str:
        """Build the query prompt with context."""
        prompt_parts = ["## Current Network Context\n"]

        # Overview stats
        if "stats" in context:
            stats = context["stats"]
            prompt_parts.append("### Network Overview")
            prompt_parts.append(f"- Active devices: {stats.get('active_devices', 'Unknown')}")
            prompt_parts.append(f"- Total events (24h): {stats.get('total_events_24h', 'Unknown')}")
            prompt_parts.append(f"- Active alerts: {stats.get('active_alerts', 'Unknown')}")
            prompt_parts.append(f"- DNS queries (24h): {stats.get('dns_queries_24h', 'Unknown')}")
            prompt_parts.append(f"- Blocked queries (24h): {stats.get('blocked_queries_24h', 'Unknown')}")
            prompt_parts.append("")

        # Device summary
        if "devices" in context:
            prompt_parts.append("### Devices")
            for device in context["devices"][:20]:  # Limit to 20 devices
                name = device.get("hostname") or device.get("mac_address", "Unknown")
                device_type = device.get("device_type", "unknown")
                status = device.get("status", "unknown")
                prompt_parts.append(f"- {name} ({device_type}) - {status}")
            prompt_parts.append("")

        # Recent alerts
        if "alerts" in context:
            prompt_parts.append("### Recent Alerts")
            for alert in context["alerts"][:10]:
                prompt_parts.append(f"- [{alert.get('severity', 'unknown')}] {alert.get('title', 'Unknown')}")
            prompt_parts.append("")

        # Recent anomalies
        if "anomalies" in context:
            prompt_parts.append("### Recent Anomalies")
            for anomaly in context["anomalies"][:10]:
                prompt_parts.append(f"- [{anomaly.get('severity', 'unknown')}] {anomaly.get('description', 'Unknown')}")
            prompt_parts.append("")

        # User query
        prompt_parts.append(f"## User Question\n{query}")
        prompt_parts.append("\nPlease provide a helpful, informative response based on the network context above.")

        return "\n".join(prompt_parts)

    async def summarize_incident(
        self,
        alerts: List[Dict[str, Any]],
        anomalies: List[Dict[str, Any]],
        events: List[Dict[str, Any]],
        device_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate an incident summary from related alerts and events.

        Args:
            alerts: Related alerts.
            anomalies: Related anomalies.
            events: Related events.
            device_data: Device information if single device.

        Returns:
            Incident summary as structured data.
        """
        if not self.is_enabled:
            return {
                "error": "LLM service not enabled",
                "summary": "LLM service unavailable",
            }

        prompt = self._build_incident_summary_prompt(alerts, anomalies, events, device_data)

        try:
            response = await self.client.messages.create(
                model=self._get_model(LLMModel.DEFAULT),
                max_tokens=settings.llm_max_tokens,
                temperature=settings.llm_temperature,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT_SECURITY_ANALYST,
                        "cache_control": {"type": "ephemeral"} if settings.llm_cache_enabled else None,
                    }
                ] if settings.llm_cache_enabled else SYSTEM_PROMPT_SECURITY_ANALYST,
                messages=[{"role": "user", "content": prompt}],
            )

            return self._parse_incident_summary(response.content[0].text)

        except Exception as e:
            logger.error("incident_summary_error", error=str(e))
            return {
                "error": str(e),
                "summary": f"Failed to generate summary: {e}",
            }

    def _build_incident_summary_prompt(
        self,
        alerts: List[Dict[str, Any]],
        anomalies: List[Dict[str, Any]],
        events: List[Dict[str, Any]],
        device_data: Optional[Dict[str, Any]],
    ) -> str:
        """Build the incident summary prompt."""
        prompt_parts = ["## Incident Data for Summary\n"]

        if device_data:
            prompt_parts.append("### Affected Device")
            prompt_parts.append(f"- Name: {device_data.get('hostname') or device_data.get('mac_address')}")
            prompt_parts.append(f"- Type: {device_data.get('device_type', 'Unknown')}")
            prompt_parts.append("")

        prompt_parts.append("### Alerts")
        for alert in alerts[:20]:
            prompt_parts.append(f"- [{alert.get('timestamp')}] {alert.get('severity')}: {alert.get('title')}")
            prompt_parts.append(f"  Description: {alert.get('description', 'N/A')}")
        prompt_parts.append("")

        prompt_parts.append("### Anomalies")
        for anomaly in anomalies[:20]:
            prompt_parts.append(f"- [{anomaly.get('detected_at')}] {anomaly.get('anomaly_type')}: {anomaly.get('description')}")
        prompt_parts.append("")

        prompt_parts.append("### Related Events")
        for event in events[:30]:
            prompt_parts.append(f"- [{event.get('timestamp')}] {event.get('event_type')}: {event.get('domain') or event.get('target_ip', 'N/A')}")
        prompt_parts.append("")

        prompt_parts.append("""## Summary Request

Please provide an incident summary:

```json
{
    "title": "<concise incident title>",
    "executive_summary": "<2-3 sentence overview for non-technical readers>",
    "technical_summary": "<detailed technical description>",
    "timeline": ["<chronological list of key events>"],
    "impact_assessment": "<what was/could be affected>",
    "root_cause": "<likely cause or attack vector>",
    "recommendations": ["<list of recommended actions>"],
    "severity": "<low|medium|high|critical>",
    "confidence": <0-100>
}
```""")

        return "\n".join(prompt_parts)

    def _parse_incident_summary(self, response_text: str) -> Dict[str, Any]:
        """Parse incident summary response."""
        try:
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                json_str = response_text[json_start:json_end].strip()
                return json.loads(json_str)
            elif "{" in response_text:
                json_start = response_text.find("{")
                json_end = response_text.rfind("}") + 1
                return json.loads(response_text[json_start:json_end])
        except json.JSONDecodeError:
            pass

        return {
            "title": "Incident Summary",
            "executive_summary": response_text[:500],
            "full_response": response_text,
        }

    async def stream_chat(
        self,
        messages: List[Dict[str, str]],
        context: Dict[str, Any],
    ) -> AsyncGenerator[str, None]:
        """Stream a chat response.

        Args:
            messages: Conversation history.
            context: Network context.

        Yields:
            Response text chunks.
        """
        if not self.is_enabled:
            yield "LLM service is not enabled. Please configure your Anthropic API key."
            return

        # Build context message
        context_message = self._build_query_prompt("", context)

        # Prepend context to first user message or add as system context
        formatted_messages = []
        context_added = False

        for msg in messages:
            if msg["role"] == "user" and not context_added:
                formatted_messages.append({
                    "role": "user",
                    "content": f"{context_message}\n\n## User Message\n{msg['content']}"
                })
                context_added = True
            else:
                formatted_messages.append(msg)

        try:
            async with self.client.messages.stream(
                model=self._get_model(LLMModel.DEFAULT),
                max_tokens=settings.llm_max_tokens,
                temperature=settings.llm_temperature,
                system=SYSTEM_PROMPT_CHAT_ASSISTANT,
                messages=formatted_messages,
            ) as stream:
                async for text in stream.text_stream:
                    yield text

        except Exception as e:
            logger.error("chat_stream_error", error=str(e))
            yield f"Error: {e}"


# Global service instance
_llm_service: Optional[LLMService] = None


def get_llm_service() -> LLMService:
    """Get the global LLM service instance."""
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service
