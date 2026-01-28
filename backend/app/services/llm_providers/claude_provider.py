"""Claude (Anthropic) LLM provider for semantic log analysis."""

from typing import Any

import structlog
from anthropic import APIError, AsyncAnthropic

from app.config import settings
from app.services.llm_providers.base import (
    SEMANTIC_ANALYSIS_SYSTEM_PROMPT,
    BaseLLMProvider,
    LLMAnalysisResult,
)

logger = structlog.get_logger()


class ClaudeLLMProvider(BaseLLMProvider):
    """LLM provider using Anthropic's Claude API."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.3,
        enable_cache: bool = True,
    ):
        """Initialize the Claude provider.

        Args:
            api_key: Anthropic API key. Defaults to settings.
            model: Model to use. Defaults to settings.llm_model_default.
            max_tokens: Maximum response tokens.
            temperature: Sampling temperature.
            enable_cache: Whether to use prompt caching.
        """
        self._api_key = api_key or settings.anthropic_api_key
        self._model = model or settings.llm_model_default
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._enable_cache = enable_cache and settings.llm_cache_enabled
        self._client: AsyncAnthropic | None = None

    @property
    def client(self) -> AsyncAnthropic:
        """Get or create the Anthropic client."""
        if self._client is None:
            if not self._api_key:
                raise ValueError("Anthropic API key not configured")
            self._client = AsyncAnthropic(api_key=self._api_key)
        return self._client

    @property
    def provider_name(self) -> str:
        return "claude"

    async def is_available(self) -> bool:
        """Check if Claude is available and configured."""
        if not self._api_key:
            return False

        try:
            # Simple test to verify API key works
            # We don't actually make an API call here to avoid costs
            return True
        except Exception:
            return False

    async def analyze_logs(
        self,
        logs: list[dict[str, Any]],
        context: str | None = None,
    ) -> LLMAnalysisResult:
        """Analyze logs using Claude.

        Args:
            logs: List of irregular log entries.
            context: Optional additional context.

        Returns:
            LLMAnalysisResult with analysis findings.
        """
        if not self._api_key:
            return LLMAnalysisResult.from_error("Anthropic API key not configured")

        prompt = self._build_analysis_prompt(logs, context)

        try:
            # Build system prompt with optional caching
            if self._enable_cache:
                system = [
                    {
                        "type": "text",
                        "text": SEMANTIC_ANALYSIS_SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ]
            else:
                system = SEMANTIC_ANALYSIS_SYSTEM_PROMPT

            response = await self.client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = response.content[0].text
            tokens_used = response.usage.input_tokens + response.usage.output_tokens

            # Log cache performance
            logger.debug(
                "claude_semantic_analysis_complete",
                model=self._model,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
                cache_creation_tokens=getattr(response.usage, "cache_creation_input_tokens", 0),
                logs_analyzed=len(logs),
            )

            # Parse the response
            parsed = self._parse_json_response(response_text)

            if "error" in parsed and parsed.get("summary") == "Failed to parse LLM response":
                return LLMAnalysisResult.from_error(
                    f"Failed to parse response: {parsed.get('raw_response', '')[:200]}"
                )

            result = LLMAnalysisResult.from_dict(parsed, response_text)
            result.tokens_used = tokens_used
            return result

        except APIError as e:
            logger.error("claude_api_error", error=str(e))
            return LLMAnalysisResult.from_error(f"Claude API error: {e}")

        except Exception as e:
            logger.error("claude_analysis_error", error=str(e))
            return LLMAnalysisResult.from_error(f"Analysis error: {e}")
