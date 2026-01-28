"""Ollama LLM provider for local semantic log analysis."""

from typing import Any

import httpx
import structlog

from app.config import settings
from app.services.llm_providers.base import (
    SEMANTIC_ANALYSIS_SYSTEM_PROMPT,
    BaseLLMProvider,
    LLMAnalysisResult,
)

logger = structlog.get_logger()


class OllamaLLMProvider(BaseLLMProvider):
    """LLM provider using local Ollama server."""

    def __init__(
        self,
        url: str | None = None,
        model: str = "llama3.2",
        timeout: int = 120,
    ):
        """Initialize the Ollama provider.

        Args:
            url: Ollama server URL. Defaults to settings.ollama_url.
            model: Model to use (e.g., "llama3.2", "mistral", "codellama").
            timeout: Request timeout in seconds.
        """
        self._url = (url or settings.ollama_url).rstrip("/")
        self._model = model
        self._timeout = timeout

    @property
    def provider_name(self) -> str:
        return "ollama"

    async def is_available(self) -> bool:
        """Check if Ollama server is available."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self._url}/api/tags")
                return response.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """List available models on the Ollama server.

        Returns:
            List of model names.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(f"{self._url}/api/tags")
                if response.status_code == 200:
                    data = response.json()
                    return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            logger.error("ollama_list_models_error", error=str(e))
        return []

    async def analyze_logs(
        self,
        logs: list[dict[str, Any]],
        context: str | None = None,
    ) -> LLMAnalysisResult:
        """Analyze logs using Ollama.

        Args:
            logs: List of irregular log entries.
            context: Optional additional context.

        Returns:
            LLMAnalysisResult with analysis findings.
        """
        prompt = self._build_analysis_prompt(logs, context)

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self._url}/api/generate",
                    json={
                        "model": self._model,
                        "prompt": prompt,
                        "system": SEMANTIC_ANALYSIS_SYSTEM_PROMPT,
                        "stream": False,
                        "options": {
                            "temperature": 0.3,
                            "num_predict": 4096,
                        },
                    },
                )

                if response.status_code != 200:
                    error_text = response.text[:200] if response.text else "Unknown error"
                    logger.error(
                        "ollama_api_error",
                        status_code=response.status_code,
                        error=error_text,
                    )
                    return LLMAnalysisResult.from_error(
                        f"Ollama API error ({response.status_code}): {error_text}"
                    )

                data = response.json()
                response_text = data.get("response", "")

                # Log completion stats
                logger.debug(
                    "ollama_semantic_analysis_complete",
                    model=self._model,
                    eval_count=data.get("eval_count", 0),
                    eval_duration_ms=data.get("eval_duration", 0) / 1_000_000,
                    logs_analyzed=len(logs),
                )

                # Parse the response
                parsed = self._parse_json_response(response_text)

                if "error" in parsed and parsed.get("summary") == "Failed to parse LLM response":
                    return LLMAnalysisResult.from_error(
                        f"Failed to parse response: {parsed.get('raw_response', '')[:200]}"
                    )

                result = LLMAnalysisResult.from_dict(parsed, response_text)
                result.tokens_used = data.get("eval_count", 0)
                return result

        except httpx.TimeoutException:
            logger.error("ollama_timeout", url=self._url, model=self._model)
            return LLMAnalysisResult.from_error(
                f"Ollama request timed out after {self._timeout}s"
            )

        except httpx.ConnectError:
            logger.error("ollama_connection_error", url=self._url)
            return LLMAnalysisResult.from_error(
                f"Failed to connect to Ollama at {self._url}"
            )

        except Exception as e:
            logger.error("ollama_analysis_error", error=str(e))
            return LLMAnalysisResult.from_error(f"Analysis error: {e}")

    async def pull_model(self, model: str) -> bool:
        """Pull a model from the Ollama registry.

        Args:
            model: Model name to pull.

        Returns:
            True if successful.
        """
        try:
            async with httpx.AsyncClient(timeout=600.0) as client:  # 10 min timeout for large models
                response = await client.post(
                    f"{self._url}/api/pull",
                    json={"name": model, "stream": False},
                )
                return response.status_code == 200
        except Exception as e:
            logger.error("ollama_pull_model_error", model=model, error=str(e))
            return False
