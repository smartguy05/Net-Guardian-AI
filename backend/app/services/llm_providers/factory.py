"""Factory for creating LLM providers."""


from app.models.semantic_analysis import LLMProvider
from app.services.llm_providers.base import BaseLLMProvider
from app.services.llm_providers.claude_provider import ClaudeLLMProvider
from app.services.llm_providers.ollama_provider import OllamaLLMProvider


class LLMProviderFactory:
    """Factory for creating LLM provider instances."""

    @staticmethod
    def get_provider(
        provider_type: LLMProvider | str,
        ollama_model: str | None = None,
        ollama_url: str | None = None,
        **kwargs,
    ) -> BaseLLMProvider:
        """Get an LLM provider instance.

        Args:
            provider_type: The provider type (claude or ollama).
            ollama_model: Model to use if provider is ollama.
            ollama_url: URL if provider is ollama.
            **kwargs: Additional provider-specific arguments.

        Returns:
            An LLM provider instance.

        Raises:
            ValueError: If provider_type is not supported.
        """
        # Convert enum to string if needed
        if isinstance(provider_type, LLMProvider):
            provider_str = provider_type.value
        else:
            provider_str = provider_type.lower()

        if provider_str == "claude":
            return ClaudeLLMProvider(**kwargs)

        elif provider_str == "ollama":
            provider_kwargs = {}
            if ollama_model:
                provider_kwargs["model"] = ollama_model
            if ollama_url:
                provider_kwargs["url"] = ollama_url
            provider_kwargs.update(kwargs)
            return OllamaLLMProvider(**provider_kwargs)

        else:
            raise ValueError(f"Unknown LLM provider type: {provider_type}")

    @staticmethod
    async def get_available_provider(
        preferred: LLMProvider | str = LLMProvider.CLAUDE,
        ollama_model: str | None = None,
    ) -> BaseLLMProvider | None:
        """Get an available LLM provider, falling back if preferred is unavailable.

        Args:
            preferred: Preferred provider type.
            ollama_model: Model to use if using ollama.

        Returns:
            An available provider, or None if none are available.
        """
        # Try preferred provider first
        provider = LLMProviderFactory.get_provider(preferred, ollama_model=ollama_model)
        if await provider.is_available():
            return provider

        # Fallback to other provider
        fallback_type = (
            LLMProvider.OLLAMA if preferred == LLMProvider.CLAUDE else LLMProvider.CLAUDE
        )
        fallback = LLMProviderFactory.get_provider(fallback_type, ollama_model=ollama_model)
        if await fallback.is_available():
            return fallback

        return None
