"""Application configuration using Pydantic Settings."""

import json
from functools import lru_cache

from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "NetGuardian AI"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql+asyncpg://netguardian:password@localhost:5432/netguardian"
    db_pool_size: int = 20  # Number of persistent connections in the pool
    db_max_overflow: int = 30  # Extra connections allowed beyond pool_size
    db_pool_timeout: int = 30  # Seconds to wait for available connection
    db_pool_recycle: int = 1800  # Recycle connections after 30 minutes

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_max_connections: int = 50  # Max connections in Redis pool

    # HTTP Client Settings
    http_timeout_seconds: int = 30
    http_max_connections: int = 100  # Max connections per host
    http_keepalive_expiry: int = 30  # Seconds to keep idle connections

    # Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_default_rpm: int = 60  # Requests per minute for default endpoints
    rate_limit_auth_rpm: int = 10  # Requests per minute for auth endpoints
    rate_limit_chat_rpm: int = 20  # Requests per minute for chat endpoints
    rate_limit_export_rpm: int = 5  # Requests per minute for export endpoints

    # Authentication
    secret_key: str = "change-this-to-a-secure-secret-key"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # CORS - stored as string to avoid pydantic-settings JSON parsing issues
    cors_origins_raw: str = "http://localhost:3000,http://localhost:5173"

    @computed_field
    @property
    def cors_origins(self) -> list[str]:
        """Parse CORS origins from raw string."""
        v = self.cors_origins_raw
        if not v:
            return []
        # Try JSON first, fall back to comma-separated
        try:
            parsed = json.loads(v)
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            pass
        return [origin.strip() for origin in v.split(",") if origin.strip()]

    # Log Ingestion
    log_sources_dir: str = "/logs"
    log_ingestion_api_enabled: bool = True
    log_ingestion_rate_limit: int = 1000  # events per minute per source

    # AdGuard Home Integration (Phase 4)
    adguard_enabled: bool = False
    adguard_url: str = ""
    adguard_username: str = ""
    adguard_password: str = ""
    adguard_verify_ssl: bool = True

    # Router Integration (Phase 4)
    router_integration_type: str = ""  # unifi, pfsense, opnsense, ssh
    router_url: str = ""
    router_username: str = ""
    router_password: str = ""
    router_site: str = "default"  # For UniFi
    router_verify_ssl: bool = True

    # LLM Configuration (Phase 3)
    anthropic_api_key: str = ""
    llm_model_default: str = "claude-sonnet-4-latest"  # For general analysis
    llm_model_fast: str = "claude-3-5-haiku-latest"  # For quick triage
    llm_model_deep: str = "claude-sonnet-4-latest"  # For detailed analysis
    llm_enabled: bool = True
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.3
    llm_cache_enabled: bool = True  # Enable Anthropic prompt caching

    # Ollama Configuration (Local LLM)
    ollama_enabled: bool = False
    ollama_url: str = "http://localhost:11434"
    ollama_poll_interval_seconds: int = 30
    ollama_verify_ssl: bool = False
    ollama_detection_enabled: bool = True  # Enable malware/injection detection
    ollama_prompt_analysis_enabled: bool = True  # Use Claude to analyze prompts
    ollama_alert_on_injection: bool = True  # Create alerts for detected attacks
    ollama_injection_severity: str = "high"  # Alert severity for injections
    ollama_default_model: str = "llama3.2"  # Default model for semantic analysis
    ollama_timeout_seconds: int = 120  # Timeout for Ollama requests

    # Semantic Log Analysis
    semantic_analysis_enabled: bool = True
    semantic_default_llm_provider: str = "claude"  # "claude" or "ollama"
    semantic_default_rarity_threshold: int = 3  # Patterns < N occurrences are rare
    semantic_default_batch_size: int = 50  # Max logs per LLM batch
    semantic_default_batch_interval_minutes: int = 60  # Minutes between batch runs
    semantic_scheduler_enabled: bool = True  # Enable automatic scheduling

    # Email Notifications (SMTP)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_sender_email: str = ""
    smtp_sender_name: str = "NetGuardian AI"

    # ntfy.sh Push Notifications
    ntfy_server_url: str = "https://ntfy.sh"
    ntfy_default_topic: str = ""
    ntfy_auth_token: str = ""  # Optional for private topics

    # Authentik OIDC Configuration
    authentik_enabled: bool = False
    authentik_issuer_url: str = ""  # e.g., https://auth.example.com/application/o/netguardian/
    authentik_client_id: str = ""
    authentik_client_secret: str = ""
    authentik_redirect_uri: str = ""  # e.g., http://localhost:8000/api/v1/auth/oidc/callback
    authentik_scopes: str = "openid profile email groups"
    authentik_group_mappings: str = "{}"  # JSON: {"group-name": "admin"}
    authentik_auto_create_users: bool = True
    authentik_default_role: str = "viewer"

    @property
    def async_database_url(self) -> str:
        """Ensure database URL uses asyncpg driver."""
        url = self.database_url
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        return url


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
