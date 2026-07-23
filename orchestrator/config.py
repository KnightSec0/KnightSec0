"""
DeepVault configuration — loaded from environment variables.
"""

import os
from dataclasses import dataclass
from typing import Optional


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    # Database
    db_url: str = os.getenv(
        "DB_URL", "postgresql+asyncpg://deepvault:changeme@postgres:5432/deepvault"
    )
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "changeme")
    elastic_host: str = os.getenv("ELASTIC_HOST", "http://elasticsearch:9200")

    # Tor proxy
    tor_proxy: str = os.getenv("TOR_PROXY", "socks5://tor-proxy:9050")

    # API Keys
    intelx_api_key: Optional[str] = os.getenv("INTELX_API_KEY")
    dehashed_api_key: Optional[str] = os.getenv("DEHASHED_API_KEY")
    dehashed_api_login: Optional[str] = os.getenv("DEHASHED_API_LOGIN")
    shodan_api_key: Optional[str] = os.getenv("SHODAN_API_KEY")
    hibp_api_key: Optional[str] = os.getenv("HIBP_API_KEY")
    hunter_api_key: Optional[str] = os.getenv("HUNTER_API_KEY")
    sociallinks_api_key: Optional[str] = os.getenv("SOCIALLINKS_API_KEY")
    brave_api_key: Optional[str] = os.getenv("BRAVE_API_KEY")
    github_token: Optional[str] = os.getenv("GITHUB_TOKEN")
    censys_api_id: Optional[str] = os.getenv("CENSYS_API_ID")
    censys_api_secret: Optional[str] = os.getenv("CENSYS_API_SECRET")
    spiderfoot_url: Optional[str] = os.getenv("SPIDERFOOT_URL")

    # Evidence analysis / reporting
    llm_provider: str = os.getenv("LLM_PROVIDER", "none")
    openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-5")
    anthropic_api_key: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    gemini_api_key: Optional[str] = os.getenv("GEMINI_API_KEY")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-pro")
    openai_compatible_api_key: Optional[str] = os.getenv("OPENAI_COMPATIBLE_API_KEY")
    openai_compatible_base_url: Optional[str] = os.getenv("OPENAI_COMPATIBLE_BASE_URL")
    openai_compatible_model: str = os.getenv("OPENAI_COMPATIBLE_MODEL", "default")
    ollama_base_url: str = os.getenv(
        "OLLAMA_BASE_URL", "http://host.docker.internal:11434"
    )
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.3")
    llm_consensus_providers: str = os.getenv("LLM_CONSENSUS_PROVIDERS", "")
    llm_include_identifiers: bool = _env_bool("LLM_INCLUDE_IDENTIFIERS", False)

    # Connector safety / resource controls
    connector_timeout: int = int(os.getenv("CONNECTOR_TIMEOUT", "30"))
    max_osint_concurrency: int = int(os.getenv("MAX_OSINT_CONCURRENCY", "4"))
    allow_sensitive_pivots: bool = _env_bool("ALLOW_SENSITIVE_PIVOTS", False)
    allow_infrastructure_enrichment: bool = _env_bool(
        "ALLOW_INFRASTRUCTURE_ENRICHMENT", False
    )
    authorization_reference: Optional[str] = os.getenv("AUTHORIZATION_REFERENCE")

    # Celery / Redis
    celery_broker: str = os.getenv("CELERY_BROKER", "redis://redis:6379/0")

    # Storage (MinIO)
    s3_endpoint: str = os.getenv("S3_ENDPOINT", "http://minio:9000")
    s3_access_key: str = os.getenv("S3_ACCESS_KEY", "deepvault")
    s3_secret_key: str = os.getenv("S3_SECRET_KEY", "changeme")
    s3_bucket: str = "deepvault-artifacts"

    # Rate limiting
    request_delay: float = 1.0  # seconds between public requests
    tor_circuit_refresh: int = 30  # minutes between Tor circuit refreshes


settings = Settings()
