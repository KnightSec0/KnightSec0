"""
DeepVault configuration — loaded from environment variables.
"""
import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Settings:
    # Database
    db_url: str = os.getenv("DB_URL", "postgresql+asyncpg://deepvault:changeme@postgres:5432/deepvault")
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
