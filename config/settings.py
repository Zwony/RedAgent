"""Global configuration and settings for RedAgent platform."""
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """Platform environment settings."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # General App Config
    APP_NAME: str = "RedAgent Security Platform"
    APP_ENV: str = Field(default="development", description="Environment: development, test, production")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")

    # LLM Orchestrator & Attacker Model Configuration (LiteLLM format)
    DEFAULT_ORCHESTRATOR_MODEL: str = Field(
        default="gpt-4o",
        description="Model used by Orchestrator and Evaluator agents"
    )
    DEFAULT_ATTACKER_MODEL: str = Field(
        default="gpt-4o",
        description="Model used by Red Team attack generation specialists"
    )

    # API Keys (Loaded from .env)
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None

    # Memory & Persistence
    REDIS_URL: str = Field(default="redis://localhost:6379/0", description="Redis connection URL for state caching")
    CHROMADB_PATH: str = Field(default="./data/chromadb", description="Persistent directory path for ChromaDB")

    # Execution Safeguards
    MAX_CONCURRENT_TESTS: int = Field(default=5, description="Maximum concurrent attack runs")
    DEFAULT_TIMEOUT_SECONDS: float = Field(default=30.0, description="HTTP / Execution timeout per interaction")
    MAX_ATTACK_ITERATIONS: int = Field(default=3, description="Maximum self-refinement iterations per test case")


settings = Settings()
