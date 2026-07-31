"""Safety-critical and environment-backed configuration for Bastion.Strike."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


# This deliberately requires a reviewed code change before Strike can target
# anything beyond the bundled, synthetic SampleBank Copilot application.
CONTAINER_SAMPLE_BANK_URL = "http://sample-target:8080/chat"
HOST_SAMPLE_BANK_URL = "http://localhost:8080/chat"

# Compose may select the container-only service DNS address, but it cannot
# supply an arbitrary target URL: both allowable endpoints remain reviewed
# constants bound to the same synthetic SampleBank target key.
ALLOWED_TARGETS: dict[str, str] = {
    "sample-bank": (
        CONTAINER_SAMPLE_BANK_URL
        if os.getenv("BASTION_CONTAINERIZED") == "true"
        else HOST_SAMPLE_BANK_URL
    ),
}


@dataclass(frozen=True)
class Settings:
    """Runtime settings that do not alter Strike's target boundary."""

    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://bastion:bastion_dev_password_change_me@localhost:5432/bastion",
    )
    request_timeout_seconds: float = float(
        os.getenv("STRIKE_REQUEST_TIMEOUT_SECONDS", "60")
    )
    planner_request_timeout_seconds: float = float(
        os.getenv("STRIKE_PLANNER_REQUEST_TIMEOUT_SECONDS", "45")
    )
    ollama_base_url: str = os.getenv(
        "OLLAMA_BASE_URL", "http://localhost:11434"
    ).rstrip("/")
    valkey_url: str = os.getenv("VALKEY_URL", "redis://localhost:6380/0")
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")
    runner_lease_seconds: int = int(os.getenv("STRIKE_RUNNER_LEASE_SECONDS", "180"))
    planner_provider: str = os.getenv("STRIKE_PLANNER_PROVIDER", "ollama")
    planner_model: str = os.getenv("STRIKE_PLANNER_MODEL", "llama3.1:8b")
    openai_model: str = os.getenv("STRIKE_OPENAI_MODEL", "gpt-4o-mini")
    openai_base_url: str = os.getenv(
        "STRIKE_OPENAI_BASE_URL", "https://api.openai.com/v1"
    ).rstrip("/")
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY") or None


settings = Settings()
