"""Safety-critical and environment-backed configuration for Bastion.Strike."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


# This deliberately requires a reviewed code change before Strike can target
# anything beyond the bundled, synthetic SampleBank Copilot application.
ALLOWED_TARGETS: dict[str, str] = {
    "sample-bank": "http://localhost:8080/chat",
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
    ollama_base_url: str = os.getenv(
        "OLLAMA_BASE_URL", "http://localhost:11434"
    ).rstrip("/")


settings = Settings()
