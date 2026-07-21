"""Environment-backed settings for the Gate service."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Runtime settings for a locally run Gate instance."""

    ollama_base_url: str = os.getenv(
        "OLLAMA_BASE_URL", "http://localhost:11434"
    ).rstrip("/")
    ollama_timeout_seconds: float = float(
        os.getenv("OLLAMA_TIMEOUT_SECONDS", "120")
    )
    gate_port: int = int(os.getenv("GATE_PORT", "8000"))


settings = Settings()
