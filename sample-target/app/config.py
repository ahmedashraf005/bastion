"""Environment-backed settings for SampleBank Copilot."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Runtime settings for the locally run sample target."""

    gate_base_url: str = os.getenv("GATE_BASE_URL", "http://localhost:8000").rstrip(
        "/"
    )
    sample_target_port: int = int(os.getenv("SAMPLE_TARGET_PORT", "8080"))
    sample_target_model: str = os.getenv("SAMPLE_TARGET_MODEL", "llama3.1:8b")


settings = Settings()
