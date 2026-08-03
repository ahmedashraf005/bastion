"""Environment-backed settings for the Gate service."""

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Runtime settings for a locally run Gate instance."""

    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://bastion:bastion_dev_password_change_me@localhost:5432/bastion",
    )
    ollama_base_url: str = os.getenv(
        "OLLAMA_BASE_URL", "http://localhost:11434"
    ).rstrip("/")
    ollama_timeout_seconds: float = float(
        os.getenv("OLLAMA_TIMEOUT_SECONDS", "120")
    )
    gate_port: int = int(os.getenv("GATE_PORT", "8000"))
    hf_token: str | None = os.getenv("HF_TOKEN") or None
    raw_exact_marker: str | None = os.getenv("GATE_RAW_EXACT_MARKER") or None
    marker_secrets_file: Path | None = (
        Path(os.environ["GATE_MARKER_SECRETS_FILE"]).resolve()
        if os.getenv("GATE_MARKER_SECRETS_FILE")
        else None
    )
    rules_path: Path | None = (
        Path(os.environ["GATE_RULES_PATH"]).resolve()
        if os.getenv("GATE_RULES_PATH")
        else None
    )
    policy_profile: str | None = os.getenv("GATE_POLICY_PROFILE") or None
    # Opt-in, default off: Presidio's false-positive behavior on structured
    # tool-output content (JSON, transaction records) is unmeasured. See
    # docs/threat-model.md and the tool-output benign corpus before ever
    # setting this true outside a measurement run.
    scan_tool_output: bool = os.getenv("GATE_SCAN_TOOL_OUTPUT", "false").lower() == "true"


settings = Settings()
