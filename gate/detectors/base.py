"""Common interface and audit signal shape for Gate detectors."""

from typing import Protocol

from pydantic import BaseModel


class DetectorSignal(BaseModel):
    """A detector result retained in the Gate audit trail."""

    detector: str
    injection_score: float | None = None
    entities: list[str] | None = None
    matched: bool | None = None
    redacted_content: str | None = None
    matched_pattern_ids: list[str] | None = None


class Detector(Protocol):
    """Protocol implemented by asynchronous Gate detectors."""

    async def scan(self, content: str) -> DetectorSignal:
        """Scan content and return one normalized detector signal."""
