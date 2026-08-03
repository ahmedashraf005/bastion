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
    # Which message this signal was scanned from ("user", "tool", ...). A
    # detector's .scan() only ever sees a string, never the message it came
    # from, so this is always set by the caller after scanning, never by a
    # detector itself. Without it, a tool-output signal is indistinguishable
    # from a user-message one in detector_signals — both were, until this
    # field existed, always implicitly "user" since that was the only
    # role ever scanned.
    source_role: str | None = None


class Detector(Protocol):
    """Protocol implemented by asynchronous Gate detectors."""

    async def scan(self, content: str) -> DetectorSignal:
        """Scan content and return one normalized detector signal."""
