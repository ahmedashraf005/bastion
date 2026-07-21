"""Pattern-based detector for system-prompt values leaked in model output."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Literal

import yaml
from pydantic import BaseModel, TypeAdapter

from detectors.base import DetectorSignal


class LeakPattern(BaseModel):
    """One detector-owned definition of a value that must not reach clients."""

    id: str
    description: str
    pattern: str
    pattern_type: Literal["literal", "regex"]


@dataclass(frozen=True)
class CompiledLeakPattern:
    """A validated pattern with its case-insensitive matcher compiled once."""

    definition: LeakPattern
    expression: re.Pattern[str]


class SystemPromptLeakDetector:
    """Detect and redact configured system-prompt patterns in model output."""

    detector_name = "system_prompt_leak"

    def __init__(self, patterns: list[CompiledLeakPattern]) -> None:
        self._patterns = patterns

    @classmethod
    def from_yaml(cls, patterns_path: Path) -> "SystemPromptLeakDetector":
        """Load and compile detector-owned patterns once at Gate startup."""

        with patterns_path.open(encoding="utf-8") as patterns_file:
            raw_patterns = yaml.safe_load(patterns_file)

        definitions = TypeAdapter(list[LeakPattern]).validate_python(raw_patterns)
        patterns = [
            CompiledLeakPattern(
                definition=definition,
                expression=re.compile(
                    re.escape(definition.pattern)
                    if definition.pattern_type == "literal"
                    else definition.pattern,
                    re.IGNORECASE,
                ),
            )
            for definition in definitions
        ]
        return cls(patterns)

    async def scan(self, content: str) -> DetectorSignal:
        """Return matched IDs and a redacted copy without retaining secret values."""

        matched_pattern_ids: list[str] = []
        redacted_content = content

        for pattern in self._patterns:
            if pattern.expression.search(content) is None:
                continue

            matched_pattern_ids.append(pattern.definition.id)
            redacted_content = pattern.expression.sub("[REDACTED]", redacted_content)

        matched = bool(matched_pattern_ids)
        return DetectorSignal(
            detector=self.detector_name,
            matched=matched,
            matched_pattern_ids=matched_pattern_ids or None,
            redacted_content=redacted_content if matched else None,
        )
