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
    normalize: Literal["none", "strip_separators"] = "none"


@dataclass(frozen=True)
class CompiledLeakPattern:
    """A validated pattern with its case-insensitive matcher compiled once."""

    definition: LeakPattern
    expression: re.Pattern[str]


class SystemPromptLeakDetector:
    """Detect and redact configured system-prompt patterns in model output."""

    detector_name = "system_prompt_leak"
    _separator_characters = frozenset(" \t\n\r-_.")

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

    @classmethod
    def _strip_separators_with_index_map(cls, content: str) -> tuple[str, list[int]]:
        """Build normalized text and map each normalized character to its source index."""

        normalized_characters: list[str] = []
        index_map: list[int] = []
        for original_index, character in enumerate(content):
            if character in cls._separator_characters or character.isspace():
                continue
            normalized_characters.append(character)
            index_map.append(original_index)
        return "".join(normalized_characters), index_map

    @staticmethod
    def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
        """Merge overlapping spans so redacting one cannot corrupt another's offsets."""

        merged: list[tuple[int, int]] = []
        for start, end in sorted(spans):
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
                continue
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        return merged

    async def scan(self, content: str) -> DetectorSignal:
        """Return matched IDs and a redacted copy without retaining secret values."""

        matched_pattern_ids: list[str] = []
        spans: list[tuple[int, int]] = []
        normalized_content: str | None = None
        index_map: list[int] | None = None

        for pattern in self._patterns:
            if pattern.definition.normalize == "strip_separators":
                if normalized_content is None or index_map is None:
                    normalized_content, index_map = self._strip_separators_with_index_map(
                        content
                    )
                matches = list(pattern.expression.finditer(normalized_content))
                pattern_spans = [
                    (index_map[match.start()], index_map[match.end() - 1] + 1)
                    for match in matches
                    if match.end() > match.start()
                ]
            else:
                pattern_spans = [
                    match.span()
                    for match in pattern.expression.finditer(content)
                    if match.end() > match.start()
                ]

            if not pattern_spans:
                continue

            matched_pattern_ids.append(pattern.definition.id)
            spans.extend(pattern_spans)

        matched = bool(matched_pattern_ids)
        redacted_content = content
        for start, end in reversed(self._merge_spans(spans)):
            redacted_content = redacted_content[:start] + "[REDACTED]" + redacted_content[end:]

        return DetectorSignal(
            detector=self.detector_name,
            matched=matched,
            matched_pattern_ids=matched_pattern_ids or None,
            redacted_content=redacted_content if matched else None,
        )
