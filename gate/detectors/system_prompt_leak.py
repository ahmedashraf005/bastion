"""Pattern-based detector for system-prompt values leaked in model output."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Literal
import unicodedata

import yaml
from pydantic import BaseModel, TypeAdapter

from .base import DetectorSignal


class LeakPattern(BaseModel):
    """One detector-owned definition of a value that must not reach clients."""

    id: str
    description: str
    pattern: str
    pattern_type: Literal["literal", "regex"]
    normalize: Literal["none", "strip_separators"] = "none"


class PromotedNormalization(BaseModel):
    """One versioned, data-only normalizer addition approved through Strike."""

    version_id: str
    proposal_id: str
    origin_finding_id: str
    detector: Literal["system_prompt_leak"]
    active: bool
    operation: Literal["add"]
    unicode_categories: list[str] = []
    named_classes: list[str] = []
    codepoints: list[str] = []


@dataclass(frozen=True)
class CompiledLeakPattern:
    """A validated pattern with its case-insensitive matcher compiled once."""

    definition: LeakPattern
    expression: re.Pattern[str]


class SystemPromptLeakDetector:
    """Detect and redact configured system-prompt patterns in model output."""

    detector_name = "system_prompt_leak"
    _separator_characters = frozenset(" \t\n\r-_.")

    def __init__(
        self,
        patterns: list[CompiledLeakPattern],
        promoted_normalizations: list[PromotedNormalization] | None = None,
    ) -> None:
        self._patterns = patterns
        active = [item for item in promoted_normalizations or [] if item.active]
        self._unicode_categories = frozenset(
            category for item in active for category in item.unicode_categories
        )
        self._named_classes = frozenset(
            named_class for item in active for named_class in item.named_classes
        )
        self._codepoints = frozenset(
            int(codepoint[2:], 16)
            for item in active
            for codepoint in item.codepoints
        )

    @classmethod
    def from_yaml(
        cls, patterns_path: Path, normalizations_path: Path | None = None
    ) -> "SystemPromptLeakDetector":
        """Load and compile detector-owned patterns once at Gate startup."""

        with patterns_path.open(encoding="utf-8") as patterns_file:
            raw_patterns = yaml.safe_load(patterns_file)

        definitions = TypeAdapter(list[LeakPattern]).validate_python(raw_patterns)
        promoted_normalizations: list[PromotedNormalization] = []
        if normalizations_path is not None and normalizations_path.exists():
            with normalizations_path.open(encoding="utf-8") as normalizations_file:
                raw_normalizations = yaml.safe_load(normalizations_file) or []
            promoted_normalizations = TypeAdapter(
                list[PromotedNormalization]
            ).validate_python(raw_normalizations)
        return cls.from_definitions(definitions, promoted_normalizations)

    @classmethod
    def from_definitions(
        cls,
        definitions: list[LeakPattern],
        promoted_normalizations: list[PromotedNormalization] | None = None,
    ) -> "SystemPromptLeakDetector":
        """Build a detector from validated definitions using Gate's live matcher logic."""

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
        return cls(patterns, promoted_normalizations)

    def _should_strip(self, character: str) -> bool:
        return (
            character in self._separator_characters
            or character.isspace()
            or unicodedata.category(character) in self._unicode_categories
            or (
                "unicode_whitespace" in self._named_classes
                and character.isspace()
            )
            or (
                "ascii_separators" in self._named_classes
                and character in self._separator_characters
            )
            or ord(character) in self._codepoints
        )

    def _strip_separators_with_index_map(self, content: str) -> tuple[str, list[int]]:
        """Build normalized text and map each normalized character to its source index."""

        normalized_characters: list[str] = []
        index_map: list[int] = []
        for original_index, character in enumerate(content):
            if self._should_strip(character):
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
