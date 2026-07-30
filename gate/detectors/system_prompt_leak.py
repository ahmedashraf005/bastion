"""Pattern-based detector for system-prompt values leaked in model output."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Callable, Literal, Mapping
import unicodedata

import yaml
from pydantic import BaseModel, TypeAdapter, model_validator

from .base import DetectorSignal


class LeakPattern(BaseModel):
    """One detector-owned definition of a value that must not reach clients."""

    id: str
    description: str
    pattern: str | None = None
    pattern_type: Literal["literal", "regex", "marker_ref"]
    normalize: Literal["none", "strip_separators"] = "none"
    marker_ref: str | None = None
    max_source_span: int | None = None

    @model_validator(mode="after")
    def validate_pattern_contract(self) -> "LeakPattern":
        """Reject ambiguous secret-bearing and non-secret pattern definitions."""

        if self.pattern_type == "marker_ref":
            if not self.marker_ref or self.pattern is not None:
                raise ValueError("marker_ref patterns require marker_ref and forbid pattern")
            if self.max_source_span is None or self.max_source_span <= 0:
                raise ValueError("marker_ref patterns require max_source_span > 0")
        elif not self.pattern:
            raise ValueError(f"{self.pattern_type} patterns require pattern")
        elif self.marker_ref is not None or self.max_source_span is not None:
            raise ValueError("literal and regex patterns cannot declare marker_ref settings")
        return self


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


class DetectorPatternVersion(BaseModel):
    """One individually reversible replacement of a detector pattern."""

    version_id: str
    proposal_id: str
    origin_finding_id: str
    detector: Literal["system_prompt_leak"]
    active: bool
    operation: Literal["replace"]
    replaces_pattern_id: str
    replacement: LeakPattern
    window_rationale: str
    known_residual: str

    @model_validator(mode="after")
    def validate_replacement(self) -> "DetectorPatternVersion":
        if self.replacement.pattern_type != "marker_ref":
            raise ValueError("pattern-version replacement must be marker_ref")
        return self


@dataclass(frozen=True)
class CompiledLeakPattern:
    """A validated pattern with its case-insensitive matcher compiled once."""

    definition: LeakPattern
    expression: re.Pattern[str] | None = None
    marker: "ResolvedMarker" | None = None


@dataclass(frozen=True)
class ResolvedMarker:
    """A secret value held only in Gate process memory for value comparison."""

    marker_ref: str
    comparison_value: str
    marker_alphanumerics: frozenset[str]
    max_source_span: int


class MarkerReferenceResolver:
    """Resolve marker values from a mounted JSON secret file or env override."""

    def __init__(
        self,
        *,
        secrets_file: Path | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._environment = environment if environment is not None else os.environ
        self._file_values = self._load_file_values(secrets_file)

    @staticmethod
    def _load_file_values(secrets_file: Path | None) -> dict[str, str]:
        if secrets_file is None:
            return {}
        try:
            with secrets_file.open(encoding="utf-8") as secret_file:
                raw_values = json.load(secret_file)
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("gate marker secrets file could not be loaded") from exc
        if not isinstance(raw_values, dict) or not all(
            isinstance(reference, str) and isinstance(value, str) and value
            for reference, value in raw_values.items()
        ):
            raise RuntimeError("gate marker secrets file must be a JSON object of non-empty strings")
        return dict(raw_values)

    @staticmethod
    def environment_name(marker_ref: str) -> str:
        """Map a non-sensitive reference to its explicit local override name."""

        normalized = re.sub(r"[^A-Za-z0-9]", "_", marker_ref).upper()
        return f"GATE_MARKER_{normalized}"

    def resolve(self, marker_ref: str) -> str:
        """Return a secret without ever including it in a log or exception."""

        environment_value = self._environment.get(self.environment_name(marker_ref))
        if environment_value:
            return environment_value
        file_value = self._file_values.get(marker_ref)
        if file_value:
            return file_value
        raise RuntimeError(f"gate marker_ref unresolved: {marker_ref}")


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
        cls,
        patterns_path: Path,
        normalizations_path: Path | None = None,
        pattern_versions_path: Path | None = None,
        *,
        marker_resolver: Callable[[str], str] | None = None,
    ) -> "SystemPromptLeakDetector":
        """Load and compile detector-owned patterns once at Gate startup."""

        with patterns_path.open(encoding="utf-8") as patterns_file:
            raw_patterns = yaml.safe_load(patterns_file)

        definitions = TypeAdapter(list[LeakPattern]).validate_python(raw_patterns)
        if pattern_versions_path is not None and pattern_versions_path.exists():
            with pattern_versions_path.open(encoding="utf-8") as versions_file:
                raw_versions = yaml.safe_load(versions_file) or []
            versions = TypeAdapter(list[DetectorPatternVersion]).validate_python(
                raw_versions
            )
            definitions = cls._apply_active_pattern_versions(definitions, versions)
        promoted_normalizations: list[PromotedNormalization] = []
        if normalizations_path is not None and normalizations_path.exists():
            with normalizations_path.open(encoding="utf-8") as normalizations_file:
                raw_normalizations = yaml.safe_load(normalizations_file) or []
            promoted_normalizations = TypeAdapter(
                list[PromotedNormalization]
            ).validate_python(raw_normalizations)
        return cls.from_definitions(
            definitions,
            promoted_normalizations,
            marker_resolver=marker_resolver,
        )

    @staticmethod
    def _apply_active_pattern_versions(
        definitions: list[LeakPattern], versions: list[DetectorPatternVersion]
    ) -> list[LeakPattern]:
        """Apply ordered, active replacements while preserving inactive baselines."""

        effective = list(definitions)
        for version in versions:
            if not version.active:
                continue
            indexes = [
                index
                for index, definition in enumerate(effective)
                if definition.id == version.replaces_pattern_id
            ]
            if len(indexes) != 1:
                raise RuntimeError(
                    "active detector pattern version cannot replace baseline pattern: "
                    f"{version.replaces_pattern_id}"
                )
            effective[indexes[0]] = version.replacement
        return effective

    @classmethod
    def from_definitions(
        cls,
        definitions: list[LeakPattern],
        promoted_normalizations: list[PromotedNormalization] | None = None,
        *,
        marker_resolver: Callable[[str], str] | None = None,
    ) -> "SystemPromptLeakDetector":
        """Build a detector from validated definitions using Gate's live matcher logic."""

        patterns: list[CompiledLeakPattern] = []
        for definition in definitions:
            if definition.pattern_type == "marker_ref":
                if marker_resolver is None or definition.marker_ref is None:
                    raise RuntimeError(
                        f"gate marker_ref unresolved: {definition.marker_ref or definition.id}"
                    )
                resolved_value = marker_resolver(definition.marker_ref)
                comparison_value = "".join(
                    character
                    for character in resolved_value
                    if character not in cls._separator_characters
                )
                if not comparison_value:
                    raise RuntimeError(
                        f"gate marker_ref resolved to an empty comparison value: {definition.marker_ref}"
                    )
                patterns.append(
                    CompiledLeakPattern(
                        definition=definition,
                        marker=ResolvedMarker(
                            marker_ref=definition.marker_ref,
                            comparison_value=comparison_value,
                            marker_alphanumerics=frozenset(
                                character.upper()
                                for character in comparison_value
                                if character.isascii() and character.isalnum()
                            ),
                            max_source_span=definition.max_source_span or 0,
                        ),
                    )
                )
                continue
            assert definition.pattern is not None
            patterns.append(
                CompiledLeakPattern(
                    definition=definition,
                    expression=re.compile(
                        re.escape(definition.pattern)
                        if definition.pattern_type == "literal"
                        else definition.pattern,
                        re.IGNORECASE,
                    ),
                )
            )
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
    def _marker_char_equal(character: str, expected: str) -> bool:
        """Compare ASCII marker letters without Unicode case-folding."""

        if expected.isascii() and expected.isalpha():
            return character.isascii() and character.upper() == expected.upper()
        return character == expected

    @staticmethod
    def _allowed_marker_interleaver(character: str, marker: ResolvedMarker) -> bool:
        """Allow formatting, but never skip an ASCII marker-alphabet character."""

        return not (
            character.isascii()
            and character.isalnum()
            and character.upper() in marker.marker_alphanumerics
        )

    def _marker_ref_spans(self, content: str, marker: ResolvedMarker) -> list[tuple[int, int]]:
        """Find bounded raw-index marker presentations without global extraction."""

        spans: list[tuple[int, int]] = []
        needle = marker.comparison_value
        for start, character in enumerate(content):
            if not self._marker_char_equal(character, needle[0]):
                continue
            cursor = start + 1
            matched = True
            for expected in needle[1:]:
                while (
                    cursor < len(content)
                    and cursor - start < marker.max_source_span
                    and not self._marker_char_equal(content[cursor], expected)
                ):
                    if not self._allowed_marker_interleaver(content[cursor], marker):
                        matched = False
                        break
                    cursor += 1
                if (
                    not matched
                    or cursor >= len(content)
                    or cursor - start >= marker.max_source_span
                ):
                    matched = False
                    break
                cursor += 1
            if matched and cursor - start <= marker.max_source_span:
                spans.append((start, cursor))
        return spans

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
            if pattern.definition.pattern_type == "marker_ref":
                assert pattern.marker is not None
                pattern_spans = self._marker_ref_spans(content, pattern.marker)
            elif pattern.definition.normalize == "strip_separators":
                if normalized_content is None or index_map is None:
                    normalized_content, index_map = self._strip_separators_with_index_map(
                        content
                    )
                assert pattern.expression is not None
                matches = list(pattern.expression.finditer(normalized_content))
                pattern_spans = [
                    (index_map[match.start()], index_map[match.end() - 1] + 1)
                    for match in matches
                    if match.end() > match.start()
                ]
            else:
                assert pattern.expression is not None
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
