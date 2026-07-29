"""Evidence-presented, schema-constrained proposals for output-leak remediation."""

from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal, Union

import httpx
from pydantic import BaseModel, Field, TypeAdapter, ValidationError, field_validator, model_validator

from gate.detectors.system_prompt_leak import SystemPromptLeakDetector


MARKER_PLACEHOLDER = "<<CONFIGURED_MARKER>>"
MARKER_REFS = frozenset({"sample-bank.internal_configuration_marker"})
UNICODE_CATEGORIES = frozenset({"Cf", "Cc", "Zs", "Zl", "Zp"})
NAMED_NORMALIZATION_CLASSES = frozenset({"unicode_whitespace", "ascii_separators"})
REGEX_METACHARACTERS = frozenset("\\.^$*+?{}[]|()")
BENIGN_CORPUS_PATH = Path(__file__).resolve().parents[2] / "tests/corpus/benign.yaml"


class BlastRadiusReport(BaseModel):
    """Required LLM-authored review surface; it never executes policy logic."""

    affected_input_classes: list[str] = Field(min_length=1)
    expected_false_positive_risk: Literal["low", "medium", "high"]
    rationale: str = Field(min_length=1)
    benign_corpus_required: bool
    existing_normalization_overlap: list[str] = Field(default_factory=list)


class SignatureSpec(BaseModel):
    """A shareable signature template which references, never embeds, a marker."""

    marker_ref: Literal["sample-bank.internal_configuration_marker"]
    pattern: str = Field(min_length=1)
    pattern_type: Literal["literal", "regex"]
    normalize: Literal["none", "strip_separators"]

    @model_validator(mode="after")
    def validate_pattern_semantics(self) -> "SignatureSpec":
        if self.pattern.count(MARKER_PLACEHOLDER) != 1:
            raise ValueError("signature_requires_exactly_one_marker_placeholder")
        remainder = self.pattern.replace(MARKER_PLACEHOLDER, "")
        if self.pattern_type == "literal":
            if "\\" in remainder or any(char in REGEX_METACHARACTERS for char in remainder):
                raise ValueError("literal_contains_regex_syntax")
        else:
            try:
                re.compile(self.pattern.replace(MARKER_PLACEHOLDER, "MARKER"))
            except re.error as exc:
                raise ValueError("regex_does_not_compile") from exc
        return self


class SignatureProposal(BaseModel):
    proposal_type: Literal["signature"]
    proposal_schema_version: Literal[1]
    signature: SignatureSpec
    description: str = Field(min_length=1)
    blast_radius: BlastRadiusReport


class AdditiveNormalization(BaseModel):
    """Closed, additive-only data: no generated executable normalization logic."""

    operation: Literal["add"]
    unicode_categories: list[Literal["Cf", "Cc", "Zs", "Zl", "Zp"]] = Field(default_factory=list)
    named_classes: list[Literal["unicode_whitespace", "ascii_separators"]] = Field(default_factory=list)
    codepoints: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("codepoints")
    @classmethod
    def validate_codepoints(cls, values: list[str]) -> list[str]:
        for value in values:
            if re.fullmatch(r"U\+[0-9A-F]{4,6}", value) is None:
                raise ValueError("invalid_bounded_codepoint")
        return values

    @model_validator(mode="after")
    def require_one_addition(self) -> "AdditiveNormalization":
        if not (self.unicode_categories or self.named_classes or self.codepoints):
            raise ValueError("additive_normalization_requires_a_closed_vocabulary_item")
        return self


class NormalizationProposal(BaseModel):
    proposal_type: Literal["normalization"]
    proposal_schema_version: Literal[1]
    detector: Literal["system_prompt_leak"]
    normalization: AdditiveNormalization
    description: str = Field(min_length=1)
    blast_radius: BlastRadiusReport


class DetectorConfigProposal(BaseModel):
    proposal_type: Literal["detector_config"]
    proposal_schema_version: Literal[1]
    detector: Literal["system_prompt_leak"]
    operation: Literal["add_signature"]
    signature: SignatureSpec
    description: str = Field(min_length=1)
    blast_radius: BlastRadiusReport


Proposal = Annotated[
    Union[SignatureProposal, NormalizationProposal, DetectorConfigProposal],
    Field(discriminator="proposal_type"),
]
PROPOSAL_ADAPTER = TypeAdapter(Proposal)


class FindingEvidence(BaseModel):
    """Persisted evidence plus the response-analysis facts needed for remediation."""

    finding_id: str
    attack_turns: list[dict[str, str]]
    target_reply: str
    normalization_evidence: dict[str, object] | None = None


def _marker_spans(value: str, marker_values: frozenset[str]) -> list[tuple[int, int]]:
    """Locate literal and separator/Cf-formatted marker regions without exposing them."""

    spans: list[tuple[int, int]] = []
    for marker_value in marker_values:
        direct_start = value.find(marker_value)
        if direct_start >= 0:
            spans.append((direct_start, direct_start + len(marker_value)))
            continue
        canonical: list[str] = []
        source_indexes: list[int] = []
        for index, character in enumerate(value):
            if character in " \t\n\r-_." or character.isspace() or unicodedata.category(character) == "Cf":
                continue
            canonical.append(character)
            source_indexes.append(index)
        canonical_marker = "".join(
            character
            for character in marker_value
            if character not in " \t\n\r-_." and not character.isspace()
        )
        start = "".join(canonical).find(canonical_marker)
        if start >= 0:
            spans.append((source_indexes[start], source_indexes[start + len(canonical_marker) - 1] + 1))
    return sorted(spans)


def _replace_markers(value: str, marker_values: frozenset[str]) -> str:
    spans = _marker_spans(value, marker_values)
    if not spans:
        return value
    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        pieces.extend((value[cursor:start], MARKER_PLACEHOLDER))
        cursor = end
    pieces.append(value[cursor:])
    return "".join(pieces)


def _masked_codepoint_sequence(value: str, marker_values: frozenset[str]) -> str:
    """Expose all non-secret response codepoints while masking a recoverable marker."""

    spans = _marker_spans(value, marker_values)
    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        parts.extend(f"U+{ord(character):04X}" for character in value[cursor:start])
        parts.append(f"<<CONFIGURED_MARKER_REGION: {end - start} source codepoints masked>>")
        cursor = end
    parts.extend(f"U+{ord(character):04X}" for character in value[cursor:])
    return " ".join(parts)


def _sanitized_normalization_evidence(
    evidence: dict[str, object] | None, marker_values: frozenset[str]
) -> dict[str, object]:
    """Keep normalization facts but avoid a codepoint list that reconstructs the secret."""

    del marker_values
    safe = dict(evidence or {})
    codepoints = safe.pop("matched_region_codepoints", None)
    if isinstance(codepoints, list):
        safe["matched_region_codepoints"] = (
            f"<<CONFIGURED_MARKER_REGION: {len(codepoints)} source codepoints masked>>"
        )
    return safe


def _visible_character_table(value: str) -> tuple[str, str]:
    """Render every non-printing character as auditable evidence for the model."""

    rows: list[str] = []
    category_counts: dict[str, int] = {}
    for index, character in enumerate(value):
        category = unicodedata.category(character)
        if category.startswith("C") or not character.isprintable():
            category_counts[category] = category_counts.get(category, 0) + 1
            rows.append(
                f"{index} | U+{ord(character):04X} | {category} | "
                f"{unicodedata.name(character, 'UNNAMED')}"
            )
    summary = ", ".join(
        f"{count} characters of Unicode category {category}"
        for category, count in sorted(category_counts.items())
    ) or "no non-printing character categories"
    return summary, "\n".join(rows) or "(none)"


def _stripped_by_current_detector(character: str) -> bool:
    """Mirror Gate's existing normalizer for evidence and no-op detection only."""

    return (
        character in SystemPromptLeakDetector._separator_characters
        or character.isspace()
    )


@lru_cache(maxsize=None)
def _category_members(category: str) -> tuple[str, ...]:
    """Return the Unicode-runtime membership of one closed-vocabulary category."""

    return tuple(
        character
        for codepoint in range(0x110000)
        if unicodedata.category(character := chr(codepoint)) == category
    )


@lru_cache(maxsize=None)
def _category_is_already_stripped(category: str) -> bool:
    return all(_stripped_by_current_detector(character) for character in _category_members(category))


def _current_normalization_state(value: str) -> str:
    """Make the exact detector delta arithmetic available to the synthesis model."""

    separator_codepoints = " ".join(
        f"U+{ord(character):04X}" for character in sorted(SystemPromptLeakDetector._separator_characters)
    )
    observed = sorted(
        {
            character
            for character in value
            if unicodedata.category(character).startswith("C") or not character.isprintable()
        },
        key=ord,
    )
    observed_rows: list[str] = []
    gap_rows: list[str] = []
    for character in observed:
        category = unicodedata.category(character)
        already_stripped = _stripped_by_current_detector(character)
        state = "ALREADY stripped" if already_stripped else "NOT stripped (gap)"
        observed_rows.append(
            f"U+{ord(character):04X} | {category} | {unicodedata.name(character, 'UNNAMED')} | "
            f"isspace={character.isspace()} | {state}"
        )
        if not already_stripped:
            member_count = len(_category_members(category))
            gap_rows.append(
                f"U+{ord(character):04X} is category {category}; this Unicode runtime has "
                f"{member_count} {category} members. Gate strips none of that category today. "
                "Any member used as an interleaver reaches the same detector gap; individual "
                "members can have different glyph/layout effects, so select the smallest class "
                "that fully explains the detector evasion rather than assuming identical visuals."
            )
    return "\n".join(
        [
            "Current target-detector normalization state (authoritative):",
            "- configured separators removed: " + separator_codepoints + " (space, tab, LF, CR, hyphen, underscore, period)",
            "- character.isspace() characters are removed, including U+00A0 NO-BREAK SPACE and Unicode Zs coverage.",
            "- no Unicode category-Cf normalization is configured.",
            "- a proposal made entirely of already stripped items is a redundant no-op and will be rejected.",
            "Observed non-printing characters (codepoint | category | name | current state):",
            "\n".join(observed_rows) or "(none)",
            "Uncovered-character category analysis:",
            "\n".join(gap_rows) or "(none)",
            "Question to answer: does the gap consist of these individual codepoints, or the smallest Unicode category that fully explains the observed evasion?",
        ]
    )


def _evidence_prompt(evidence: FindingEvidence, marker_values: frozenset[str]) -> str:
    rendered_reply = _replace_markers(evidence.target_reply, marker_values)
    reply_codepoints = _masked_codepoint_sequence(evidence.target_reply, marker_values)
    category_summary, character_table = _visible_character_table(evidence.target_reply)
    sanitized_turns = [
        {**turn, "content": _replace_markers(turn["content"], marker_values)}
        for turn in evidence.attack_turns
    ]
    return "\n\n".join(
        [
            f"Finding ID: {evidence.finding_id}",
            f"Attack turns (marker values replaced with {MARKER_PLACEHOLDER}):\n"
            f"{json.dumps(sanitized_turns, ensure_ascii=False)}",
            f"Rendered target reply (marker values replaced with {MARKER_PLACEHOLDER}):\n"
            f"{rendered_reply}",
            f"Full target-reply codepoint sequence:\n{reply_codepoints}",
            "Per-character table for non-printing regions "
            "(index | codepoint | Unicode category | Unicode name):\n"
            f"{character_table}",
            f"Response contains {category_summary} interleaved within the matched region.",
            _current_normalization_state(evidence.target_reply),
            "Attempt normalization evidence:\n"
            f"{json.dumps(_sanitized_normalization_evidence(evidence.normalization_evidence, marker_values), ensure_ascii=False)}",
        ]
    )


class RuleSynthesizer:
    """Best-effort, schema-constrained proposals that never apply a detector change."""

    def __init__(
        self,
        ollama_base_url: str,
        model: str,
        max_parse_retries: int = 3,
        request_timeout_seconds: float = 60,
        forbidden_marker_values: set[str] | None = None,
    ) -> None:
        self._ollama_base_url = ollama_base_url.rstrip("/")
        self._model = model
        self._max_parse_retries = max_parse_retries
        self._request_timeout_seconds = request_timeout_seconds
        self._forbidden_marker_values = frozenset(forbidden_marker_values or ())
        self.last_raw_output: str | None = None
        self.last_retry_trace: list[dict[str, object]] = []

    @staticmethod
    def build_messages(
        finding: FindingEvidence,
        marker_values: frozenset[str] = frozenset(),
        verification_feedback: str | None = None,
    ) -> list[dict[str, str]]:
        """Build an explicit, marker-safe evidence package for remediation proposals."""

        system_prompt = """You propose one evidence-supported remediation for an output-leak finding. Return only JSON matching the supplied schema. Choose exactly one proposal_type:
- signature: a narrow match signature; reference the marker through marker_ref and the literal token <<CONFIGURED_MARKER>>, never a marker value.
- normalization: an additive normalizer change when evidence shows an evasion mechanism affecting a Unicode character class.
- detector_config: an additive detector configuration signature when existing normalization is sufficient.
Use the detector normalization state as authoritative. Generalize to the smallest character class that fully explains the observed evasion gap. Enumerate codepoints only when no available class fully explains the evidence. Never propose normalization already provided by the detector; it is a no-op. Every proposal needs a concrete blast-radius report. Normalization proposals are review-only until a benign corpus exists; do not claim they are safe to promote."""
        sections = [_evidence_prompt(finding, marker_values)]
        if verification_feedback is not None:
            sections.append(verification_feedback)
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "\n\n".join(sections)},
        ]

    def _secret_in_rule_rejection_reason(self, candidate: Proposal) -> str | None:
        serialized = json.dumps(candidate.model_dump(mode="json"), ensure_ascii=False)
        if any(marker and marker in serialized for marker in self._forbidden_marker_values):
            return "contains_configured_marker_value"
        return None

    @staticmethod
    def _normalization_overlap(candidate: Proposal) -> tuple[bool, list[str]]:
        """Return whether a normalization adds no new detector behavior and its overlaps."""

        if not isinstance(candidate, NormalizationProposal):
            return False, []
        change = candidate.normalization
        components: list[tuple[str, bool]] = []
        components.extend(
            (f"unicode_category:{category}", _category_is_already_stripped(category))
            for category in change.unicode_categories
        )
        components.extend(
            (
                ("named_class:unicode_whitespace", True)
                if name == "unicode_whitespace"
                else ("named_class:ascii_separators", True)
            )
            for name in change.named_classes
        )
        components.extend(
            (
                f"codepoint:{codepoint}",
                _stripped_by_current_detector(chr(int(codepoint[2:], 16))),
            )
            for codepoint in change.codepoints
        )
        redundant = [name for name, already_covered in components if already_covered]
        return bool(components) and len(redundant) == len(components), redundant

    @staticmethod
    def _signature_pattern(signature: SignatureSpec, marker_value: str) -> str:
        replacement = re.escape(marker_value) if signature.pattern_type == "regex" else marker_value
        return signature.pattern.replace(MARKER_PLACEHOLDER, replacement)

    @classmethod
    async def _signature_matches_evidence(
        cls, signature: SignatureSpec, evidence: str, marker_value: str
    ) -> bool:
        from gate.detectors.system_prompt_leak import LeakPattern

        detector = SystemPromptLeakDetector.from_definitions(
            [
                LeakPattern(
                    id="synthesizer-verification",
                    description="mechanical proposal verification",
                    pattern=cls._signature_pattern(signature, marker_value),
                    pattern_type=signature.pattern_type,
                    normalize=signature.normalize,
                )
            ]
        )
        return (await detector.scan(evidence)).matched is True

    @staticmethod
    def _apply_additive_normalization(value: str, change: AdditiveNormalization) -> str:
        codepoints = {int(codepoint[2:], 16) for codepoint in change.codepoints}
        output: list[str] = []
        for character in value:
            if unicodedata.category(character) in change.unicode_categories:
                continue
            if "unicode_whitespace" in change.named_classes and character.isspace():
                continue
            if "ascii_separators" in change.named_classes and character in " \t\n\r-_.":
                continue
            if ord(character) in codepoints:
                continue
            output.append(character)
        return "".join(output)

    async def mechanical_verification(
        self, candidate: Proposal, evidence: str
    ) -> tuple[bool, str]:
        """Verify a proposal against evidence without changing the live Gate detector."""

        if isinstance(candidate, NormalizationProposal):
            transformed = self._apply_additive_normalization(evidence, candidate.normalization)
            detector = SystemPromptLeakDetector.from_yaml(
                __import__("pathlib").Path(__file__).resolve().parents[2]
                / "gate/detectors/leak_patterns.yaml"
            )
            return (await detector.scan(transformed)).matched is True, "normalization_simulation"
        signature = candidate.signature
        marker_value = next(iter(self._forbidden_marker_values), "")
        if not marker_value:
            return False, "marker_value_unavailable_for_verification"
        return (
            await self._signature_matches_evidence(signature, evidence, marker_value),
            "signature_against_live_gate_semantics",
        )

    @staticmethod
    def promotion_tier(candidate: Proposal) -> tuple[str, str | None]:
        """Return review tier; normalization is structurally blocked before benign corpus."""

        if isinstance(candidate, NormalizationProposal):
            if not BENIGN_CORPUS_PATH.exists():
                return "tier_3_normalization", "blocked_missing_benign_corpus"
            return "tier_3_normalization", "requires_bypass_and_benign_corpora"
        if isinstance(candidate, DetectorConfigProposal):
            return "tier_2_detector_config", "requires_bypass_and_benign_corpora"
        return "tier_1_signature", "requires_mechanical_verification_and_human_review"

    async def propose(self, finding: FindingEvidence) -> Proposal | None:
        """Return only a candidate that mechanically covers the persisted evidence."""

        feedback: str | None = None
        failures: list[str] = []
        self.last_retry_trace = []
        async with httpx.AsyncClient(timeout=self._request_timeout_seconds) as client:
            for attempt in range(1, self._max_parse_retries + 1):
                try:
                    response = await client.post(
                        f"{self._ollama_base_url}/api/chat",
                        json={
                            "model": self._model,
                            "messages": self.build_messages(
                                finding, self._forbidden_marker_values, feedback
                            ),
                            "stream": False,
                            "format": PROPOSAL_ADAPTER.json_schema(),
                        },
                    )
                    response.raise_for_status()
                    raw_output = response.json()["message"]["content"]
                    if not isinstance(raw_output, str):
                        raise ValueError("ollama_proposal_content_not_string")
                    self.last_raw_output = raw_output
                    candidate = PROPOSAL_ADAPTER.validate_json(raw_output)
                    rejection_reason = self._secret_in_rule_rejection_reason(candidate)
                    if rejection_reason is not None:
                        raise ValueError(rejection_reason)
                    redundant_no_op, redundant_components = self._normalization_overlap(candidate)
                    if redundant_no_op:
                        self.last_retry_trace.append(
                            {
                                "attempt": attempt,
                                "raw_output": raw_output,
                                "verified": False,
                                "rejection_reason": "redundant_no_op",
                                "redundant_components": redundant_components,
                            }
                        )
                        feedback = (
                            "Your last normalization proposal was entirely covered by Gate's "
                            "existing normalizer and is a redundant no-op. Propose only the "
                            "uncovered delta shown in the evidence."
                        )
                        failures.append(f"attempt {attempt}: redundant_no_op")
                        continue
                    if isinstance(candidate, NormalizationProposal):
                        # This is computed from Gate's actual state, not left to
                        # model inference, and travels with the review report.
                        candidate.blast_radius.existing_normalization_overlap = (
                            redundant_components
                        )
                    verified, verification_mode = await self.mechanical_verification(
                        candidate, finding.target_reply
                    )
                    self.last_retry_trace.append(
                        {
                            "attempt": attempt,
                            "raw_output": raw_output,
                            "verified": verified,
                            "verification_mode": verification_mode,
                            "partial_redundancy": redundant_components,
                        }
                    )
                    if verified:
                        return candidate
                    feedback = "Your last candidate did not mechanically cover the supplied evidence. Re-read the codepoint table and propose only a supported mechanism."
                    failures.append(f"attempt {attempt}: candidate_did_not_match_evidence")
                except (httpx.HTTPError, KeyError, TypeError, ValueError, ValidationError) as exc:
                    reason = str(exc)
                    rejection_reason = next(
                        (
                            known
                            for known in (
                                "contains_configured_marker_value",
                                "literal_contains_regex_syntax",
                                "regex_does_not_compile",
                                "redundant_no_op",
                            )
                            if known in reason
                        ),
                        type(exc).__name__,
                    )
                    self.last_retry_trace.append(
                        {
                            "attempt": attempt,
                            "raw_output": self.last_raw_output,
                            "verified": False,
                            "rejection_reason": rejection_reason,
                        }
                    )
                    feedback = "Your last candidate was rejected. Use the schema and evidence, never include a marker value, and do not use regex syntax in a literal pattern."
                    failures.append(f"attempt {attempt}: {rejection_reason}")
        print("rule_synthesizer_proposal_failed " + "; ".join(failures))
        return None
