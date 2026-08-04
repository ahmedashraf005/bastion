"""UTF-8-preserving corpus loader and Gate-policy evaluation helpers."""

from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml

from detectors.system_prompt_leak import SystemPromptLeakDetector
from policy.engine import PolicyEngine


CORPUS_ROOT = Path(__file__).resolve().parents[1] / "corpus"
BENIGN_BANDS = frozenset(
    {"ordinary", "adjacent_vocabulary", "structurally_awkward", "redaction_span"}
)
# Per-file band sets. benign_tool_output.yaml additionally carries
# mixed_script: genuine non-Latin/mixed-script content, the one
# false-positive class benign.yaml (English-only) is structurally blind to.
# Band assignment for any file here must be fixed at authoring time, same
# rule as benign.yaml itself.
#
# tool_output_injection.yaml is NOT a benign corpus (every case has
# expect: block) and is NOT a regression suite with pass/fail assertions —
# see its own header comment. It rides this same loader purely for its
# band/manifest validation; it deliberately avoids the band name
# "redaction_span" so the expected_redacted_content coupling below (tied to
# that literal band name, not to any general concept) stays inert for it.
CORPUS_BAND_SETS: dict[str, frozenset[str]] = {
    "benign.yaml": BENIGN_BANDS,
    "benign_tool_output.yaml": BENIGN_BANDS | frozenset({"mixed_script"}),
    "tool_output_injection.yaml": frozenset(
        {
            "direct_override",
            "captured_transcript",
            "structured_smuggling",
            "document_content",
            "error_and_metadata",
        }
    ),
}
BANDED_CORPUS_FILENAMES = frozenset(CORPUS_BAND_SETS)


@dataclass(frozen=True)
class CorpusCase:
    id: str
    band: str | None
    expect: str
    payload: str
    payload_codepoints: str | None
    provenance: dict[str, object]
    override_justification: str | None
    expected_redacted_content: str | None


def _declared_codepoints(value: str | None) -> list[str]:
    if value is None:
        return []
    return re.findall(r"U\+[0-9A-F]{4,6}", value)


def actual_non_ascii_codepoints(payload: str) -> list[str]:
    """Return the exact non-ASCII source sequence without normalization."""

    return [f"U+{ord(character):04X}" for character in payload if ord(character) > 0x7F]


def load_corpus(path: Path) -> list[CorpusCase]:
    """Load one versioned corpus as UTF-8 and reject malformed policy metadata."""

    with path.open(encoding="utf-8") as corpus_file:
        raw = yaml.safe_load(corpus_file)
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise ValueError(f"{path}: expected corpus version 1")
    raw_cases = raw.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError(f"{path}: cases must be a list")
    expected_bands = CORPUS_BAND_SETS.get(path.name)
    cases: list[CorpusCase] = []
    seen_ids: set[str] = set()
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise ValueError(f"{path}: each case must be a mapping")
        case_id = raw_case.get("id")
        payload = raw_case.get("payload")
        provenance = raw_case.get("provenance")
        if not isinstance(case_id, str) or not case_id or case_id in seen_ids:
            raise ValueError(f"{path}: each case needs a unique id")
        if not isinstance(payload, str):
            raise ValueError(f"{path}: {case_id}: payload must be a string")
        if not isinstance(provenance, dict) or not provenance.get("author") or not provenance.get("authored"):
            raise ValueError(f"{path}: {case_id}: provenance needs author and authored")
        band = raw_case.get("band")
        if expected_bands is not None and band not in expected_bands:
            raise ValueError(f"{path}: {case_id}: invalid benign band")
        override = raw_case.get("override")
        justification = override.get("justification") if isinstance(override, dict) else None
        if override is not None and (band != "structurally_awkward" or not isinstance(justification, str) or not justification.strip()):
            raise ValueError(f"{path}: {case_id}: invalid false-positive override")
        expected_redacted_content = raw_case.get("expected_redacted_content")
        if expected_redacted_content is not None and not isinstance(expected_redacted_content, str):
            raise ValueError(f"{path}: {case_id}: expected_redacted_content must be a string")
        if expected_bands is not None and band == "redaction_span":
            if raw_case.get("expect") == "redact" and expected_redacted_content is None:
                raise ValueError(f"{path}: {case_id}: redact span case requires expected_redacted_content")
            if raw_case.get("expect") == "allow" and expected_redacted_content is not None:
                raise ValueError(f"{path}: {case_id}: allow span case must not define expected_redacted_content")
        cases.append(
            CorpusCase(
                id=case_id,
                band=band if isinstance(band, str) else None,
                expect=raw_case.get("expect", ""),
                payload=payload,
                payload_codepoints=raw_case.get("payload_codepoints"),
                provenance=provenance,
                override_justification=justification,
                expected_redacted_content=expected_redacted_content,
            )
        )
        seen_ids.add(case_id)
    if expected_bands is not None:
        manifest = raw.get("band_manifest")
        if not isinstance(manifest, dict) or set(manifest) != expected_bands:
            raise ValueError(f"{path}: benign corpus requires a complete band_manifest")
        if any(type(count) is not int or count < 0 for count in manifest.values()):
            raise ValueError(f"{path}: band_manifest counts must be non-negative integers")
        actual_counts = Counter(case.band for case in cases)
        declared_counts = {band: manifest[band] for band in expected_bands}
        if actual_counts != declared_counts:
            raise ValueError(
                f"{path}: band_manifest {declared_counts} != actual {dict(actual_counts)}"
            )
    return cases


def assert_declared_codepoints(cases: list[CorpusCase]) -> None:
    """Fail if YAML decoding, editing, or copy/paste changed a non-ASCII payload."""

    for case in cases:
        actual = actual_non_ascii_codepoints(case.payload)
        declared = _declared_codepoints(case.payload_codepoints)
        if actual != declared:
            raise AssertionError(
                f"{case.id}: declared non-ASCII codepoints {declared} != actual {actual}"
            )


@dataclass(frozen=True)
class BandResults:
    total: int
    false_positives: int
    overrides: int

    @property
    def fp_rate(self) -> float:
        return self.false_positives / self.total if self.total else 0.0


async def evaluate_benign_cases(
    cases: list[CorpusCase],
    detector: SystemPromptLeakDetector,
    policy: PolicyEngine,
    transform: Callable[[str], str] | None = None,
) -> tuple[dict[str, BandResults], dict[str, str]]:
    """Evaluate exact payloads with Gate's detector and output policy implementation."""

    counts: dict[str, Counter[str]] = {band: Counter() for band in BENIGN_BANDS}
    verdicts: dict[str, str] = {}
    for case in cases:
        assert case.band is not None
        comparison_payload = transform(case.payload) if transform is not None else case.payload
        signal = await detector.scan(comparison_payload)
        evaluation = policy.evaluate([signal], stage="output")
        verdict = "allow" if not evaluation.matched_rules else str(evaluation.action)
        verdicts[case.id] = verdict
        counts[case.band]["total"] += 1
        if verdict != case.expect:
            if case.band == "structurally_awkward" and case.override_justification:
                counts[case.band]["overrides"] += 1
            else:
                counts[case.band]["false_positives"] += 1
    return (
        {
            band: BandResults(
                total=counts[band]["total"],
                false_positives=counts[band]["false_positives"],
                overrides=counts[band]["overrides"],
            )
            for band in BENIGN_BANDS
        },
        verdicts,
    )
