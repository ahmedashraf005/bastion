"""PromptGuard2 score measurement over a tool-output-shaped injection corpus.

MEASUREMENT ARTIFACT, NOT A REGRESSION SUITE. No detector is currently wired
to Gate's tool-output path (confirmed: PromptGuardDetector never receives
tool-role content in gate/app/main.py — see docs/threat-model.md, "Indirect
prompt-injection boundary"). There is therefore no live behavior to assert
pass/fail against yet. This file measures PromptGuard2's raw MALICIOUS-class
score on every case in tests/corpus/tool_output_injection.yaml, standalone
(no Gate, no Docker, no HTTP — PromptGuardDetector is invoked directly), and
prints per-case and per-band results so the raw numbers are recoverable from
CI/local output. It asserts corpus WELL-FORMEDNESS only (loads, unique ids,
manifest reconciles, declared codepoints byte-exact) — never a detection
outcome. Detection-outcome assertions get added when a detector is actually
wired to this path, not before; wiring one is out of scope here and requires
separate sign-off (see docs/threat-model.md's tool-output-injection design
note).
"""

from __future__ import annotations

import asyncio
import statistics
import unittest
from pathlib import Path

import yaml

from tests import _pathfix  # noqa: F401
from corpus import CORPUS_BAND_SETS, CORPUS_ROOT, assert_declared_codepoints, load_corpus
from detectors.prompt_guard import PromptGuardDetector


TOOL_OUTPUT_INJECTION_BANDS = CORPUS_BAND_SETS["tool_output_injection.yaml"]
# CORPUS_BAND_SETS values are frozensets: fine for membership/manifest
# validation, but frozenset iteration order depends on PYTHONHASHSEED and is
# NOT stable across process runs (confirmed: two consecutive runs printed
# identical scores in different band order). Iterate this fixed, explicit
# sequence for the printed report instead, so output order is reproducible
# run to run -- matches the corpus file's own band_manifest declaration
# order.
TOOL_OUTPUT_INJECTION_BAND_ORDER = (
    "direct_override",
    "captured_transcript",
    "structured_smuggling",
    "document_content",
    "error_and_metadata",
)
RULES_PATH = Path(__file__).resolve().parents[2] / "gate/policy/rules.yaml"


def _prompt_guard_threshold() -> float:
    """Read the live block threshold for prompt_guard_2 directly from
    gate/policy/rules.yaml, rather than hardcoding it, so this measurement
    stays honest if the threshold ever changes."""

    with RULES_PATH.open(encoding="utf-8") as rules_file:
        rules = yaml.safe_load(rules_file)
    for rule in rules:
        if rule.get("detector") == "prompt_guard_2" and rule.get("matcher_type") == "threshold":
            return float(rule["matcher_config"]["threshold"])
    raise RuntimeError(f"{RULES_PATH}: no threshold rule found for prompt_guard_2")


class ToolOutputInjectionCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_corpus(CORPUS_ROOT / "tool_output_injection.yaml")
        # Fail loudly, not silently, if PG2 cannot load (missing HF_TOKEN,
        # missing/corrupt cache, network failure for an uncached model,
        # etc.) — no try/except, no skip, no xfail. The real exception
        # surfaces as-is.
        cls.detector = PromptGuardDetector.load()
        cls.threshold = _prompt_guard_threshold()

    def test_corpus_is_well_formed(self) -> None:
        """load_corpus() itself already enforces unique ids and a
        reconciled band_manifest (raises ValueError otherwise) -- this
        restates the expected shape as a readable assertion, and separately
        checks declared non-ASCII codepoints are byte-exact."""

        self.assertEqual(len(self.cases), 44)
        self.assertEqual(sum(case.band == "direct_override" for case in self.cases), 8)
        self.assertEqual(sum(case.band == "captured_transcript" for case in self.cases), 10)
        self.assertEqual(sum(case.band == "structured_smuggling" for case in self.cases), 10)
        self.assertEqual(sum(case.band == "document_content" for case in self.cases), 8)
        self.assertEqual(sum(case.band == "error_and_metadata" for case in self.cases), 8)
        ids = [case.id for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        for case in self.cases:
            self.assertEqual(case.expect, "block")
            self.assertNotEqual(case.band, "redaction_span")
        assert_declared_codepoints(self.cases)

    def test_measure_prompt_guard_scores(self) -> None:
        """Not a pass/fail gate. Runs real PromptGuard2 inference on every
        case's payload and prints per-case and per-band results. No
        assertion here concerns a detection outcome -- see the module
        docstring for why."""

        async def exercise() -> dict[str, float]:
            scores: dict[str, float] = {}
            for case in self.cases:
                signal = await self.detector.scan(case.payload)
                self.assertIsNotNone(signal.injection_score)
                scores[case.id] = signal.injection_score
            return scores

        scores = asyncio.run(exercise())

        by_band: dict[str, list[tuple[str, float]]] = {band: [] for band in TOOL_OUTPUT_INJECTION_BANDS}
        for case in self.cases:
            by_band[case.band].append((case.id, scores[case.id]))

        print(
            "\n--- tool_output_injection.yaml: PromptGuard2 raw score per case "
            f"(threshold={self.threshold}, model=meta-llama/Llama-Prompt-Guard-2-22M) ---"
        )
        for band in TOOL_OUTPUT_INJECTION_BAND_ORDER:
            for case_id, score in by_band[band]:
                print(f"  {band:22s} {case_id:12s} score={score:.4f}")

        print(
            "\n--- tool_output_injection.yaml: PromptGuard2 score summary per band "
            f"(threshold={self.threshold}) ---"
        )
        print(
            f"  {'band':22s} {'n':>3s} {'mean':>8s} {'median':>8s} "
            f"{'min':>8s} {'max':>8s} {'>=thresh':>9s}"
        )
        for band in TOOL_OUTPUT_INJECTION_BAND_ORDER:
            band_scores = [score for _, score in by_band[band]]
            n = len(band_scores)
            mean = statistics.mean(band_scores) if n else float("nan")
            median = statistics.median(band_scores) if n else float("nan")
            band_min = min(band_scores) if n else float("nan")
            band_max = max(band_scores) if n else float("nan")
            at_or_above = sum(1 for score in band_scores if score >= self.threshold)
            print(
                f"  {band:22s} {n:3d} {mean:8.4f} {median:8.4f} "
                f"{band_min:8.4f} {band_max:8.4f} {at_or_above:9d}"
            )


if __name__ == "__main__":
    unittest.main()
