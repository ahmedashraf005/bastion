"""PromptGuard2 score measurement over a controlled serialization factorial.

MEASUREMENT ARTIFACT, NOT A REGRESSION SUITE. Same status as
test_tool_output_injection_corpus.py: no detector is wired to Gate's
tool-output path, so there is no live behavior to assert pass/fail against.
This file measures PromptGuard2's raw MALICIOUS-class score on every case in
tests/corpus/serialization_carriers.yaml, standalone (no Gate, no Docker, no
HTTP -- PromptGuardDetector is invoked directly), and prints per-case,
per-band, AND per-payload-across-carriers results -- the last of those is
the entire point of this corpus (see the corpus file's own header comment):
tool_output_injection.yaml's structured_smuggling band confounded
serialization with payload text, field name, and nesting depth; this corpus
holds everything but serialization constant so a bare-vs-wrapped delta can
actually be attributed to serialization alone. Asserts corpus
WELL-FORMEDNESS only -- never a detection outcome.
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


SERIALIZATION_CARRIERS_BANDS = CORPUS_BAND_SETS["serialization_carriers.yaml"]
# Same non-determinism reason as test_tool_output_injection_corpus.py:
# frozenset iteration order depends on PYTHONHASHSEED. Fixed, explicit
# order for reproducible printed output.
SERIALIZATION_CARRIERS_BAND_ORDER = ("bare", "json", "yaml", "xml", "csv", "key_value")
# Case ids encode which of the 3 constant payloads each case carries
# ("-high-"/"-mid-"/"-low-" per the corpus file's own naming), so scores can
# be regrouped by payload across all 6 carriers for the side-by-side
# comparison that is this corpus's whole purpose.
PAYLOAD_TIERS = ("high", "mid", "low")
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


def _payload_tier(case_id: str) -> str:
    for tier in PAYLOAD_TIERS:
        if f"-{tier}-" in case_id:
            return tier
    raise ValueError(f"case id {case_id!r} does not encode a known payload tier")


class SerializationCarriersCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_corpus(CORPUS_ROOT / "serialization_carriers.yaml")
        # Fail loudly, not silently, if PG2 cannot load -- no try/except,
        # no skip, no xfail. The real exception surfaces as-is.
        cls.detector = PromptGuardDetector.load()
        cls.threshold = _prompt_guard_threshold()

    def test_corpus_is_well_formed(self) -> None:
        """load_corpus() itself already enforces unique ids and a
        reconciled band_manifest (raises ValueError otherwise) -- this
        restates the expected shape as a readable assertion, and separately
        checks declared non-ASCII codepoints are byte-exact."""

        self.assertEqual(len(self.cases), 18)
        for band in SERIALIZATION_CARRIERS_BAND_ORDER:
            self.assertEqual(sum(case.band == band for case in self.cases), 3)
        ids = [case.id for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        for case in self.cases:
            self.assertEqual(case.expect, "block")
            self.assertNotEqual(case.band, "redaction_span")
        assert_declared_codepoints(self.cases)

    def test_bare_cases_match_baseline_corpus_payloads(self) -> None:
        """The "bare" band is byte-identical to
        tool_output_injection.yaml's do-001/do-008/do-006 by construction
        (see the corpus file's header comment) -- confirm that identity
        holds, independent of any score measurement."""

        baseline = {
            case.id: case
            for case in load_corpus(CORPUS_ROOT / "tool_output_injection.yaml")
        }
        bare_cases = {case.id: case for case in self.cases if case.band == "bare"}
        self.assertEqual(bare_cases["bare-high-001"].payload, baseline["do-001"].payload)
        self.assertEqual(bare_cases["bare-mid-001"].payload, baseline["do-008"].payload)
        self.assertEqual(bare_cases["bare-low-001"].payload, baseline["do-006"].payload)

    def test_measure_prompt_guard_scores(self) -> None:
        """Not a pass/fail gate. Runs real PromptGuard2 inference on every
        case's payload and prints per-case, per-band, and
        per-payload-across-carriers results. No assertion here concerns a
        detection outcome -- see the module docstring for why."""

        async def exercise() -> dict[str, float]:
            scores: dict[str, float] = {}
            for case in self.cases:
                signal = await self.detector.scan(case.payload)
                self.assertIsNotNone(signal.injection_score)
                scores[case.id] = signal.injection_score
            return scores

        scores = asyncio.run(exercise())

        by_band: dict[str, list[tuple[str, float]]] = {
            band: [] for band in SERIALIZATION_CARRIERS_BAND_ORDER
        }
        for case in self.cases:
            by_band[case.band].append((case.id, scores[case.id]))

        print(
            "\n--- serialization_carriers.yaml: PromptGuard2 raw score per case "
            f"(threshold={self.threshold}, model=meta-llama/Llama-Prompt-Guard-2-22M) ---"
        )
        for band in SERIALIZATION_CARRIERS_BAND_ORDER:
            for case_id, score in by_band[band]:
                print(f"  {band:10s} {case_id:16s} score={score:.4f}")

        print(
            "\n--- serialization_carriers.yaml: PromptGuard2 score summary per band "
            f"(threshold={self.threshold}) ---"
        )
        print(
            f"  {'band':10s} {'n':>3s} {'mean':>8s} {'median':>8s} "
            f"{'min':>8s} {'max':>8s} {'>=thresh':>9s}"
        )
        for band in SERIALIZATION_CARRIERS_BAND_ORDER:
            band_scores = [score for _, score in by_band[band]]
            n = len(band_scores)
            mean = statistics.mean(band_scores) if n else float("nan")
            median = statistics.median(band_scores) if n else float("nan")
            band_min = min(band_scores) if n else float("nan")
            band_max = max(band_scores) if n else float("nan")
            at_or_above = sum(1 for score in band_scores if score >= self.threshold)
            print(
                f"  {band:10s} {n:3d} {mean:8.4f} {median:8.4f} "
                f"{band_min:8.4f} {band_max:8.4f} {at_or_above:9d}"
            )

        # The per-payload breakdown is the entire point of this corpus: for
        # each of the 3 constant payloads, its score across all 6 carriers,
        # side by side, so a bare-vs-wrapped delta can be read directly.
        by_payload: dict[str, dict[str, float]] = {tier: {} for tier in PAYLOAD_TIERS}
        for case in self.cases:
            by_payload[_payload_tier(case.id)][case.band] = scores[case.id]

        print("\n--- serialization_carriers.yaml: per-payload score across all 6 carriers ---")
        header = "  {:5s}".format("tier") + "".join(
            f" {band:>10s}" for band in SERIALIZATION_CARRIERS_BAND_ORDER
        )
        print(header)
        for tier in PAYLOAD_TIERS:
            row = f"  {tier:5s}" + "".join(
                f" {by_payload[tier][band]:10.4f}" for band in SERIALIZATION_CARRIERS_BAND_ORDER
            )
            print(row)
            bare_score = by_payload[tier]["bare"]
            deltas = " ".join(
                f"{band}={by_payload[tier][band] - bare_score:+.4f}"
                for band in SERIALIZATION_CARRIERS_BAND_ORDER
                if band != "bare"
            )
            print(f"    delta vs bare: {deltas}")


if __name__ == "__main__":
    unittest.main()
