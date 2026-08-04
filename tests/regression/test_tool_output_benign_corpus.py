"""FP-rate measurement for tool-output PII scanning against real Presidio,
plus a mixed-script check against real LLM07 marker detection.

Separate from test_benign_corpus.py because that harness (evaluate_benign_cases)
is hardwired to the output-stage SystemPromptLeakDetector. This corpus
exercises the input-stage presidio_pii detector and the redact-input-pii
rule instead — the actual mechanism GATE_SCAN_TOOL_OUTPUT enables. The
mixed_script band is the exception: it also gets a dedicated LLM07 check
below, since it exists specifically to catch a false-positive class that
touches both detectors (see the band's header comment in the corpus file).
"""

from __future__ import annotations

import asyncio
import unittest
from collections import Counter
from pathlib import Path

from corpus import CORPUS_BAND_SETS, CORPUS_ROOT, assert_declared_codepoints, load_corpus
from detectors.presidio_pii import PresidioPiiDetector
from detectors.system_prompt_leak import SystemPromptLeakDetector
from policy.engine import PolicyEngine


TEST_MARKERS = {"sample-bank.internal_configuration_marker": "BASTION-CANARY-7K2M9QX4"}
TOOL_OUTPUT_BANDS = CORPUS_BAND_SETS["benign_tool_output.yaml"]


class ToolOutputBenignCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_corpus(CORPUS_ROOT / "benign_tool_output.yaml")
        cls.detector = PresidioPiiDetector.from_yaml(Path("gate/detectors/pii_entities.yaml"))
        cls.policy = PolicyEngine.from_yaml(Path("gate/policy/rules.yaml"))

    def test_fixed_band_manifest_and_utf8_codepoints(self) -> None:
        self.assertEqual(len(self.cases), 46)
        self.assertEqual(sum(case.band == "ordinary" for case in self.cases), 12)
        self.assertEqual(sum(case.band == "adjacent_vocabulary" for case in self.cases), 8)
        self.assertEqual(sum(case.band == "structurally_awkward" for case in self.cases), 8)
        self.assertEqual(sum(case.band == "redaction_span" for case in self.cases), 9)
        self.assertEqual(sum(case.band == "mixed_script" for case in self.cases), 9)
        assert_declared_codepoints(self.cases)

    def test_mixed_script_band_does_not_false_positive_on_llm07_confusables(self) -> None:
        """The Presidio FP check below cannot see this: genuine Cyrillic/Greek
        text run through SystemPromptLeakDetector's confusables skeleton
        mapping, checked against the real, live normalization_versions.yaml
        (not a temporary copy) — this is the permanent regression guard for
        the Step 3 mixed-script finding in
        docs/design/confusables-marker-normalization.md."""

        leak_detector = SystemPromptLeakDetector.from_yaml(
            Path("gate/detectors/leak_patterns.yaml"),
            Path("gate/detectors/normalization_versions.yaml"),
            Path("gate/detectors/pattern_versions.yaml"),
            marker_resolver=TEST_MARKERS.__getitem__,
        )

        async def exercise() -> None:
            for case in self.cases:
                if case.band != "mixed_script":
                    continue
                signal = await leak_detector.scan(case.payload)
                with self.subTest(case_id=case.id):
                    self.assertFalse(signal.matched, case.id)

        asyncio.run(exercise())

    def test_report_fp_rate_per_band(self) -> None:
        """Not a pass/fail gate — prints the measured FP rate per band.

        span-account-routing-001 was a measured false positive (a bank
        routing number misclassified as PHONE_NUMBER via the generic
        "number" context word) until the AbaRoutingRecognizer-based
        suppression in PresidioPiiDetector._scan_blocking was added: a
        checksum-validated ABA routing number match on the same span now
        excludes the overlapping PHONE_NUMBER candidate before thresholding.
        Asserted at zero explicitly, not just implied by the other bands'
        checks, so a regression here is unambiguous.
        """

        async def exercise() -> dict[str, tuple[int, int, list[str]]]:
            band_totals: dict[str, int] = {band: 0 for band in TOOL_OUTPUT_BANDS}
            band_mismatches: dict[str, list[str]] = {band: [] for band in TOOL_OUTPUT_BANDS}
            for case in self.cases:
                signal = await self.detector.scan(case.payload)
                evaluation = self.policy.evaluate([signal], stage="input")
                verdict = "allow" if not evaluation.matched_rules else str(evaluation.action)
                band_totals[case.band] += 1
                if verdict != case.expect:
                    band_mismatches[case.band].append(case.id)
                if case.expect == "redact" and verdict == "redact":
                    self.assertEqual(signal.redacted_content, case.expected_redacted_content)
            return {
                band: (band_totals[band], len(band_mismatches[band]), band_mismatches[band])
                for band in TOOL_OUTPUT_BANDS
            }

        results = asyncio.run(exercise())

        print("\n--- tool-output benign corpus: FP rate per band (flag ON, real Presidio) ---")
        for band, (total, mismatches, ids) in results.items():
            rate = mismatches / total if total else 0.0
            print(f"{band:24s} {mismatches}/{total} mismatched ({rate:.1%}) {ids}")

        # If this fails, either a genuinely new Presidio false positive was
        # introduced, or the corpus needs updating — either way, do not
        # loosen this assertion without reporting why.
        self.assertEqual(results["ordinary"][1], 0)
        self.assertEqual(results["adjacent_vocabulary"][1], 0)
        self.assertEqual(results["structurally_awkward"][1], 0)
        self.assertEqual(results["redaction_span"][1], 0)
        self.assertEqual(results["mixed_script"][1], 0)


if __name__ == "__main__":
    unittest.main()
