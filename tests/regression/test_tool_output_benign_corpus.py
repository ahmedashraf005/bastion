"""FP-rate measurement for tool-output PII scanning against real Presidio.

Separate from test_benign_corpus.py because that harness (evaluate_benign_cases)
is hardwired to the output-stage SystemPromptLeakDetector. This corpus
exercises the input-stage presidio_pii detector and the redact-input-pii
rule instead — the actual mechanism GATE_SCAN_TOOL_OUTPUT enables.
"""

from __future__ import annotations

import asyncio
import unittest
from collections import Counter
from pathlib import Path

from corpus import BENIGN_BANDS, CORPUS_ROOT, assert_declared_codepoints, load_corpus
from detectors.presidio_pii import PresidioPiiDetector
from policy.engine import PolicyEngine


class ToolOutputBenignCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_corpus(CORPUS_ROOT / "benign_tool_output.yaml")
        cls.detector = PresidioPiiDetector.from_yaml(Path("gate/detectors/pii_entities.yaml"))
        cls.policy = PolicyEngine.from_yaml(Path("gate/policy/rules.yaml"))

    def test_fixed_band_manifest_and_utf8_codepoints(self) -> None:
        self.assertEqual(len(self.cases), 37)
        self.assertEqual(sum(case.band == "ordinary" for case in self.cases), 12)
        self.assertEqual(sum(case.band == "adjacent_vocabulary" for case in self.cases), 8)
        self.assertEqual(sum(case.band == "structurally_awkward" for case in self.cases), 8)
        self.assertEqual(sum(case.band == "redaction_span" for case in self.cases), 9)
        assert_declared_codepoints(self.cases)

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
            band_totals: dict[str, int] = {band: 0 for band in BENIGN_BANDS}
            band_mismatches: dict[str, list[str]] = {band: [] for band in BENIGN_BANDS}
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
                for band in BENIGN_BANDS
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


if __name__ == "__main__":
    unittest.main()
