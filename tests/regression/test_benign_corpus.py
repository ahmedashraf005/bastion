"""Deterministic benign-corpus regression checks using Gate's live policy code."""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path

from tests import _pathfix  # noqa: F401
from corpus import (
    CORPUS_ROOT,
    assert_declared_codepoints,
    evaluate_benign_cases,
    load_corpus,
)
from detectors.system_prompt_leak import SystemPromptLeakDetector
from policy.engine import PolicyEngine
from strike.synthesizer.rule_synthesizer import AdditiveNormalization, RuleSynthesizer


REPO_ROOT = Path(__file__).resolve().parents[2]

TEST_MARKERS = {
    "sample-bank.internal_configuration_marker": "BASTION-CANARY-7K2M9QX4"
}


class BenignCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_corpus(CORPUS_ROOT / "benign.yaml")
        cls.detector = SystemPromptLeakDetector.from_yaml(
            REPO_ROOT / "gate/detectors/leak_patterns.yaml",
            REPO_ROOT / "gate/detectors/normalization_versions.yaml",
            REPO_ROOT / "gate/detectors/pattern_versions.yaml",
            marker_resolver=TEST_MARKERS.__getitem__,
        )
        cls.policy = PolicyEngine.from_yaml(REPO_ROOT / "gate/policy/rules.yaml")

    def test_fixed_band_manifest_and_utf8_codepoints(self) -> None:
        self.assertGreaterEqual(len(self.cases), 40)
        self.assertEqual(sum(case.band == "ordinary" for case in self.cases), 20)
        self.assertEqual(sum(case.band == "adjacent_vocabulary" for case in self.cases), 10)
        self.assertEqual(sum(case.band == "structurally_awkward" for case in self.cases), 12)
        self.assertEqual(sum(case.band == "redaction_span" for case in self.cases), 6)
        assert_declared_codepoints(self.cases)

    def test_current_policy_has_zero_false_positives_per_blocking_band(self) -> None:
        async def exercise() -> None:
            results, _ = await evaluate_benign_cases(
                self.cases, self.detector, self.policy
            )
            self.assertEqual(results["ordinary"].false_positives, 0)
            self.assertEqual(results["adjacent_vocabulary"].false_positives, 0)
            self.assertEqual(results["structurally_awkward"].false_positives, 0)
            self.assertEqual(results["redaction_span"].false_positives, 0)

        asyncio.run(exercise())

    def test_redaction_span_cases_preserve_non_marker_content(self) -> None:
        async def exercise() -> None:
            for case in (case for case in self.cases if case.band == "redaction_span"):
                signal = await self.detector.scan(case.payload)
                evaluation = self.policy.evaluate([signal], stage="output")
                with self.subTest(case_id=case.id):
                    if case.expect == "allow":
                        self.assertFalse(signal.matched)
                        self.assertIsNone(signal.redacted_content)
                        self.assertFalse(evaluation.matched_rules)
                    else:
                        self.assertTrue(signal.matched)
                        self.assertEqual(evaluation.action, "redact")
                        self.assertEqual(signal.redacted_content.count("[REDACTED]"), 1)
                        self.assertEqual(signal.redacted_content, case.expected_redacted_content)

        asyncio.run(exercise())

    def test_cf_proposal_simulation_preserves_benign_verdicts(self) -> None:
        async def exercise() -> None:
            change = AdditiveNormalization(operation="add", unicode_categories=["Cf"])
            results, _ = await evaluate_benign_cases(
                self.cases,
                self.detector,
                self.policy,
                transform=lambda payload: RuleSynthesizer._apply_additive_normalization(
                    payload, change
                ),
            )
            self.assertEqual(sum(result.false_positives for result in results.values()), 0)

        asyncio.run(exercise())
