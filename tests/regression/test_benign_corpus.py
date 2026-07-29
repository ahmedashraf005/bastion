"""Deterministic benign-corpus regression checks using Gate's live policy code."""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path

from corpus import (
    CORPUS_ROOT,
    assert_declared_codepoints,
    evaluate_benign_cases,
    load_corpus,
)
from detectors.system_prompt_leak import SystemPromptLeakDetector
from policy.engine import PolicyEngine
from strike.synthesizer.rule_synthesizer import AdditiveNormalization, RuleSynthesizer


class BenignCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_corpus(CORPUS_ROOT / "benign.yaml")
        cls.detector = SystemPromptLeakDetector.from_yaml(
            Path("gate/detectors/leak_patterns.yaml"),
            Path("gate/detectors/normalization_versions.yaml"),
        )
        cls.policy = PolicyEngine.from_yaml(Path("gate/policy/rules.yaml"))

    def test_minimum_band_composition_and_utf8_codepoints(self) -> None:
        self.assertGreaterEqual(len(self.cases), 40)
        self.assertGreaterEqual(sum(case.band == "ordinary" for case in self.cases), 20)
        self.assertGreaterEqual(
            sum(case.band == "adjacent_vocabulary" for case in self.cases), 10
        )
        self.assertGreaterEqual(
            sum(case.band == "structurally_awkward" for case in self.cases), 10
        )
        assert_declared_codepoints(self.cases)

    def test_current_policy_has_zero_false_positives_per_blocking_band(self) -> None:
        async def exercise() -> None:
            results, _ = await evaluate_benign_cases(
                self.cases, self.detector, self.policy
            )
            self.assertEqual(results["ordinary"].false_positives, 0)
            self.assertEqual(results["adjacent_vocabulary"].false_positives, 0)
            self.assertEqual(results["structurally_awkward"].false_positives, 0)

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
