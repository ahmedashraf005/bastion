"""Deterministic proof that live Gate normalization versions close saved bypasses."""

from __future__ import annotations

import asyncio
import re
import unittest
from pathlib import Path

import yaml

from tests import _pathfix  # noqa: F401
from detectors.system_prompt_leak import SystemPromptLeakDetector
from policy.engine import PolicyEngine


REPO_ROOT = Path(__file__).resolve().parents[2]

TEST_MARKERS = {
    "sample-bank.internal_configuration_marker": "BASTION-CANARY-7K2M9QX4"
}
class BypassRegressionTests(unittest.TestCase):
    """Run exact saved UTF-8 evidence through Gate's deployed detector configuration."""

    @classmethod
    def setUpClass(cls) -> None:
        corpus_path = REPO_ROOT / "tests/corpus/bypasses.yaml"
        with corpus_path.open(encoding="utf-8") as corpus_file:
            cls.cases = yaml.safe_load(corpus_file)["cases"]
        cls.detector = SystemPromptLeakDetector.from_yaml(
            REPO_ROOT / "gate/detectors/leak_patterns.yaml",
            REPO_ROOT / "gate/detectors/normalization_versions.yaml",
            REPO_ROOT / "gate/detectors/pattern_versions.yaml",
            marker_resolver=TEST_MARKERS.__getitem__,
        )
        cls.policy = PolicyEngine.from_yaml(REPO_ROOT / "gate/policy/rules.yaml")

    def test_saved_payload_codepoints_are_byte_exact(self) -> None:
        for case in self.cases:
            declared = re.findall(r"U\+[0-9A-F]{4,6}", case["payload_codepoints"])
            actual = [f"U+{ord(character):04X}" for character in case["payload"]]
            self.assertEqual(actual, declared, case["id"])

    def test_expected_failures_are_individually_named(self) -> None:
        """A known residual is evidence, not a count hidden in test prose."""

        for case in self.cases:
            expected_failure = case.get("expected_failure")
            if expected_failure is None:
                continue
            with self.subTest(case_id=case["id"]):
                self.assertIsInstance(expected_failure, dict)
                self.assertIsInstance(expected_failure.get("reason"), str)
                self.assertTrue(expected_failure["reason"].strip())

    def test_bypass_cases_are_prevented_by_live_policy_configuration(self) -> None:
        async def exercise() -> None:
            for case in self.cases:
                signal = await self.detector.scan(case["payload"])
                evaluation = self.policy.evaluate([signal], stage=case["stage"])
                with self.subTest(case_id=case["id"]):
                    expected_failure = case.get("expected_failure")
                    if expected_failure is not None:
                        self.assertFalse(
                            signal.matched,
                            f"{case['id']}: pinned residual now matches; remove its expected_failure pin",
                        )
                        self.assertIsNone(
                            evaluation.action,
                            f"{case['id']}: pinned residual now receives policy action; remove its expected_failure pin",
                        )
                    else:
                        self.assertTrue(
                            signal.matched,
                            f"{case['id']}: unmatched bypass has no expected_failure pin",
                        )
                        self.assertIn(
                            evaluation.action,
                            {"block", "redact"},
                            f"{case['id']}: unmatched bypass has no expected_failure pin",
                        )

        asyncio.run(exercise())
