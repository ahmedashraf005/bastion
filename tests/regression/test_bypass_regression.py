"""Deterministic proof that live Gate normalization versions close saved bypasses."""

from __future__ import annotations

import asyncio
import re
import unittest
from pathlib import Path

import yaml

from detectors.system_prompt_leak import SystemPromptLeakDetector
from policy.engine import PolicyEngine


class BypassRegressionTests(unittest.TestCase):
    """Run exact saved UTF-8 evidence through Gate's deployed detector configuration."""

    @classmethod
    def setUpClass(cls) -> None:
        corpus_path = Path("tests/corpus/bypasses.yaml")
        with corpus_path.open(encoding="utf-8") as corpus_file:
            cls.cases = yaml.safe_load(corpus_file)["cases"]
        cls.detector = SystemPromptLeakDetector.from_yaml(
            Path("gate/detectors/leak_patterns.yaml"),
            Path("gate/detectors/normalization_versions.yaml"),
        )
        cls.policy = PolicyEngine.from_yaml(Path("gate/policy/rules.yaml"))

    def test_saved_payload_codepoints_are_byte_exact(self) -> None:
        for case in self.cases:
            declared = re.findall(r"U\+[0-9A-F]{4,6}", case["payload_codepoints"])
            actual = [f"U+{ord(character):04X}" for character in case["payload"]]
            self.assertEqual(actual, declared, case["id"])

    def test_bypass_cases_are_prevented_by_live_policy_configuration(self) -> None:
        async def exercise() -> None:
            for case in self.cases:
                signal = await self.detector.scan(case["payload"])
                evaluation = self.policy.evaluate([signal], stage=case["stage"])
                with self.subTest(case_id=case["id"]):
                    self.assertTrue(signal.matched, case["id"])
                    self.assertIn(evaluation.action, {"block", "redact"}, case["id"])

        asyncio.run(exercise())
