"""Value-anchored Gate detector coverage without exposing a marker to YAML."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import yaml

from detectors.system_prompt_leak import (
    LeakPattern,
    MarkerReferenceResolver,
    PromotedNormalization,
    SystemPromptLeakDetector,
)


MARKER_REF = "sample-bank.internal_configuration_marker"
MARKER = "BASTION-CANARY-7K2M9QX4"

NFKC_TARGET_CASES = (
    "llm07-homoglyph-fullwidth-001",
    "llm07-homoglyph-mathematical-bold-001",
    "llm07-homoglyph-circled-001",
    "llm07-homoglyph-parenthesized-001",
)
NFKC_OUT_OF_SCOPE_CASES = (
    "llm07-homoglyph-cyrillic-greek-confusables-001",
    "llm07-cf-zero-width-space-density-k8-001",
)


def _marker_pattern() -> LeakPattern:
    return LeakPattern(
        id="test-marker",
        description="test-only value marker",
        pattern_type="marker_ref",
        marker_ref=MARKER_REF,
        normalize="strip_separators",
        max_source_span=160,
    )


def _nfkc_promoted_normalization(*, active: bool = True) -> PromotedNormalization:
    return PromotedNormalization(
        version_id="test-normalization-nfkc",
        proposal_id="test-proposal-nfkc",
        origin_finding_id="test-fixture",
        detector="system_prompt_leak",
        active=active,
        operation="add",
        marker_unicode_form="NFKC",
    )


class MarkerReferenceDetectorTests(unittest.TestCase):
    """Keep the empirical source-window contract explicit and testable."""

    @classmethod
    def setUpClass(cls) -> None:
        with Path("tests/corpus/bypasses.yaml").open(encoding="utf-8") as corpus_file:
            cls.bypasses = {case["id"]: case for case in yaml.safe_load(corpus_file)["cases"]}
        with Path("tests/corpus/benign.yaml").open(encoding="utf-8") as corpus_file:
            cls.benign = {case["id"]: case for case in yaml.safe_load(corpus_file)["cases"]}
        cls.detector = SystemPromptLeakDetector.from_definitions(
            [
                LeakPattern(
                    id="test-marker",
                    description="test-only value marker",
                    pattern_type="marker_ref",
                    marker_ref=MARKER_REF,
                    normalize="strip_separators",
                    max_source_span=160,
                )
            ],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

    def test_marker_value_is_not_in_the_pattern_yaml(self) -> None:
        pattern_yaml = Path("gate/detectors/leak_patterns.yaml").read_text(encoding="utf-8")
        pattern_versions = Path("gate/detectors/pattern_versions.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn(MARKER_REF, pattern_versions)
        self.assertNotIn(MARKER, pattern_yaml + pattern_versions)

    def test_resolver_prefers_explicit_environment_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            secrets_path = Path(temporary_directory) / "marker-secrets.json"
            secrets_path.write_text(json.dumps({MARKER_REF: "file-value"}), encoding="utf-8")
            environment = {
                MarkerReferenceResolver.environment_name(MARKER_REF): "environment-value"
            }
            resolver = MarkerReferenceResolver(
                secrets_file=secrets_path, environment=environment
            )
            self.assertEqual(resolver.resolve(MARKER_REF), "environment-value")

    def test_unresolved_reference_fails_loudly_without_a_value(self) -> None:
        with self.assertRaisesRegex(RuntimeError, MARKER_REF):
            MarkerReferenceResolver(environment={}).resolve(MARKER_REF)

    def test_window_and_raw_redaction_span(self) -> None:
        async def exercise() -> None:
            for case_id in (
                "llm07-cf-zero-width-space-density-k6-001",
                "llm07-clean-marker-control-001",
            ):
                case = self.bypasses[case_id]
                signal = await self.detector.scan(case["payload"])
                with self.subTest(case_id=case_id):
                    self.assertTrue(signal.matched)
                    self.assertEqual(signal.redacted_content, "[REDACTED]")

            for case_id in (
                "llm07-cf-zero-width-space-density-k8-001",
                "span-partial-marker-prefix-001",
                "span-scattered-marker-alphabet-001",
                "span-marker-wide-interleaver-001",
            ):
                source = self.bypasses.get(case_id, self.benign.get(case_id))
                assert source is not None
                signal = await self.detector.scan(source["payload"])
                with self.subTest(case_id=case_id):
                    self.assertFalse(signal.matched)
                    self.assertIsNone(signal.redacted_content)

        asyncio.run(exercise())

    def test_nfkc_inactive_by_default_the_four_targets_still_fail(self) -> None:
        """Regression guard: this feature is opt-in, not on by default."""

        async def exercise() -> None:
            for case_id in NFKC_TARGET_CASES:
                signal = await self.detector.scan(self.bypasses[case_id]["payload"])
                with self.subTest(case_id=case_id):
                    self.assertFalse(signal.matched)

        asyncio.run(exercise())

    def test_nfkc_active_closes_exactly_the_four_target_residuals(self) -> None:
        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

        async def exercise() -> None:
            for case_id in NFKC_TARGET_CASES:
                signal = await detector.scan(self.bypasses[case_id]["payload"])
                with self.subTest(case_id=case_id):
                    self.assertTrue(signal.matched, case_id)

            for case_id in NFKC_OUT_OF_SCOPE_CASES:
                signal = await detector.scan(self.bypasses[case_id]["payload"])
                with self.subTest(case_id=case_id):
                    self.assertFalse(signal.matched, case_id)

        asyncio.run(exercise())

    def test_nfkc_active_redaction_span_is_byte_exact_against_raw_content(self) -> None:
        """The redaction span must map back to the ORIGINAL content, not the
        NFKC-normalized text, since normalized text is never persisted or
        returned — only used internally to locate the match."""

        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

        async def exercise() -> None:
            for case_id in NFKC_TARGET_CASES:
                payload = self.bypasses[case_id]["payload"]
                signal = await detector.scan(payload)
                with self.subTest(case_id=case_id):
                    self.assertTrue(signal.matched)
                    # Every non-ASCII source character was consumed by the
                    # match (each payload is marker-shaped end to end), so
                    # the whole raw payload collapses to one redaction, not
                    # a slice of NFKC-normalized replacement text.
                    self.assertEqual(signal.redacted_content, "[REDACTED]")
                    self.assertNotIn("(", signal.redacted_content)

        asyncio.run(exercise())

    def test_nfkc_active_still_redacts_the_pre_existing_control_cases(self) -> None:
        """The new capability must not regress cases that already passed."""

        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

        async def exercise() -> None:
            for case_id in (
                "llm07-cf-zero-width-space-density-k6-001",
                "llm07-clean-marker-control-001",
                "llm07-mn-combining-acute-001",
            ):
                signal = await detector.scan(self.bypasses[case_id]["payload"])
                with self.subTest(case_id=case_id):
                    self.assertTrue(signal.matched, case_id)
                    self.assertEqual(signal.redacted_content, "[REDACTED]")

        asyncio.run(exercise())

    def test_only_one_active_marker_unicode_form_is_supported_today(self) -> None:
        # Documents current behavior: a single Literal["NFKC"] means only one
        # active form can ever exist, so the conflict branch in __init__ is
        # unreachable with today's schema and is defensive for a future form.
        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_promoted_normalization(), _nfkc_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )
        self.assertEqual(detector._marker_unicode_form, "NFKC")
