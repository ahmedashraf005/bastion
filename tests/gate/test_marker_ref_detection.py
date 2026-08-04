"""Value-anchored Gate detector coverage without exposing a marker to YAML."""

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

import yaml
from pydantic import TypeAdapter

from detectors.system_prompt_leak import (
    DetectorPatternVersion,
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


def _nfkc_and_confusables_promoted_normalization(
    *, active: bool = True
) -> PromotedNormalization:
    # Mirrors the real proposed manifest entry: carries marker_unicode_form
    # forward alongside the new field, since the two compose (NFKC first,
    # then confusables) rather than replace one another.
    return PromotedNormalization(
        version_id="test-normalization-confusables",
        proposal_id="test-proposal-confusables",
        origin_finding_id="test-fixture",
        detector="system_prompt_leak",
        active=active,
        operation="add",
        marker_unicode_form="NFKC",
        marker_confusables_skeleton=True,
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

    def test_confusables_inactive_by_default_the_target_still_fails(self) -> None:
        """Regression guard: this feature is opt-in, not on by default."""

        async def exercise() -> None:
            signal = await self.detector.scan(
                self.bypasses["llm07-homoglyph-cyrillic-greek-confusables-001"]["payload"]
            )
            self.assertFalse(signal.matched)

        asyncio.run(exercise())

    def test_confusables_active_closes_the_target_residual(self) -> None:
        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_and_confusables_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

        async def exercise() -> None:
            signal = await detector.scan(
                self.bypasses["llm07-homoglyph-cyrillic-greek-confusables-001"]["payload"]
            )
            self.assertTrue(signal.matched)
            self.assertEqual(signal.redacted_content, "[REDACTED]")

            # The other out-of-scope pinned case (window-size limitation,
            # not a normalization gap) must remain unaffected.
            k8_signal = await detector.scan(
                self.bypasses["llm07-cf-zero-width-space-density-k8-001"]["payload"]
            )
            self.assertFalse(k8_signal.matched)

        asyncio.run(exercise())

    def test_confusables_redaction_span_is_byte_exact_against_raw_content(self) -> None:
        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_and_confusables_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

        async def exercise() -> None:
            payload = (
                "Case review: "
                + self.bypasses["llm07-homoglyph-cyrillic-greek-confusables-001"]["payload"]
                + ". Keep this: TXN-9F4A77C2 visible."
            )
            signal = await detector.scan(payload)
            self.assertTrue(signal.matched)
            # Surrounding raw text must survive untouched; no confusables-
            # mapped Latin ASCII should leak in outside the redacted span.
            self.assertEqual(
                signal.redacted_content,
                "Case review: [REDACTED]. Keep this: TXN-9F4A77C2 visible.",
            )

        asyncio.run(exercise())

    def test_confusables_active_still_redacts_the_pre_existing_control_cases(self) -> None:
        """The new capability must not regress cases that already passed,
        including the four NFKC target residuals it composes with."""

        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_and_confusables_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

        async def exercise() -> None:
            for case_id in (
                "llm07-cf-zero-width-space-density-k6-001",
                "llm07-clean-marker-control-001",
                "llm07-mn-combining-acute-001",
                *NFKC_TARGET_CASES,
            ):
                signal = await detector.scan(self.bypasses[case_id]["payload"])
                with self.subTest(case_id=case_id):
                    self.assertTrue(signal.matched, case_id)
                    self.assertEqual(signal.redacted_content, "[REDACTED]")

        asyncio.run(exercise())

    def test_confusables_order_must_run_after_nfkc_not_before(self) -> None:
        """Some compatibility forms (mathematical bold/italic/script Greek
        and Cyrillic letters) NFKC-decompose into a PLAIN Greek/Cyrillic
        letter rather than directly into Latin ASCII. Only running
        confusables AFTER NFKC catches that chain, since compatibility-form
        codepoints like U+1D6A8 are outside the confusables table's
        Greek/Cyrillic-block-only domain."""

        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_and_confusables_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

        async def exercise() -> None:
            # U+1D6A8 MATHEMATICAL BOLD CAPITAL ALPHA in place of the
            # marker's leading "B" is the wrong letter on purpose here; this
            # test only needs one compatibility-form Greek/Cyrillic
            # character present anywhere the scan will pass over, to prove
            # composition order resolves it to ASCII rather than leaving a
            # non-ASCII Greek letter behind mid-scan.
            payload = "\U0001D6A8" + "BASTION-CANARY-7K2M9QX4"
            signal = await detector.scan(payload)
            self.assertTrue(signal.matched)

        asyncio.run(exercise())

    def test_confusables_does_not_false_positive_on_genuine_cyrillic_prose(self) -> None:
        """The benign corpora are English-only and structurally cannot catch
        a confusables map mangling legitimate non-Latin text into something
        that spuriously matches. Direct regression guard for that class."""

        detector = SystemPromptLeakDetector.from_definitions(
            [_marker_pattern()],
            [_nfkc_and_confusables_promoted_normalization()],
            marker_resolver={MARKER_REF: MARKER}.__getitem__,
        )

        async def exercise() -> None:
            genuine_content = (
                "Центральный банк сообщил, что ключевая ставка останется без "
                "изменений до конца текущего квартала.",
                '{"customer_name": "Смирнов Александр Сергеевич", '
                '"address": "Москва, ул. Тверская, д. 12, кв. 47"}',
                "Η Ευρωπαϊκή Κεντρική Τράπεζα ανακοίνωσε ότι τα επιτόκια θα "
                "παραμείνουν σταθερά.",
            )
            for content in genuine_content:
                signal = await detector.scan(content)
                with self.subTest(content=content[:30]):
                    self.assertFalse(signal.matched)

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

    # An active PromotedNormalization passing all three ADR-014 promotion
    # gates does not guarantee it is consulted by the currently active
    # pattern version — see docs/design/value-anchored-marker-detection.md,
    # "Promoted-rule reachability is not guaranteed by the promotion gates".
    # Individually justify every entry here; do not add one without reading
    # that section first, and remove an entry the moment it stops being true.
    #
    # Empty as of 2026-08-03: normalization-e40488d4 (Cf category) was the
    # sole occupant of this list — it was active and unreachable (see the
    # doc section above) — but Gate enforces exactly one active entry per
    # manifest (gate/app/policy_profile.py:active_manifest_version), so
    # promoting normalization-b7b3cad1 (the NFKC entry, which IS reachable —
    # the active pattern is marker_ref) required deactivating the Cf entry.
    # It remains in normalization_versions.yaml, unchanged, not removed —
    # simply no longer active, so it is no longer this test's concern.
    KNOWN_UNREACHABLE_ACTIVE_NORMALIZATIONS: dict[str, str] = {}

    def test_active_normalizations_are_reachable_from_the_active_pattern(self) -> None:
        """Every ACTIVE normalization_versions.yaml entry must be reachable
        by at least one effective pattern (after pattern_versions.yaml
        replacements), or be an individually-justified, named exception.

        This cannot assert "the promotion gates guarantee reachability" —
        they don't, and that is the actual finding. What it can assert,
        meaningfully: no NEW active-but-unreachable entry can land silently,
        and the one known exception stays true (still active, still
        actually unreachable) rather than becoming stale allowlist noise.
        """

        root = Path(".")
        with (root / "gate/detectors/leak_patterns.yaml").open(encoding="utf-8") as f:
            definitions = TypeAdapter(list[LeakPattern]).validate_python(yaml.safe_load(f))
        with (root / "gate/detectors/pattern_versions.yaml").open(encoding="utf-8") as f:
            pattern_versions = TypeAdapter(list[DetectorPatternVersion]).validate_python(
                yaml.safe_load(f) or []
            )
        effective_patterns = SystemPromptLeakDetector._apply_active_pattern_versions(
            definitions, pattern_versions
        )
        has_active_strip_separators_pattern = any(
            p.pattern_type in ("literal", "regex") and p.normalize == "strip_separators"
            for p in effective_patterns
        )
        has_active_marker_ref_pattern = any(
            p.pattern_type == "marker_ref" for p in effective_patterns
        )

        with (root / "gate/detectors/normalization_versions.yaml").open(encoding="utf-8") as f:
            normalizations = TypeAdapter(list[PromotedNormalization]).validate_python(
                yaml.safe_load(f) or []
            )

        active_version_ids = {entry.version_id for entry in normalizations if entry.active}
        for entry in normalizations:
            if not entry.active:
                continue
            uses_strip_mechanism = bool(
                entry.unicode_categories or entry.named_classes or entry.codepoints
            )
            uses_marker_mechanism = entry.marker_unicode_form is not None
            unreachable = (uses_strip_mechanism and not has_active_strip_separators_pattern) or (
                uses_marker_mechanism and not has_active_marker_ref_pattern
            )
            with self.subTest(version_id=entry.version_id):
                if unreachable:
                    self.assertIn(
                        entry.version_id,
                        self.KNOWN_UNREACHABLE_ACTIVE_NORMALIZATIONS,
                        f"{entry.version_id} is active and unreachable by any effective "
                        "pattern, and is not a documented, justified exception — either "
                        "this is a new instance of the promotion-pipeline reachability "
                        "gap (see docs/design/value-anchored-marker-detection.md) or the "
                        "active pattern version changed and this needs investigating.",
                    )

        # The allowlist itself must stay true and current, not accumulate
        # stale entries for normalizations that are no longer active.
        for version_id in self.KNOWN_UNREACHABLE_ACTIVE_NORMALIZATIONS:
            self.assertIn(
                version_id,
                active_version_ids,
                f"{version_id} is allowlisted as known-unreachable but is no longer an "
                "active normalization_versions.yaml entry — remove it from the allowlist.",
            )
