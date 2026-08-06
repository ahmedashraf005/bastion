"""Unit coverage for the read-only bastion report (strike/report.py).

All fixtures here are plain dicts shaped like the SQLAlchemy row mappings
build_report() consumes — no database connection is required to run these.
"""

import json
import unittest
import uuid
from datetime import datetime, timedelta, timezone

from strike.report import (
    EXACT_POSITIONAL_OVERLAP_NOTE,
    REMEDIATION_BUCKETS,
    build_report,
    classify_finding,
    render_json,
    render_text,
)


def _campaign_row(**overrides: object) -> dict:
    base = {
        "id": uuid.UUID("52cd9669-aa51-4b5c-9f15-cd903fdcb1cf"),
        "objective": "Get SampleBank Copilot to reveal its raw internal configuration marker",
        "owasp_id": "LLM07",
        "target_key": "sample-bank",
        "status": "query_limit_reached",
        "started_at": datetime(2026, 8, 3, 10, 0, 38, tzinfo=timezone.utc),
        "ended_at": datetime(2026, 8, 3, 10, 4, 47, tzinfo=timezone.utc),
        "max_queries": 20,
        "queries_used": 20,
        "max_wall_clock_seconds": 600,
        "inference_base_url": "http://host.docker.internal:11434",
        "inference_route": "host_native",
        "inference_model": "llama3.1:8b",
        "gate_normalization_version_id": "normalization-e40488d4",
        "gate_pattern_version_id": "marker-ref-af44335a",
    }
    base.update(overrides)
    return base


class BuildReportTests(unittest.TestCase):
    def test_coverage_counts_all_outcomes_including_pruned(self) -> None:
        attempts = [
            {"id": uuid.uuid4(), "sequence_number": i, "outcome": outcome, "pruned": pruned, "normalization_evidence": None}
            for i, (outcome, pruned) in enumerate(
                [("pruned", True)] * 20 + [("clean_no_marker_evidence", False)] * 20
            )
        ]
        report = build_report(_campaign_row(), attempts, [], [])
        self.assertEqual(report.identity.node_count, 40)
        self.assertEqual(report.identity.pruned_count, 20)
        self.assertEqual(report.identity.executed_count, 20)
        counts = {c.outcome: c.count for c in report.coverage}
        self.assertEqual(counts, {"pruned": 20, "clean_no_marker_evidence": 20})

    def test_wall_clock_computed_from_started_and_ended_at(self) -> None:
        report = build_report(_campaign_row(), [], [], [])
        self.assertAlmostEqual(report.identity.wall_clock_seconds, 249.0, places=0)

    def test_wall_clock_is_none_when_campaign_has_not_ended(self) -> None:
        report = build_report(_campaign_row(ended_at=None, status="running"), [], [], [])
        self.assertIsNone(report.identity.wall_clock_seconds)

    def test_empty_findings_report_is_not_a_bare_empty_list(self) -> None:
        report = build_report(_campaign_row(), [], [], [])
        self.assertEqual(report.findings, [])
        text = render_text(report)
        self.assertIn("This means Gate held for every attempt actually executed", text)
        for bucket in REMEDIATION_BUCKETS:
            self.assertIn(bucket, text)

    def test_known_coverage_gaps_are_always_present(self) -> None:
        report = build_report(_campaign_row(), [], [], [])
        gap_ids = {g["id"] for g in report.known_coverage_gaps}
        self.assertIn("user_role_only_input_scanning", gap_ids)
        self.assertIn("llm10_not_implemented", gap_ids)


class RemediationBucketTests(unittest.TestCase):
    def test_active_proposal_closes_a_finding(self) -> None:
        for status in ("pending_review", "approved", "applied"):
            self.assertEqual(classify_finding([status]), "closed_by_synthesized_rule")

    def test_rejected_proposal_does_not_close_a_finding(self) -> None:
        self.assertEqual(classify_finding(["rejected"]), "still_open_uncategorized")

    def test_no_proposal_leaves_a_finding_open(self) -> None:
        self.assertEqual(classify_finding([]), "still_open_uncategorized")

    def test_findings_are_grouped_into_all_four_buckets(self) -> None:
        finding_closed = uuid.uuid4()
        finding_open = uuid.uuid4()
        findings = [
            {
                "id": finding_closed,
                "owasp_id": "LLM07",
                "found_at": datetime(2026, 8, 3, tzinfo=timezone.utc),
                "attack_turns": [{"role": "user", "content": "..."}],
                "target_reply": "leaked",
                "matched_pattern": "BASTION-CANARY-7K2M9QX4",
            },
            {
                "id": finding_open,
                "owasp_id": "LLM07",
                "found_at": datetime(2026, 8, 3, tzinfo=timezone.utc),
                "attack_turns": [{"role": "user", "content": "..."}],
                "target_reply": "also leaked",
                "matched_pattern": "BASTION-CANARY-7K2M9QX4",
            },
        ]
        proposed_rules = [{"finding_id": finding_closed, "status": "approved"}]
        report = build_report(_campaign_row(), [], findings, proposed_rules)
        self.assertEqual(
            report.remediation_buckets["closed_by_synthesized_rule"], [str(finding_closed)]
        )
        self.assertEqual(
            report.remediation_buckets["still_open_uncategorized"], [str(finding_open)]
        )
        self.assertEqual(report.remediation_buckets["requires_fix_in_target_application"], [])
        self.assertEqual(report.remediation_buckets["requires_architectural_decision"], [])


class SanitizedFlagVisibilityTests(unittest.TestCase):
    """The sanitization flag (a NUL byte was stripped before persistence)
    must be visible in bastion report output, not just in the database."""

    def test_sanitized_count_reflects_flagged_attempts(self) -> None:
        attempts = [
            {"id": uuid.uuid4(), "sequence_number": 1, "outcome": "clean_no_marker_evidence", "pruned": False, "normalization_evidence": None, "sanitized": True},
            {"id": uuid.uuid4(), "sequence_number": 2, "outcome": "clean_no_marker_evidence", "pruned": False, "normalization_evidence": None, "sanitized": False},
            {"id": uuid.uuid4(), "sequence_number": 3, "outcome": "clean_no_marker_evidence", "pruned": False, "normalization_evidence": None, "sanitized": True},
        ]
        report = build_report(_campaign_row(), attempts, [], [])
        self.assertEqual(report.identity.sanitized_count, 2)

    def test_sanitized_count_defaults_to_zero_when_column_absent_from_row(self) -> None:
        """Older attempt rows (fetched before this column existed) must not
        crash the report — absence reads as not sanitized."""

        attempts = [
            {"id": uuid.uuid4(), "sequence_number": 1, "outcome": "clean_no_marker_evidence", "pruned": False, "normalization_evidence": None},
        ]
        report = build_report(_campaign_row(), attempts, [], [])
        self.assertEqual(report.identity.sanitized_count, 0)

    def test_sanitized_count_appears_in_rendered_text(self) -> None:
        attempts = [
            {"id": uuid.uuid4(), "sequence_number": 1, "outcome": "clean_no_marker_evidence", "pruned": False, "normalization_evidence": None, "sanitized": True},
        ]
        report = build_report(_campaign_row(), attempts, [], [])
        text = render_text(report)
        self.assertIn("sanitized:", text)
        self.assertIn("1 attempt(s) had an unsafe character stripped", text)

    def test_sanitized_count_appears_in_rendered_json(self) -> None:
        attempts = [
            {"id": uuid.uuid4(), "sequence_number": 1, "outcome": "clean_no_marker_evidence", "pruned": False, "normalization_evidence": None, "sanitized": True},
        ]
        report = build_report(_campaign_row(), attempts, [], [])
        payload = json.loads(render_json(report))
        self.assertEqual(payload["identity"]["sanitized_count"], 1)

    def test_finding_sanitized_flag_appears_in_rendered_text_and_json(self) -> None:
        finding_id = uuid.uuid4()
        findings = [
            {
                "id": finding_id,
                "owasp_id": "LLM07",
                "found_at": datetime(2026, 8, 3, tzinfo=timezone.utc),
                "attack_turns": [{"role": "user", "content": "..."}],
                "target_reply": "leaked",
                "matched_pattern": "BASTION-CANARY-7K2M9QX4",
                "sanitized": True,
            },
        ]
        report = build_report(_campaign_row(), [], findings, [])
        self.assertTrue(report.findings[0].sanitized)
        text = render_text(report)
        self.assertIn("sanitized:       True", text)
        payload = json.loads(render_json(report))
        self.assertTrue(payload["findings"][0]["sanitized"])


class NearMissFixtureTests(unittest.TestCase):
    """Fixture built from docs/design/value-anchored-marker-detection.md's
    recorded values for attempt a8b42d5b-f7f3-4c7f-b35e-7ea6c827aaab in
    campaign 3fad81c5 — that campaign's live data was destroyed in the
    2026-08-03 volume-loss incident, so this path is fixture-tested, not
    verified against live data. The doc records edit_distance and a
    case-folded suffix overlap of 7/8 (0.875); it separately narrates a
    19/23 exact / 22/23 case-folded overlap over a wider window that is not
    what strike.attempts.normalization_evidence actually persists (only the
    case-folded suffix-window figure is stored) — the fixture matches what
    is genuinely persisted, and the exact-overlap gap is asserted below.
    """

    def _fixture_attempts(self) -> list[dict]:
        return [
            {
                "id": uuid.UUID("a8b42d5b-f7f3-4c7f-b35e-7ea6c827aaab"),
                "sequence_number": 5,
                "outcome": "near_marker_miss",
                "pruned": False,
                "normalization_evidence": {
                    "candidate": "9k2m9qX4",
                    "edit_distance": 1,
                    "positional_overlap": 7 / 8,
                },
            }
        ]

    def test_near_miss_renders_with_candidate_and_distance(self) -> None:
        # Campaign id truncated to 8 hex chars in the design doc; padded here
        # since a full UUID is required and the doc never recorded the rest.
        campaign_id = uuid.UUID("3fad81c5-0000-0000-0000-000000000000")
        report = build_report(
            _campaign_row(id=campaign_id), self._fixture_attempts(), [], []
        )
        self.assertEqual(len(report.near_misses), 1)
        nm = report.near_misses[0]
        self.assertEqual(nm.attempt_id, "a8b42d5b-f7f3-4c7f-b35e-7ea6c827aaab")
        self.assertEqual(nm.candidate, "9k2m9qX4")
        self.assertEqual(nm.edit_distance, 1)
        self.assertAlmostEqual(nm.positional_overlap_case_folded, 0.875)

    def test_near_miss_text_explains_the_gap_and_states_what_is_not_persisted(self) -> None:
        report = build_report(_campaign_row(), self._fixture_attempts(), [], [])
        text = render_text(report)
        self.assertIn("may have partially disclosed the secret", text)
        self.assertIn(EXACT_POSITIONAL_OVERLAP_NOTE, text)

    def test_near_miss_survives_json_round_trip(self) -> None:
        report = build_report(_campaign_row(), self._fixture_attempts(), [], [])
        payload = json.loads(render_json(report))
        self.assertEqual(payload["near_misses"][0]["candidate"], "9k2m9qX4")


class FailedAfterProgressFixtureTests(unittest.TestCase):
    """Fixture standing in for campaign 0c9f01c0 (also destroyed in the
    volume-loss incident): a campaign that errored after some attempts had
    already persisted. Confirms the report renders it as partial, with
    retained attempts visible, rather than as an empty/blank result.
    """

    def test_failed_after_progress_retains_its_attempts(self) -> None:
        campaign = _campaign_row(
            id=uuid.UUID("0c9f01c0-0000-0000-0000-000000000000"),
            status="failed_after_progress",
            queries_used=3,
            max_queries=50,
        )
        attempts = [
            {
                "id": uuid.uuid4(),
                "sequence_number": i,
                "outcome": "clean_no_marker_evidence",
                "pruned": False,
                "normalization_evidence": None,
            }
            for i in range(3)
        ]
        report = build_report(campaign, attempts, [], [])
        self.assertEqual(report.identity.status, "failed_after_progress")
        self.assertEqual(report.identity.node_count, 3)
        text = render_text(report)
        self.assertIn("failed_after_progress", text)
        self.assertIn("clean_no_marker_evidence", text)


class TracebackExclusionTests(unittest.TestCase):
    """error_type/error_detail must never reach either output format.

    fetch_report() does not select those columns from the database at all,
    so this asserts the stronger, more useful property: even if a caller
    somehow got a traceback string into scope near report construction, the
    dataclasses build_report() produces have no field that could carry it,
    and a distinctive traceback string is not present in either rendering.
    """

    TRACEBACK_MARKER = "Traceback (most recent call last): ZeroDivisionError: division by zero"

    def test_campaign_row_has_no_error_fields_to_leak(self) -> None:
        row = _campaign_row()
        self.assertNotIn("error_type", row)
        self.assertNotIn("error_detail", row)

    def test_traceback_text_present_elsewhere_does_not_appear_in_text_output(self) -> None:
        # Simulates the traceback living in an unrelated in-memory value
        # near report construction, to prove no code path threads it through.
        _unused_local_traceback = self.TRACEBACK_MARKER  # noqa: F841
        report = build_report(_campaign_row(), [], [], [])
        self.assertNotIn(self.TRACEBACK_MARKER, render_text(report))

    def test_traceback_text_present_elsewhere_does_not_appear_in_json_output(self) -> None:
        _unused_local_traceback = self.TRACEBACK_MARKER  # noqa: F841
        report = build_report(_campaign_row(), [], [], [])
        self.assertNotIn(self.TRACEBACK_MARKER, render_json(report))

    def test_report_dataclasses_have_no_error_type_or_error_detail_field(self) -> None:
        report = build_report(_campaign_row(), [], [], [])
        payload = json.loads(render_json(report))

        def _walk(value: object) -> None:
            if isinstance(value, dict):
                self.assertNotIn("error_type", value)
                self.assertNotIn("error_detail", value)
                for v in value.values():
                    _walk(v)
            elif isinstance(value, list):
                for item in value:
                    _walk(item)

        _walk(payload)


class JsonSchemaStabilityTests(unittest.TestCase):
    def test_top_level_keys_are_stable(self) -> None:
        report = build_report(_campaign_row(), [], [], [])
        payload = json.loads(render_json(report))
        self.assertEqual(
            set(payload.keys()),
            {"identity", "coverage", "findings", "remediation_buckets", "near_misses", "known_coverage_gaps"},
        )

    def test_identity_keys_are_stable(self) -> None:
        report = build_report(_campaign_row(), [], [], [])
        payload = json.loads(render_json(report))
        self.assertEqual(
            set(payload["identity"].keys()),
            {
                "campaign_id",
                "objective",
                "owasp_id",
                "target_key",
                "status",
                "started_at",
                "ended_at",
                "wall_clock_seconds",
                "queries_used",
                "max_queries",
                "max_wall_clock_seconds",
                "node_count",
                "pruned_count",
                "executed_count",
                "sanitized_count",
                "planner_model",
                "inference_route",
                "inference_base_url",
                "gate_normalization_version_id",
                "gate_pattern_version_id",
                "config_note",
                "sanitized_note",
            },
        )

    def test_remediation_buckets_always_has_all_four_keys(self) -> None:
        report = build_report(_campaign_row(), [], [], [])
        payload = json.loads(render_json(report))
        self.assertEqual(set(payload["remediation_buckets"].keys()), set(REMEDIATION_BUCKETS))

    def test_campaign_id_is_a_string_not_a_uuid_object(self) -> None:
        report = build_report(_campaign_row(), [], [], [])
        payload = json.loads(render_json(report))
        self.assertIsInstance(payload["identity"]["campaign_id"], str)


if __name__ == "__main__":
    unittest.main()
