"""Unit coverage for explicit terminal campaign-error accounting."""

from pathlib import Path
import unittest

from strike.app.runner import (
    active_gate_manifest_versions,
    feasibility_estimate,
    inference_route,
    load_attempts,
    terminal_exception_values,
)


class CampaignTerminalErrorTests(unittest.TestCase):
    def test_exception_before_any_attempt_is_error(self) -> None:
        try:
            raise RuntimeError("planner unavailable")
        except RuntimeError as exc:
            values = terminal_exception_values(exc, persisted_attempt_count=0)

        self.assertEqual(values["status"], "error")
        self.assertEqual(values["error_type"], "RuntimeError")
        self.assertIn("planner unavailable", str(values["error_detail"]))

    def test_exception_after_persisted_attempt_is_visibly_partial(self) -> None:
        try:
            raise RuntimeError("planner unavailable")
        except RuntimeError as exc:
            values = terminal_exception_values(exc, persisted_attempt_count=1)

        self.assertEqual(values["status"], "failed_after_progress")

    def test_inference_routes_are_explicit(self) -> None:
        self.assertEqual(inference_route("http://host.docker.internal:11434"), "host_native")
        self.assertEqual(inference_route("http://ollama:11434"), "compose_container")
        self.assertEqual(inference_route("http://inference.example:11434"), "other")

    def test_branching_demo_budget_has_measured_feasibility_headroom(self) -> None:
        attempts_file = load_attempts(
            Path("strike/attempts/canary_leak_branching.yaml")
        )

        self.assertEqual(attempts_file.max_queries, 20)
        self.assertEqual(attempts_file.max_wall_clock_seconds, 600)
        self.assertTrue(attempts_file.use_strategy_library)
        estimate = feasibility_estimate(attempts_file, attempts_file.max_queries or 0)
        self.assertEqual(estimate["expected_rounds"], 10)
        self.assertAlmostEqual(estimate["query_seconds"], 389.692)
        self.assertAlmostEqual(estimate["drift_seconds"], 63.0)
        self.assertAlmostEqual(estimate["total_seconds"], 452.692)
        self.assertLess(estimate["total_seconds"], attempts_file.max_wall_clock_seconds or 0)

    def test_static_smoke_campaign_feasibility_uses_actual_attempt_count(self) -> None:
        """A static attempts list's query count is known exactly, not bounded by max_queries.

        Estimating from the 50-query safety default here produced a large
        negative headroom for canary_leak.yaml even though it always issues
        exactly len(attempts) queries and finishes in seconds.
        """

        attempts_file = load_attempts(Path("strike/attempts/canary_leak.yaml"))

        self.assertEqual(attempts_file.attempt_source, "static")
        self.assertEqual(len(attempts_file.attempts or []), 5)
        estimate = feasibility_estimate(attempts_file, max_queries=50)
        self.assertEqual(estimate["expected_queries"], 5)
        self.assertEqual(estimate["expected_rounds"], 5)
        self.assertEqual(estimate["drift_seconds"], 0.0)
        self.assertGreater(estimate["total_seconds"], 0)
        self.assertLess(estimate["total_seconds"], 300)

    def test_active_gate_manifest_versions_are_recordable_independently(self) -> None:
        self.assertEqual(
            active_gate_manifest_versions(),
            {
                "gate_normalization_version_id": "normalization-e40488d4-f3a6-427b-b1aa-62b04b0271e1",
                "gate_pattern_version_id": "marker-ref-af44335a-9f28-4547-b857-ac7cc53d1e8a",
            },
        )
