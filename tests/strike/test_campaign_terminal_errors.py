"""Unit coverage for explicit terminal campaign-error accounting."""

from pathlib import Path
import unittest

from strike.app.runner import (
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
