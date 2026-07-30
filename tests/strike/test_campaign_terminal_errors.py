"""Unit coverage for explicit terminal campaign-error accounting."""

import unittest

from strike.app.runner import inference_route, terminal_exception_values


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
