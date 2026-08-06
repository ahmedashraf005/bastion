"""Prompt Guard is optional; Gate's other detectors must remain available."""

import unittest
from unittest.mock import patch

from tests import _pathfix  # noqa: F401
from app.main import load_prompt_guard


class PromptGuardDegradedTests(unittest.TestCase):
    def test_missing_hf_token_disables_only_prompt_guard_with_warning(self) -> None:
        with patch("app.main.logger.warning") as warning:
            detector = load_prompt_guard(None)

        self.assertIsNone(detector)
        warning.assert_called_once()
        message = warning.call_args.args[0]
        self.assertIn("LLM01", message)
        self.assertIn("Prompt Guard 2", message)
        self.assertIn("INACTIVE", message)
        self.assertIn("HF_TOKEN", message)

    def test_hf_token_loads_prompt_guard(self) -> None:
        sentinel = object()
        with patch("app.main.PromptGuardDetector.load", return_value=sentinel):
            self.assertIs(load_prompt_guard("local-token"), sentinel)
