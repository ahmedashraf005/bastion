"""Opt-in tool-output PII scanning: routing, flag behavior, and content shapes.

Uses a stub Presidio detector rather than the real one — these tests are
about the plumbing (which message gets scanned, which gets redacted, what
source_role gets recorded, response shape), not entity-detection accuracy.
Real Presidio false-positive behavior is measured separately by the
tool-output benign corpus, which needs the real detector.

extract_text_content() and most_recent_user_message()'s content-shape
handling are covered by test_input_content_extraction.py, not here — that
fix predates and is independent of the flag this file tests.
"""

from __future__ import annotations

import json as json_module
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import settings as real_settings
from app.main import chat_completions, most_recent_tool_message
from detectors.base import DetectorSignal
from policy.engine import PolicyEngine


RULES_PATH = Path("gate/policy/rules.yaml")
SECRET_MARKER = "SECRET-VALUE"

FAKE_UPSTREAM_RESPONSE = {
    "id": "chatcmpl-test",
    "object": "chat.completion",
    "created": 0,
    "model": "test-model",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop",
        }
    ],
}


class StubPiiDetector:
    """Flags SECRET_MARKER as PII; real Presidio is not needed to test routing."""

    detector_name = "presidio_pii"

    async def scan(self, content: str) -> DetectorSignal:
        if SECRET_MARKER in content:
            return DetectorSignal(
                detector="presidio_pii",
                entities=["EMAIL_ADDRESS"],
                redacted_content=content.replace(SECRET_MARKER, "[REDACTED]"),
            )
        return DetectorSignal(detector="presidio_pii")


class StubLeakDetector:
    """Output-stage stub — these tests never assert on output-stage behavior."""

    detector_name = "system_prompt_leak"

    async def scan(self, content: str) -> DetectorSignal:
        return DetectorSignal(detector="system_prompt_leak", matched=False)


class FakeResponse:
    def __init__(self, body: dict, status_code: int = 200) -> None:
        self._body = body
        self.status_code = status_code
        self.content = json_module.dumps(body).encode("utf-8")
        self.headers = {"content-type": "application/json"}

    def json(self) -> dict:
        return self._body


class FakeUpstreamClient:
    """Stands in for httpx.AsyncClient so no real network call happens.

    Captures the JSON body it was posted with, so a test can inspect exactly
    what Gate forwarded upstream — including whether input-stage redaction
    mutated a message before this point.
    """

    last_posted_json: dict | None = None

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self) -> "FakeUpstreamClient":
        return self

    async def __aexit__(self, *exc_info) -> bool:
        return False

    async def post(self, url: str, *, json: dict) -> FakeResponse:
        FakeUpstreamClient.last_posted_json = json
        return FakeResponse(FAKE_UPSTREAM_RESPONSE)


def build_test_app() -> FastAPI:
    """A minimal FastAPI app reusing the real handler, without the real lifespan."""

    test_app = FastAPI()
    test_app.add_api_route("/v1/chat/completions", chat_completions, methods=["POST"])
    test_app.state.presidio_pii_detector = StubPiiDetector()
    test_app.state.prompt_guard_detector = None
    test_app.state.system_prompt_leak_detector = StubLeakDetector()
    test_app.state.policy_engine = PolicyEngine.from_yaml(RULES_PATH)
    return test_app


def request_body(messages: list[dict]) -> dict:
    return {"model": "test-model", "stream": False, "messages": messages}


class MessageSelectionTests(unittest.TestCase):
    def test_most_recent_tool_message_selects_latest_only(self) -> None:
        body = {
            "messages": [
                {"role": "tool", "tool_call_id": "call_1", "content": "first tool result"},
                {"role": "assistant", "content": "thinking"},
                {"role": "tool", "tool_call_id": "call_2", "content": "second tool result"},
            ]
        }
        selected = most_recent_tool_message(body)
        self.assertIsNotNone(selected)
        self.assertEqual(selected["tool_call_id"], "call_2")

    def test_most_recent_tool_message_none_when_absent(self) -> None:
        body = {"messages": [{"role": "user", "content": "hi"}]}
        self.assertIsNone(most_recent_tool_message(body))


class ToolOutputScanningEndpointTests(unittest.TestCase):
    """Exercises the real chat_completions() handler end to end."""

    def setUp(self) -> None:
        FakeUpstreamClient.last_posted_json = None
        self._httpx_patch = patch("app.main.httpx.AsyncClient", new=FakeUpstreamClient)
        self._httpx_patch.start()
        self.addCleanup(self._httpx_patch.stop)
        self.app = build_test_app()
        self.client = TestClient(self.app)

    def _settings(self, *, scan_tool_output: bool):
        return patch("app.main.settings", replace(real_settings, scan_tool_output=scan_tool_output))

    def test_tool_content_untouched_when_flag_off(self) -> None:
        body = request_body(
            [
                {"role": "user", "content": "do the thing"},
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": f"balance record: {SECRET_MARKER}",
                },
            ]
        )
        with self._settings(scan_tool_output=False):
            response = self.client.post("/v1/chat/completions", json=body)

        self.assertEqual(response.status_code, 200)
        forwarded = FakeUpstreamClient.last_posted_json
        self.assertIn(SECRET_MARKER, forwarded["messages"][1]["content"])

    def test_tool_content_redacted_when_flag_on(self) -> None:
        body = request_body(
            [
                {"role": "user", "content": "do the thing"},
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": f"balance record: {SECRET_MARKER}",
                },
            ]
        )
        with self._settings(scan_tool_output=True):
            response = self.client.post("/v1/chat/completions", json=body)

        self.assertEqual(response.status_code, 200)
        forwarded = FakeUpstreamClient.last_posted_json
        self.assertNotIn(SECRET_MARKER, forwarded["messages"][1]["content"])
        self.assertIn("[REDACTED]", forwarded["messages"][1]["content"])

    def test_only_latest_tool_message_is_scanned(self) -> None:
        body = request_body(
            [
                {"role": "user", "content": "do the thing"},
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": f"earlier secret: {SECRET_MARKER}",
                },
                {"role": "assistant", "content": "still working"},
                {
                    "role": "tool",
                    "tool_call_id": "call_2",
                    "content": "latest result, nothing sensitive",
                },
            ]
        )
        with self._settings(scan_tool_output=True):
            response = self.client.post("/v1/chat/completions", json=body)

        self.assertEqual(response.status_code, 200)
        forwarded = FakeUpstreamClient.last_posted_json
        # Earlier tool message is untouched: only the latest was scanned.
        self.assertIn(SECRET_MARKER, forwarded["messages"][1]["content"])
        self.assertEqual(
            forwarded["messages"][3]["content"], "latest result, nothing sensitive"
        )

    def test_content_block_array_scanned_for_both_roles(self) -> None:
        body = request_body(
            [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": f"user says {SECRET_MARKER}"}],
                },
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": [{"type": "text", "text": f"tool returns {SECRET_MARKER}"}],
                },
            ]
        )
        with self._settings(scan_tool_output=True):
            response = self.client.post("/v1/chat/completions", json=body)

        self.assertEqual(response.status_code, 200)
        forwarded = FakeUpstreamClient.last_posted_json
        self.assertIn("[REDACTED]", forwarded["messages"][0]["content"])
        self.assertIn("[REDACTED]", forwarded["messages"][1]["content"])

    def test_string_content_scanned_for_both_roles(self) -> None:
        body = request_body(
            [
                {"role": "user", "content": f"user says {SECRET_MARKER}"},
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": f"tool returns {SECRET_MARKER}",
                },
            ]
        )
        with self._settings(scan_tool_output=True):
            response = self.client.post("/v1/chat/completions", json=body)

        self.assertEqual(response.status_code, 200)
        forwarded = FakeUpstreamClient.last_posted_json
        self.assertIn("[REDACTED]", forwarded["messages"][0]["content"])
        self.assertIn("[REDACTED]", forwarded["messages"][1]["content"])

    def test_source_role_populated_for_user_and_tool_signals(self) -> None:
        body = request_body(
            [
                {"role": "user", "content": f"user says {SECRET_MARKER}"},
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": f"tool returns {SECRET_MARKER}",
                },
            ]
        )
        with self._settings(scan_tool_output=True), patch(
            "app.main.persist_request", new=AsyncMock()
        ) as persist:
            self.client.post("/v1/chat/completions", json=body)

        signals = persist.call_args.kwargs["detector_signals"]
        source_roles = {
            (signal["detector"], signal.get("source_role")) for signal in signals
        }
        self.assertIn(("presidio_pii", "user"), source_roles)
        self.assertIn(("presidio_pii", "tool"), source_roles)
        self.assertIn(("prompt_guard_2", "user"), source_roles)

    def test_redacted_tool_message_produces_valid_openai_response(self) -> None:
        body = request_body(
            [
                {"role": "user", "content": "do the thing"},
                {
                    "role": "tool",
                    "tool_call_id": "call_1",
                    "content": f"balance record: {SECRET_MARKER}",
                },
            ]
        )
        with self._settings(scan_tool_output=True):
            response = self.client.post("/v1/chat/completions", json=body)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("choices", payload)
        self.assertEqual(payload["choices"][0]["message"]["role"], "assistant")

    def test_user_message_behavior_unchanged_with_flag_off(self) -> None:
        body = request_body([{"role": "user", "content": f"user says {SECRET_MARKER}"}])
        with self._settings(scan_tool_output=False):
            response = self.client.post("/v1/chat/completions", json=body)

        self.assertEqual(response.status_code, 200)
        forwarded = FakeUpstreamClient.last_posted_json
        self.assertIn("[REDACTED]", forwarded["messages"][0]["content"])
        self.assertNotIn(SECRET_MARKER, forwarded["messages"][0]["content"])


if __name__ == "__main__":
    unittest.main()
