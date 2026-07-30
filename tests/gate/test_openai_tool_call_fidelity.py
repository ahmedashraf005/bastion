"""Live OpenAI-compatible tool-call fidelity checks for the buffered Gate path."""

from __future__ import annotations

import json
import os
import unittest
from collections.abc import Iterable
from typing import Any

import httpx


GATE_URL = os.getenv("BASTION_GATE_URL", "http://localhost:8000").rstrip("/")
OLLAMA_URL = os.getenv("BASTION_DIRECT_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
MODEL = os.getenv("BASTION_TOOL_CALL_TEST_MODEL", "llama3.1:8b")


def tool_request(*, stream: bool) -> dict[str, Any]:
    """Use a no-argument tool so the expected tool-call shape is stable."""

    return {
        "model": MODEL,
        "stream": stream,
        "temperature": 0,
        "messages": [
            {
                "role": "user",
                "content": "Call the get_balance tool now. Do not answer in prose before the tool call.",
            }
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "get_balance",
                    "description": "Return the account balance.",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            }
        ],
    }


def sse_events(raw: str) -> Iterable[dict[str, Any]]:
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload and payload != "[DONE]":
            yield json.loads(payload)


def stream_tool_calls(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    tool_calls: list[dict[str, Any]] = []
    for event in events:
        for choice in event.get("choices", []):
            delta = choice.get("delta", {})
            for tool_call in delta.get("tool_calls", []):
                tool_calls.append(
                    {
                        "index": tool_call.get("index"),
                        "type": tool_call.get("type"),
                        "function": tool_call.get("function"),
                    }
                )
    return tool_calls


def finish_reasons(events: Iterable[dict[str, Any]]) -> list[str]:
    return [
        choice["finish_reason"]
        for event in events
        for choice in event.get("choices", [])
        if choice.get("finish_reason") is not None
    ]


class OpenAIToolCallFidelityTests(unittest.TestCase):
    """Pin the live proxy contract against the direct host-native upstream."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            gate_health = httpx.get(f"{GATE_URL}/healthz", timeout=2.0)
            ollama_health = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=2.0)
        except httpx.HTTPError as exc:
            raise unittest.SkipTest(
                "live Gate/Ollama required; start the stack and host Ollama "
                f"(Gate={GATE_URL}, Ollama={OLLAMA_URL}): {exc}"
            ) from exc
        if gate_health.status_code != 200 or ollama_health.status_code != 200:
            raise unittest.SkipTest(
                "live Gate/Ollama required; start the stack and host Ollama "
                f"(Gate={GATE_URL}, Ollama={OLLAMA_URL})"
            )
        try:
            pulled_models = ollama_health.json().get("models", [])
        except ValueError as exc:
            raise unittest.SkipTest(
                f"host Ollama tags response was not JSON; cannot verify required model {MODEL}"
            ) from exc
        if not any(model.get("name") == MODEL for model in pulled_models if isinstance(model, dict)):
            raise unittest.SkipTest(
                f"host Ollama is reachable but required model {MODEL!r} is not pulled"
            )

    def test_buffered_stream_preserves_tool_calls_and_finish_reason(self) -> None:
        direct = httpx.post(
            f"{OLLAMA_URL}/v1/chat/completions",
            json=tool_request(stream=True),
            timeout=45.0,
        )
        gate = httpx.post(
            f"{GATE_URL}/v1/chat/completions",
            json=tool_request(stream=True),
            timeout=45.0,
        )
        self.assertEqual(direct.status_code, 200, direct.text)
        self.assertEqual(gate.status_code, 200, gate.text)

        direct_events = list(sse_events(direct.text))
        gate_events = list(sse_events(gate.text))
        self.assertEqual(stream_tool_calls(gate_events), stream_tool_calls(direct_events))
        self.assertEqual(finish_reasons(gate_events), finish_reasons(direct_events))
        self.assertEqual(finish_reasons(gate_events), ["tool_calls"])

    def test_non_streaming_tool_calls_remain_available(self) -> None:
        response = httpx.post(
            f"{GATE_URL}/v1/chat/completions",
            json=tool_request(stream=False),
            timeout=45.0,
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["choices"][0]["finish_reason"], "tool_calls")
        tool_calls = body["choices"][0]["message"]["tool_calls"]
        self.assertEqual(tool_calls[0]["function"]["name"], "get_balance")
