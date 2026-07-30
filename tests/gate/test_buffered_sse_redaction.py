"""Hermetic fidelity coverage for Gate's buffered output-redaction path."""

from __future__ import annotations

import asyncio
import json
import unittest
from collections.abc import AsyncIterator
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from starlette.requests import Request

from app import main as gate_main
from detectors.base import DetectorSignal


RECORDED_UPSTREAM_SSE = b""": keepalive\n\n""" + b"""data: {\"id\":\"chatcmpl-fixture\",\"object\":\"chat.completion.chunk\",\"created\":1234567890,\"model\":\"fixture-model\",\"system_fingerprint\":\"fp-fixture\",\"service_tier\":\"default\",\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18},\"choices\":[{\"index\":7,\"delta\":{\"role\":\"assistant\",\"content\":\"LEAK-\",\"tool_calls\":[{\"id\":\"call_fixture\",\"index\":0,\"type\":\"function\",\"function\":{\"name\":\"get_balance\",\"arguments\":\"{}\"}}],\"provider_extension\":{\"trace\":\"kept\"}},\"logprobs\":null,\"finish_reason\":null},{\"index\":9,\"delta\":{\"role\":\"assistant\",\"content\":\"KEEP-ME\",\"reasoning_content\":\"unrelated\"},\"logprobs\":{\"content\":[]},\"finish_reason\":null}]}\n\n""" + b"""data: {\"id\":\"chatcmpl-fixture\",\"object\":\"chat.completion.chunk\",\"created\":1234567890,\"model\":\"fixture-model\",\"system_fingerprint\":\"fp-fixture\",\"service_tier\":\"default\",\"choices\":[{\"index\":7,\"delta\":{\"content\":\"SECRET\"},\"logprobs\":null,\"finish_reason\":\"tool_calls\"},{\"index\":9,\"delta\":{\"content\":\"-UNCHANGED\"},\"logprobs\":null,\"finish_reason\":\"length\"}]}\n\n""" + b"data: [DONE]\n\n"


def events(raw_sse: bytes) -> list[dict]:
    return [
        json.loads(line[5:].strip())
        for line in raw_sse.decode("utf-8").splitlines()
        if line.startswith("data:") and line[5:].strip() != "[DONE]"
    ]


class FixtureUpstreamResponse:
    status_code = 200

    async def aiter_raw(self) -> AsyncIterator[bytes]:
        # Deliberately split inside events: the accumulator must handle real
        # transport segmentation before redacting and re-emitting the stream.
        yield RECORDED_UPSTREAM_SSE[:193]
        yield RECORDED_UPSTREAM_SSE[193:]

    async def aclose(self) -> None:
        return None


class FixtureClient:
    async def aclose(self) -> None:
        return None


class FixtureLeakDetector:
    async def scan(self, content: str) -> DetectorSignal:
        if content != "LEAK-SECRET":
            raise AssertionError(f"fixture did not reconstruct the protected content: {content!r}")
        return DetectorSignal(
            detector="system_prompt_leak",
            matched=True,
            redacted_content="[REDACTED]",
        )


class FixturePolicyEngine:
    def evaluate(self, signals: list[DetectorSignal], *, stage: str) -> SimpleNamespace:
        if stage != "output" or signals[0].redacted_content != "[REDACTED]":
            raise AssertionError("fixture did not exercise output redaction")
        return SimpleNamespace(
            action="redact",
            matched_rules=["fixture-redact-rule"],
            matches=[SimpleNamespace(action="redact", signal=signals[0])],
        )


class BufferedSSERedactionTests(unittest.TestCase):
    """Redaction may alter content, never the surrounding OpenAI SSE shape."""

    def test_redaction_preserves_tool_calls_and_unrelated_choice_fields(self) -> None:
        app = FastAPI()
        app.state.system_prompt_leak_detector = FixtureLeakDetector()
        app.state.policy_engine = FixturePolicyEngine()
        request = Request({"type": "http", "method": "POST", "path": "/v1/chat/completions", "app": app})

        async def collect() -> bytes:
            parts = [
                part
                async for part in gate_main.relay_buffered_stream(
                    request,
                    client=FixtureClient(),
                    upstream_response=FixtureUpstreamResponse(),
                    request_id=gate_main.uuid4(),
                    model="fixture-model",
                    request_body={"model": "fixture-model", "stream": True},
                    started_at=0.0,
                    policy_action=None,
                    matched_rules=None,
                    detector_signals=[],
                )
            ]
            return b"".join(parts)

        with patch.object(gate_main, "persist_request", new=AsyncMock()):
            redacted_sse = asyncio.run(collect())

        original_events = events(RECORDED_UPSTREAM_SSE)
        redacted_events = events(redacted_sse)
        self.assertEqual(len(redacted_events), len(original_events))
        self.assertIn(b": keepalive\n\n", redacted_sse)

        original_first, original_second = original_events
        redacted_first, redacted_second = redacted_events
        for original, redacted in ((original_first, redacted_first), (original_second, redacted_second)):
            self.assertEqual(redacted["id"], original["id"])
            self.assertEqual(redacted["object"], original["object"])
            self.assertEqual(redacted["created"], original["created"])
            self.assertEqual(redacted["model"], original["model"])
            self.assertEqual(redacted["system_fingerprint"], original["system_fingerprint"])
            self.assertEqual(redacted["service_tier"], original["service_tier"])
            self.assertEqual(
                [choice["index"] for choice in redacted["choices"]],
                [choice["index"] for choice in original["choices"]],
            )
            self.assertEqual(
                [choice["finish_reason"] for choice in redacted["choices"]],
                [choice["finish_reason"] for choice in original["choices"]],
            )

        self.assertEqual(redacted_first["usage"], original_first["usage"])
        self.assertEqual(
            redacted_first["choices"][0]["delta"]["tool_calls"],
            original_first["choices"][0]["delta"]["tool_calls"],
        )
        self.assertEqual(
            redacted_first["choices"][0]["delta"]["provider_extension"],
            original_first["choices"][0]["delta"]["provider_extension"],
        )
        self.assertEqual(redacted_first["choices"][0]["delta"]["content"], "[REDACTED]")
        self.assertEqual(redacted_second["choices"][0]["delta"]["content"], "")
        self.assertEqual(redacted_first["choices"][1]["delta"]["content"], "KEEP-ME")
        self.assertEqual(redacted_second["choices"][1]["delta"]["content"], "-UNCHANGED")
