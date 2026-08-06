"""persist_request() sanitizes NUL bytes immediately before the DB write.

Uses a fake engine/connection that captures the compiled INSERT statement
rather than a live Postgres connection, matching this project's existing
test conventions (no test in this suite requires a live database). The
live-Postgres reproduction and fix confirmation are recorded in
docs/design/nul-byte-persistence-fix.md.
"""

from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace
from uuid import uuid4

from tests import _pathfix  # noqa: F401
from app.main import persist_request


class FakeConnection:
    def __init__(self) -> None:
        self.executed_statement = None

    async def execute(self, statement) -> None:
        self.executed_statement = statement

    async def __aenter__(self) -> "FakeConnection":
        return self

    async def __aexit__(self, *exc_info) -> bool:
        return False


class FakeEngine:
    def __init__(self) -> None:
        self.connection = FakeConnection()

    def begin(self) -> FakeConnection:
        return self.connection


def fake_request(engine: FakeEngine) -> SimpleNamespace:
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(database_engine=engine)))


class PersistRequestSanitizationTests(unittest.TestCase):
    def _params(self, engine: FakeEngine) -> dict:
        return engine.connection.executed_statement.compile().params

    def test_nul_byte_in_response_body_is_stripped_and_flagged(self) -> None:
        engine = FakeEngine()
        response_body = {
            "choices": [
                {"message": {"role": "assistant", "content": "the token is B\x00ASTION"}}
            ]
        }

        async def exercise() -> None:
            await persist_request(
                fake_request(engine),
                request_id=uuid4(),
                model="test-model",
                stream_requested=False,
                request_body={"messages": [{"role": "user", "content": "hi"}]},
                response_body=response_body,
                upstream_status=200,
                latency_ms=1.0,
                error=None,
            )

        asyncio.run(exercise())
        params = self._params(engine)
        self.assertEqual(
            params["response_body"]["choices"][0]["message"]["content"],
            "the token is BASTION",
        )
        self.assertTrue(params["sanitized"])
        # The original object passed in must be untouched (evidence integrity).
        self.assertIn("\x00", response_body["choices"][0]["message"]["content"])

    def test_clean_request_is_byte_identical_and_unflagged(self) -> None:
        engine = FakeEngine()
        request_body = {"messages": [{"role": "user", "content": "What is my balance?"}]}
        response_body = {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}

        async def exercise() -> None:
            await persist_request(
                fake_request(engine),
                request_id=uuid4(),
                model="test-model",
                stream_requested=False,
                request_body=request_body,
                response_body=response_body,
                upstream_status=200,
                latency_ms=1.0,
                error=None,
            )

        asyncio.run(exercise())
        params = self._params(engine)
        self.assertEqual(params["request_body"], request_body)
        self.assertEqual(params["response_body"], response_body)
        self.assertFalse(params["sanitized"])

    def test_nul_byte_in_error_field_is_stripped_and_flagged(self) -> None:
        engine = FakeEngine()

        async def exercise() -> None:
            await persist_request(
                fake_request(engine),
                request_id=uuid4(),
                model="test-model",
                stream_requested=False,
                request_body={"messages": []},
                response_body=None,
                upstream_status=None,
                latency_ms=None,
                error="upstream failed: bad\x00byte in response",
            )

        asyncio.run(exercise())
        params = self._params(engine)
        self.assertEqual(params["error"], "upstream failed: badbyte in response")
        self.assertTrue(params["sanitized"])

    def test_lone_surrogate_in_response_body_jsonb_field_is_stripped_and_flagged(self) -> None:
        """response_body is a JSONB column (gate/app/main.py), not Text --
        Postgres rejects a lone surrogate there server-side with
        InvalidTextRepresentationError, a different exception than the
        client-side one Text columns raise. Both paths go through the same
        sanitizer, so this must be covered here too, not just for Text.
        """

        engine = FakeEngine()
        response_body = {
            "choices": [
                {"message": {"role": "assistant", "content": "the token is B\ud800ASTION"}}
            ]
        }

        async def exercise() -> None:
            await persist_request(
                fake_request(engine),
                request_id=uuid4(),
                model="test-model",
                stream_requested=False,
                request_body={"messages": [{"role": "user", "content": "hi"}]},
                response_body=response_body,
                upstream_status=200,
                latency_ms=1.0,
                error=None,
            )

        asyncio.run(exercise())
        params = self._params(engine)
        self.assertEqual(
            params["response_body"]["choices"][0]["message"]["content"],
            "the token is BASTION",
        )
        self.assertTrue(params["sanitized"])

    def test_valid_astral_character_in_response_body_survives_unmangled(self) -> None:
        engine = FakeEngine()
        response_body = {
            "choices": [{"message": {"role": "assistant", "content": "here you go \U0001f600"}}]
        }

        async def exercise() -> None:
            await persist_request(
                fake_request(engine),
                request_id=uuid4(),
                model="test-model",
                stream_requested=False,
                request_body={"messages": [{"role": "user", "content": "hi"}]},
                response_body=response_body,
                upstream_status=200,
                latency_ms=1.0,
                error=None,
            )

        asyncio.run(exercise())
        params = self._params(engine)
        self.assertEqual(params["response_body"], response_body)
        self.assertFalse(params["sanitized"])

    def test_lone_surrogate_row_is_persisted_not_silently_swallowed(self) -> None:
        """Before this fix, a lone surrogate reaching the write would raise
        (DataError/UnicodeEncodeError for Text columns, or
        InvalidTextRepresentationError for JSONB columns -- see
        docs/design/nul-byte-persistence-fix.md), and persist_request()'s
        broad `except Exception` would swallow it silently, dropping the
        audit row with no trace at all -- worse than Strike's crash, because
        it fails invisibly. This simulates that same rejection at the
        connection layer to prove sanitizing at the boundary means execute()
        never receives the offending character, so the row is actually
        written instead of being dropped.
        """

        class RejectsLoneSurrogates(FakeConnection):
            async def execute(self, statement) -> None:
                for value in statement.compile().params.values():
                    text = value if isinstance(value, str) else repr(value)
                    if any(0xD800 <= ord(character) <= 0xDFFF for character in text):
                        raise RuntimeError(
                            "simulated InvalidTextRepresentationError: lone surrogate"
                        )
                await super().execute(statement)

        class RejectingEngine(FakeEngine):
            def __init__(self) -> None:
                self.connection = RejectsLoneSurrogates()

        engine = RejectingEngine()

        async def exercise() -> None:
            await persist_request(
                fake_request(engine),
                request_id=uuid4(),
                model="test-model",
                stream_requested=False,
                request_body={"messages": []},
                response_body=None,
                upstream_status=None,
                latency_ms=None,
                error="upstream failed: bad\ud800surrogate in response",
            )

        asyncio.run(exercise())
        # The row was actually written -- not dropped by the broad except.
        self.assertIsNotNone(engine.connection.executed_statement)
        params = self._params(engine)
        self.assertEqual(params["error"], "upstream failed: badsurrogate in response")
        self.assertTrue(params["sanitized"])

    def test_persistence_still_best_effort_on_a_real_failure(self) -> None:
        """Sanitization must not defeat the existing best-effort contract:
        persist_request() never raises, even if the write itself fails for
        an unrelated reason."""

        class FailingConnection(FakeConnection):
            async def execute(self, statement) -> None:
                raise RuntimeError("connection lost")

        class FailingEngine(FakeEngine):
            def __init__(self) -> None:
                self.connection = FailingConnection()

        engine = FailingEngine()

        async def exercise() -> None:
            await persist_request(
                fake_request(engine),
                request_id=uuid4(),
                model="test-model",
                stream_requested=False,
                request_body={"messages": []},
                response_body=None,
                upstream_status=200,
                latency_ms=1.0,
                error=None,
            )

        asyncio.run(exercise())  # must not raise


if __name__ == "__main__":
    unittest.main()
