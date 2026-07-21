"""Transparent, non-streaming OpenAI-compatible proxy for Ollama."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from sqlalchemy import Boolean, Column, Float, Integer, MetaData, Table, Text, insert
from sqlalchemy.dialects.postgresql import JSONB, UUID as PostgreSQLUUID
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.config import settings
from detectors.base import DetectorSignal
from detectors.presidio_pii import PresidioPiiDetector
from detectors.prompt_guard import PromptGuardDetector
from detectors.system_prompt_leak import SystemPromptLeakDetector
from policy.engine import PolicyEngine


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("bastion.gate")

RULES_PATH = Path(__file__).resolve().parent.parent / "policy" / "rules.yaml"
LEAK_PATTERNS_PATH = (
    Path(__file__).resolve().parent.parent / "detectors" / "leak_patterns.yaml"
)
PII_ENTITIES_PATH = (
    Path(__file__).resolve().parent.parent / "detectors" / "pii_entities.yaml"
)

requests_table = Table(
    "requests",
    MetaData(),
    Column("id", PostgreSQLUUID(as_uuid=True), primary_key=True),
    Column("model", Text, nullable=False),
    Column("stream_requested", Boolean, nullable=False),
    Column("request_body", JSONB, nullable=False),
    Column("response_body", JSONB, nullable=True),
    Column("upstream_status", Integer, nullable=True),
    Column("latency_ms", Float(precision=53), nullable=True),
    Column("error", Text, nullable=True),
    Column("policy_action", Text, nullable=True),
    Column("matched_rules", JSONB, nullable=True),
    Column("detector_signals", JSONB, nullable=True),
    schema="gate",
)


@dataclass
class StreamAccumulator:
    """Reconstruct an OpenAI-compatible completion from SSE delta chunks."""

    request_model: str
    stream_id: str | None = None
    model: str | None = None
    content_parts: list[str] = field(default_factory=list)
    finish_reason: str | None = None
    usage: Any | None = None
    usage_seen: bool = False
    terminal_seen: bool = False

    def consume_sse_line(self, line: bytes) -> None:
        """Parse one complete SSE data line without altering relayed bytes."""

        if not line.startswith(b"data:"):
            return

        payload = line[5:].lstrip()
        if payload == b"[DONE]":
            self.terminal_seen = True
            return

        try:
            chunk = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return

        if not isinstance(chunk, dict):
            return

        chunk_id = chunk.get("id")
        if isinstance(chunk_id, str):
            self.stream_id = chunk_id

        chunk_model = chunk.get("model")
        if isinstance(chunk_model, str):
            self.model = chunk_model

        if chunk.get("usage") is not None:
            self.usage = chunk["usage"]
            self.usage_seen = True

        choices = chunk.get("choices")
        if not isinstance(choices, list) or not choices:
            return

        choice = choices[0]
        if not isinstance(choice, dict):
            return

        delta = choice.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("content"), str):
            self.content_parts.append(delta["content"])

        if choice.get("finish_reason") is not None:
            self.finish_reason = str(choice["finish_reason"])
            self.terminal_seen = True

    def response_body(self) -> dict[str, Any]:
        """Build the persisted non-streaming-shaped response body."""

        response_body: dict[str, Any] = {
            "id": self.stream_id,
            "object": "chat.completion",
            "model": self.model or self.request_model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "".join(self.content_parts),
                    },
                    "finish_reason": self.finish_reason,
                }
            ],
        }
        if self.usage_seen:
            response_body["usage"] = self.usage
        return response_body


def first_assistant_message(response_body: Any) -> dict[str, Any] | None:
    """Return the first assistant message from an OpenAI-compatible response."""

    if not isinstance(response_body, dict):
        return None
    choices = response_body.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    choice = choices[0]
    if not isinstance(choice, dict):
        return None
    message = choice.get("message")
    return message if isinstance(message, dict) else None


def merge_matched_rules(*rule_groups: list[str]) -> list[str] | None:
    """Merge stage results in order while retaining each rule ID once."""

    merged: list[str] = []
    for rule_group in rule_groups:
        for rule_id in rule_group:
            if rule_id not in merged:
                merged.append(rule_id)
    return merged or None


def most_recent_user_message(body: dict[str, Any]) -> dict[str, Any] | None:
    """Return the latest string-content user message for input-side redaction."""

    messages = body.get("messages")
    if not isinstance(messages, list):
        return None

    for message in reversed(messages):
        if (
            isinstance(message, dict)
            and message.get("role") == "user"
            and isinstance(message.get("content"), str)
        ):
            return message
    return None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create Gate's process-lifetime infrastructure and defensive components."""

    app.state.database_engine = create_async_engine(settings.database_url)
    try:
        app.state.policy_engine = PolicyEngine.from_yaml(RULES_PATH)
        app.state.system_prompt_leak_detector = SystemPromptLeakDetector.from_yaml(
            LEAK_PATTERNS_PATH
        )
        app.state.presidio_pii_detector = PresidioPiiDetector.from_yaml(
            PII_ENTITIES_PATH
        )
        app.state.presidio_analyzer = app.state.presidio_pii_detector.analyzer
        app.state.presidio_anonymizer = app.state.presidio_pii_detector.anonymizer
        if not settings.hf_token:
            raise RuntimeError(
                "HF_TOKEN is required to download the gated Prompt Guard 2 model; "
                "set it in .env"
            )
        app.state.prompt_guard_detector = PromptGuardDetector.load()
        yield
    finally:
        await app.state.database_engine.dispose()


app = FastAPI(title="Bastion.Gate", lifespan=lifespan)


async def persist_request(
    request: Request,
    *,
    request_id: UUID,
    model: str,
    stream_requested: bool,
    request_body: dict[str, Any],
    response_body: Any | None,
    upstream_status: int | None,
    latency_ms: float | None,
    error: str | None,
    policy_action: str | None = None,
    matched_rules: list[str] | None = None,
    detector_signals: list[dict[str, Any]] | None = None,
) -> None:
    """Best-effort persistence that never changes the proxy response."""

    try:
        database_engine: AsyncEngine = request.app.state.database_engine
        async with database_engine.begin() as connection:
            await connection.execute(
                insert(requests_table).values(
                    id=request_id,
                    model=model,
                    stream_requested=stream_requested,
                    request_body=request_body,
                    response_body=response_body,
                    upstream_status=upstream_status,
                    latency_ms=latency_ms,
                    error=error,
                    policy_action=policy_action,
                    matched_rules=matched_rules,
                    detector_signals=detector_signals,
                )
            )
    except Exception:
        logger.exception("persistence_failed request_id=%s", request_id)


async def relay_stream(
    request: Request,
    *,
    client: httpx.AsyncClient,
    upstream_response: httpx.Response,
    request_id: UUID,
    model: str,
    request_body: dict[str, Any],
    started_at: float,
    policy_action: str | None,
    matched_rules: list[str] | None,
    detector_signals: list[dict[str, Any]],
) -> AsyncIterator[bytes]:
    """Relay upstream SSE bytes and persist one audit row when the stream ends."""

    accumulator = StreamAccumulator(request_model=model)
    line_buffer = bytearray()
    client_disconnected = False
    upstream_error: str | None = None
    cancellation: asyncio.CancelledError | None = None

    try:
        raw_chunks = upstream_response.aiter_raw()
        while True:
            if await request.is_disconnected():
                client_disconnected = True
                break

            try:
                raw_chunk = await anext(raw_chunks)
            except StopAsyncIteration:
                break

            line_buffer.extend(raw_chunk)
            while b"\n" in line_buffer:
                newline_index = line_buffer.index(b"\n")
                line = bytes(line_buffer[:newline_index]).rstrip(b"\r")
                del line_buffer[: newline_index + 1]
                accumulator.consume_sse_line(line)

            yield raw_chunk
    except asyncio.CancelledError as exc:
        client_disconnected = True
        cancellation = exc
    except GeneratorExit:
        client_disconnected = True
        raise
    except httpx.HTTPError as exc:
        upstream_error = f"upstream stream interrupted: {exc.__class__.__name__}: {exc}"
    finally:
        if line_buffer:
            accumulator.consume_sse_line(bytes(line_buffer).rstrip(b"\r"))

        await upstream_response.aclose()
        await client.aclose()

        latency_ms = (perf_counter() - started_at) * 1000
        if client_disconnected:
            error = "client disconnected mid-stream"
            logger.info(
                "stream_client_disconnected request_id=%s model=%s latency_ms=%.2f",
                request_id,
                model,
                latency_ms,
            )
        elif upstream_error is not None:
            error = upstream_error
            logger.info(
                "stream_failed request_id=%s model=%s latency_ms=%.2f error=%s",
                request_id,
                model,
                latency_ms,
                error,
            )
        elif accumulator.terminal_seen:
            error = None
            logger.info(
                "stream_completed request_id=%s model=%s latency_ms=%.2f upstream_status=%s",
                request_id,
                model,
                latency_ms,
                upstream_response.status_code,
            )
        else:
            error = "upstream stream interrupted: ended before a terminal event"
            logger.info(
                "stream_failed request_id=%s model=%s latency_ms=%.2f error=%s",
                request_id,
                model,
                latency_ms,
                error,
            )

        response_body = accumulator.response_body()
        persisted_policy_action = policy_action
        persisted_matched_rules = matched_rules
        persisted_detector_signals = detector_signals

        if accumulator.terminal_seen:
            message = first_assistant_message(response_body)
            assistant_content = (
                message.get("content") if isinstance(message, dict) else ""
            )
            if not isinstance(assistant_content, str):
                assistant_content = ""

            leak_detector: SystemPromptLeakDetector = (
                request.app.state.system_prompt_leak_detector
            )
            output_signal = await leak_detector.scan(assistant_content)
            policy_engine: PolicyEngine = request.app.state.policy_engine
            output_evaluation = policy_engine.evaluate(
                [output_signal], stage="output"
            )
            persisted_matched_rules = merge_matched_rules(
                matched_rules or [], output_evaluation.matched_rules
            )
            persisted_detector_signals = detector_signals + [
                output_signal.model_dump(mode="json")
            ]
            if output_evaluation.matched_rules:
                persisted_policy_action = "detected_after_stream"

        persistence_arguments = {
            "request_id": request_id,
            "model": model,
            "stream_requested": True,
            "request_body": request_body,
            "response_body": response_body,
            "upstream_status": upstream_response.status_code,
            "latency_ms": latency_ms,
            "error": error,
            "policy_action": persisted_policy_action,
            "matched_rules": persisted_matched_rules,
            "detector_signals": persisted_detector_signals,
        }
        if cancellation is not None:
            asyncio.create_task(
                persist_request(request, **persistence_arguments),
                name=f"persist-stream-{request_id}",
            )
        else:
            await persist_request(request, **persistence_arguments)

    if cancellation is not None:
        raise cancellation


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Return a basic liveness response without contacting the upstream."""

    return {"status": "ok"}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    """Forward a non-streaming OpenAI-compatible request to Ollama unchanged."""

    body = await request.json()
    if not isinstance(body, dict):
        return JSONResponse(
            status_code=422,
            content={"error": "request body must be a JSON object"},
        )

    request_id = uuid4()
    requested_model = body.get("model")
    model = requested_model if isinstance(requested_model, str) else ""
    stream_requested = body.get("stream") is True
    started_at = perf_counter()

    latest_user_message = most_recent_user_message(body)
    if latest_user_message is None:
        pii_signal = DetectorSignal(detector="presidio_pii")
    else:
        pii_detector: PresidioPiiDetector = request.app.state.presidio_pii_detector
        pii_signal = await pii_detector.scan(latest_user_message["content"])

    user_content = "\n".join(
        message["content"]
        for message in body.get("messages", [])
        if isinstance(message, dict)
        and message.get("role") == "user"
        and isinstance(message.get("content"), str)
    )
    prompt_guard_detector: PromptGuardDetector = request.app.state.prompt_guard_detector
    detector_signal = await prompt_guard_detector.scan(user_content)
    detector_signals = [
        detector_signal.model_dump(mode="json"),
        pii_signal.model_dump(mode="json"),
    ]
    policy_engine: PolicyEngine = request.app.state.policy_engine
    policy_result = policy_engine.evaluate(
        [detector_signal, pii_signal], stage="input"
    )
    matched_rules = policy_result.matched_rules or None

    if policy_result.action == "block":
        rule_id = policy_result.terminal_rule_id
        latency_ms = (perf_counter() - started_at) * 1000
        response = JSONResponse(
            status_code=400,
            content={"error": "blocked by policy", "rule_id": rule_id},
            headers={"X-Bastion-Request-Id": str(request_id)},
        )
        error = f"blocked by policy: {rule_id}"
        logger.info(
            "request_blocked request_id=%s model=%s latency_ms=%.2f rule_id=%s",
            request_id,
            requested_model,
            latency_ms,
            rule_id,
        )
        await persist_request(
            request,
            request_id=request_id,
            model=model,
            stream_requested=stream_requested,
            request_body=body,
            response_body=None,
            upstream_status=response.status_code,
            latency_ms=latency_ms,
            error=error,
            policy_action="block",
            matched_rules=matched_rules,
            detector_signals=detector_signals,
        )
        return response

    pii_redaction_match = next(
        (
            match
            for match in policy_result.matches
            if match.action == "redact"
            and match.signal.detector == "presidio_pii"
            and match.signal.redacted_content is not None
        ),
        None,
    )
    if pii_redaction_match is not None and latest_user_message is not None:
        latest_user_message["content"] = pii_redaction_match.signal.redacted_content

    if stream_requested:
        client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.ollama_timeout_seconds)
        )
        try:
            upstream_request = client.build_request(
                "POST",
                f"{settings.ollama_base_url}/v1/chat/completions",
                json=body,
            )
            upstream_response = await client.send(upstream_request, stream=True)
        except httpx.RequestError as exc:
            await client.aclose()
            latency_ms = (perf_counter() - started_at) * 1000
            error = f"upstream Ollama request failed ({exc.__class__.__name__}): {exc}"
            response = JSONResponse(
                status_code=502,
                content={"error": "upstream Ollama request failed"},
                headers={"X-Bastion-Request-Id": str(request_id)},
            )
            logger.info(
                "request_failed request_id=%s model=%s latency_ms=%.2f upstream_status=%s",
                request_id,
                requested_model,
                latency_ms,
                response.status_code,
            )
            await persist_request(
                request,
                request_id=request_id,
                model=model,
                stream_requested=True,
                request_body=body,
                response_body=None,
                upstream_status=response.status_code,
                latency_ms=latency_ms,
                error=error,
                policy_action=policy_result.action,
                matched_rules=matched_rules,
                detector_signals=detector_signals,
            )
            return response

        return StreamingResponse(
            relay_stream(
                request,
                client=client,
                upstream_response=upstream_response,
                request_id=request_id,
                model=model,
                request_body=body,
                started_at=started_at,
                policy_action=policy_result.action,
                matched_rules=matched_rules,
                detector_signals=detector_signals,
            ),
            status_code=upstream_response.status_code,
            media_type="text/event-stream",
            headers={"X-Bastion-Request-Id": str(request_id)},
        )

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.ollama_timeout_seconds)
        ) as client:
            upstream_response = await client.post(
                f"{settings.ollama_base_url}/v1/chat/completions",
                json=body,
            )
    except httpx.RequestError as exc:
        latency_ms = (perf_counter() - started_at) * 1000
        error = f"upstream Ollama request failed ({exc.__class__.__name__}): {exc}"
        response = JSONResponse(
            status_code=502,
            content={"error": "upstream Ollama request failed"},
            headers={"X-Bastion-Request-Id": str(request_id)},
        )
        logger.info(
            "request_failed request_id=%s model=%s latency_ms=%.2f upstream_status=%s",
            request_id,
            requested_model,
            latency_ms,
            response.status_code,
        )
        await persist_request(
            request,
            request_id=request_id,
            model=model,
            stream_requested=stream_requested,
            request_body=body,
            response_body=None,
            upstream_status=response.status_code,
            latency_ms=latency_ms,
            error=error,
            policy_action=policy_result.action,
            matched_rules=matched_rules,
            detector_signals=detector_signals,
        )
        return response

    latency_ms = (perf_counter() - started_at) * 1000
    try:
        response_body = upstream_response.json()
        error = None
    except ValueError:
        response_body = None
        error = "upstream response was not valid JSON"

    message = first_assistant_message(response_body)
    assistant_content = message.get("content") if message is not None else ""
    if not isinstance(assistant_content, str):
        assistant_content = ""

    leak_detector: SystemPromptLeakDetector = request.app.state.system_prompt_leak_detector
    output_signal = await leak_detector.scan(assistant_content)
    output_evaluation = policy_engine.evaluate([output_signal], stage="output")
    merged_matched_rules = merge_matched_rules(
        policy_result.matched_rules, output_evaluation.matched_rules
    )
    merged_detector_signals = detector_signals + [output_signal.model_dump(mode="json")]

    if output_evaluation.action == "block":
        rule_id = output_evaluation.terminal_rule_id
        response = JSONResponse(
            status_code=400,
            content={"error": "blocked by policy", "rule_id": rule_id},
            headers={"X-Bastion-Request-Id": str(request_id)},
        )
        error = f"blocked by policy: {rule_id}"
        logger.info(
            "response_blocked request_id=%s model=%s latency_ms=%.2f rule_id=%s",
            request_id,
            requested_model,
            latency_ms,
            rule_id,
        )
        await persist_request(
            request,
            request_id=request_id,
            model=model,
            stream_requested=False,
            request_body=body,
            response_body=None,
            upstream_status=response.status_code,
            latency_ms=latency_ms,
            error=error,
            policy_action="block",
            matched_rules=merged_matched_rules,
            detector_signals=merged_detector_signals,
        )
        return response

    redaction_match = next(
        (
            match
            for match in output_evaluation.matches
            if match.action == "redact" and match.signal.redacted_content is not None
        ),
        None,
    )
    if redaction_match is not None and message is not None:
        message["content"] = redaction_match.signal.redacted_content
        response = JSONResponse(
            content=response_body,
            status_code=upstream_response.status_code,
            headers={"X-Bastion-Request-Id": str(request_id)},
        )
    else:
        response = Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers={
                "Content-Type": upstream_response.headers.get(
                    "content-type", "application/json"
                ),
                "X-Bastion-Request-Id": str(request_id),
            },
        )
    logger.info(
        "request_completed request_id=%s model=%s latency_ms=%.2f upstream_status=%s",
        request_id,
        requested_model,
        latency_ms,
        upstream_response.status_code,
    )
    await persist_request(
        request,
        request_id=request_id,
        model=model,
        stream_requested=stream_requested,
        request_body=body,
        response_body=response_body,
        upstream_status=response.status_code,
        latency_ms=latency_ms,
        error=error,
        policy_action=output_evaluation.action or policy_result.action,
        matched_rules=merged_matched_rules,
        detector_signals=merged_detector_signals,
    )
    return response
