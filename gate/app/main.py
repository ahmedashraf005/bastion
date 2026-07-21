"""Transparent, non-streaming OpenAI-compatible proxy for Ollama."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import logging
from time import perf_counter
from typing import Any
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import Boolean, Column, Float, Integer, MetaData, Table, Text, insert
from sqlalchemy.dialects.postgresql import JSONB, UUID as PostgreSQLUUID
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.config import settings


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("bastion.gate")

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
    schema="gate",
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create one async database engine for the Gate process lifetime."""

    app.state.database_engine = create_async_engine(settings.database_url)
    try:
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
                )
            )
    except Exception:
        logger.exception("persistence_failed request_id=%s", request_id)


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

    if stream_requested:
        latency_ms = (perf_counter() - started_at) * 1000
        error = "streaming not yet supported in this build"
        response = JSONResponse(
            status_code=501,
            content={"error": error},
            headers={"X-Bastion-Request-Id": str(request_id)},
        )
        logger.info(
            "request_rejected request_id=%s model=%s latency_ms=%.2f upstream_status=%s",
            request_id,
            requested_model,
            latency_ms,
            "not_called",
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
        )
        return response

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
        )
        return response

    latency_ms = (perf_counter() - started_at) * 1000
    try:
        response_body = upstream_response.json()
        error = None
    except ValueError:
        response_body = None
        error = "upstream response was not valid JSON"

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
    )
    return response
