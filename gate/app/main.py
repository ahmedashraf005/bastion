"""Transparent, non-streaming OpenAI-compatible proxy for Ollama."""

import logging
from time import perf_counter
from uuid import uuid4

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from app.config import settings


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("bastion.gate")

app = FastAPI(title="Bastion.Gate")


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

    request_id = str(uuid4())
    requested_model = body.get("model")
    started_at = perf_counter()

    if body.get("stream") is True:
        latency_ms = (perf_counter() - started_at) * 1000
        logger.info(
            "request_rejected request_id=%s model=%s latency_ms=%.2f upstream_status=%s",
            request_id,
            requested_model,
            latency_ms,
            "not_called",
        )
        return JSONResponse(
            status_code=501,
            content={"error": "streaming not yet supported in this build"},
            headers={"X-Bastion-Request-Id": request_id},
        )

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.ollama_timeout_seconds)
    ) as client:
        upstream_response = await client.post(
            f"{settings.ollama_base_url}/v1/chat/completions",
            json=body,
        )

    latency_ms = (perf_counter() - started_at) * 1000
    logger.info(
        "request_completed request_id=%s model=%s latency_ms=%.2f upstream_status=%s",
        request_id,
        requested_model,
        latency_ms,
        upstream_response.status_code,
    )

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers={
            "Content-Type": upstream_response.headers.get(
                "content-type", "application/json"
            ),
            "X-Bastion-Request-Id": request_id,
        },
    )
