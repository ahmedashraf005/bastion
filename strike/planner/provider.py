"""Provider-neutral schema-constrained chat calls for Strike planners."""

from __future__ import annotations

from typing import Any

import httpx


class PlannerChatClient:
    """Adapt Ollama's native format and OpenAI's response_format contract."""

    def __init__(
        self,
        provider: str = "ollama",
        *,
        ollama_base_url: str,
        openai_base_url: str,
        openai_api_key: str | None,
    ) -> None:
        if provider not in {"ollama", "openai"}:
            raise ValueError(f"unsupported planner provider: {provider}")
        if provider == "openai" and not openai_api_key:
            raise ValueError(
                "--planner openai requires OPENAI_API_KEY; no hosted provider is used by default"
            )
        self.provider = provider
        self._ollama_base_url = ollama_base_url.rstrip("/")
        self._openai_base_url = openai_base_url.rstrip("/")
        self._openai_api_key = openai_api_key

    async def complete(
        self,
        client: httpx.AsyncClient,
        *,
        model: str,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        schema_name: str,
    ) -> str:
        body: dict[str, Any] = {"model": model, "messages": messages, "stream": False}
        headers: dict[str, str] = {}
        if self.provider == "openai":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "strict": True, "schema": schema},
            }
            headers["Authorization"] = f"Bearer {self._openai_api_key}"
            endpoint = f"{self._openai_base_url}/chat/completions"
        else:
            body["format"] = schema
            endpoint = f"{self._ollama_base_url}/api/chat"

        response = await client.post(endpoint, headers=headers, json=body)
        response.raise_for_status()
        response_body = response.json()
        if self.provider == "openai":
            raw_output = response_body["choices"][0]["message"]["content"]
        else:
            raw_output = response_body["message"]["content"]
        if not isinstance(raw_output, str):
            raise ValueError("planner response content was not a string")
        return raw_output
