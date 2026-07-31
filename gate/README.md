# Bastion.Gate

Bastion.Gate is the FastAPI data-plane service for Bastion. It is a
transparent OpenAI-compatible passthrough to a local Ollama instance,
supporting both JSON and SSE chat-completion responses.

Start Postgres from the repository root, then from inside `gate/`, create and
activate a virtual environment, install the dependencies, apply the Gate-owned
migrations, and run the service:

```bash
docker compose up -d postgres
cd gate
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

With an Ollama model already available locally, send a non-streaming request:

```bash
curl http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"<installed-model>","messages":[{"role":"user","content":"Hello"}],"stream":false}'
```

Use `"stream": true` for an SSE response. Gate relays Ollama's event bytes
without reformatting them while reconstructing the assistant content for the
audit record after the stream ends.

Each request is persisted best-effort in the Gate-owned `gate.requests` audit
table. A database write failure is logged but does not prevent the proxy from
returning its already-prepared response. Gate runs Prompt Guard 2 for direct
LLM01 input injection when `HF_TOKEN` is available, Presidio for LLM02 input
PII, and the value-anchored system-prompt leak detector for LLM07 output.
At this revision, the Gate entrypoint requires `HF_TOKEN` to download Prompt
Guard before readiness; the fresh-clone startup change is tracked separately.
Indirect tool-output injection, tool-argument scanning, multi-choice output
scanning, and LLM10 are outside current coverage; see `docs/threat-model.md`.
