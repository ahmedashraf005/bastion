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
returning its already-prepared response. Detection is not implemented yet.
