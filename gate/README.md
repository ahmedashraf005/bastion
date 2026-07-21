# Bastion.Gate

Bastion.Gate is the FastAPI data-plane service for Bastion. In this first
slice, it is a transparent, non-streaming OpenAI-compatible passthrough to a
local Ollama instance.

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

Each request is persisted best-effort in the Gate-owned `gate.requests` audit
table. A database write failure is logged but does not prevent the proxy from
returning its already-prepared response. Streaming and detection are not yet
implemented. A request with `"stream": true` is deliberately rejected with
HTTP 501 rather than being silently converted into a non-streaming response.
