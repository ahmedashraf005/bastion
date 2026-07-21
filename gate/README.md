# Bastion.Gate

Bastion.Gate is the FastAPI data-plane service for Bastion. In this first
slice, it is a transparent, non-streaming OpenAI-compatible passthrough to a
local Ollama instance.

From inside `gate/`, create and activate a virtual environment, install the
dependencies, and run the service:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

With an Ollama model already available locally, send a non-streaming request:

```bash
curl http://localhost:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"<installed-model>","messages":[{"role":"user","content":"Hello"}],"stream":false}'
```

Streaming, request/response persistence, and detection are not implemented in
this slice. A request with `"stream": true` is deliberately rejected with
HTTP 501 rather than being silently converted into a non-streaming response.
