# ADR-012: Containerization

- Status: Accepted
- Date: 2026-07-23

## Context

Bastion's services currently run as separate host processes while Postgres,
Valkey, and Ollama run through Compose. That makes a full local environment
dependent on several manual startup commands and on host-only `localhost`
addresses. Containerization should make the working stack reproducible without
changing its existing safety or ownership decisions.

## Decision

Gate, Control, SampleBank Copilot, and the dashboard run as Compose services.
Strike also has an image and Compose entry, but it is placed behind a `manual`
profile and remains an explicit `docker compose run strike ...` operation.
Containerization does not create a background campaign worker, queue consumer,
or any new job-control behavior.

Gate's image installs dependencies and the small ungated spaCy model only.
Prompt Guard 2 weights are downloaded at container startup, before Uvicorn,
into a runtime cache volume using `HF_TOKEN` supplied from `.env`. The image
never contains those gated weights. A missing or empty token fails the
container immediately with a clear error.

Ollama models remain in Ollama's named volume. A one-shot
`ollama-model-init` Compose service waits for Ollama's API health check, lists
existing models, and pulls `llama3.1:8b` and `nomic-embed-text` only when they
are absent. Gate and Strike retain their independent Alembic histories, while
Control applies its own EF Core migration at startup; each is gated on the
health of the infrastructure it needs.

Compose supplies internal service-DNS overrides such as `postgres`, `valkey`,
`ollama`, `gate`, and `sample-target`. Host-development defaults remain
`localhost` in each service's existing configuration. Strike preserves its
hardcoded allowlist by selecting only between reviewed host and container
SampleBank endpoints through a boolean container-mode flag, rather than
accepting an arbitrary target URL from the environment.

The dashboard is deliberately different: its JavaScript executes in the
operator's browser, outside the Compose network. Its Vite build therefore
bakes `http://localhost:5080` as the Control API base URL and the static
container serves that build on host port 5173. Control's existing narrowly
scoped development CORS origin remains valid.

## Consequences

`docker compose up` can start the normal interactive stack with service-owned
migrations and model initialization, while a campaign still requires an
intentional human command. Migrations are idempotent on later starts and model
volumes avoid repeated large downloads.

Container addresses are environment-specific wiring, not new application
defaults. Direct host development remains supported by the committed
`localhost` examples. Prompt Guard's cache is runtime state and must be
treated as sensitive licensed-model material rather than an image artifact.

The dashboard continues to use polling and Control remains read-only. This
operational packaging change neither creates a write API nor changes Control's
orchestration responsibilities.
