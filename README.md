# Bastion

> Bastion is a self-hostable AI gateway that inspects and blocks malicious LLM
> traffic (blue team) while an autonomous adversarial engine continuously
> red-teams the protected app and feeds confirmed bypasses back as new
> defensive rules (red team) — attack and defense against the same target, in
> one product.

**Status: working local MVP.** The repository contains a runnable FastAPI Gate
proxy, TAP-style Strike campaigns, the deliberately vulnerable SampleBank
target, the read-only Control API, and the dashboard. Gate covers LLM01 direct
prompt injection when Prompt Guard is enabled, LLM02 input PII, and LLM07
output leakage. Strike records branching campaign evidence and the Rule
Synthesizer produces proposals for human sign-off.

The remaining boundaries are recorded in [`docs/threat-model.md`](docs/threat-model.md):
LLM10 is planned; indirect tool-output injection, tool-argument scanning, and
multi-choice output scanning are open gaps. The feedback loop is review-gated;
this repository does not claim a demonstrated promoted-rule loop.

## Target architecture

```text
                         React/Vite/TypeScript Dashboard
                    policies · live traffic · findings · loop
                                      │ REST + WebSocket
                                      ▼
              Bastion.Control (.NET Web API, control plane)
                 policies · findings · RBAC · job control
                          │                         │
                      Postgres                 Valkey
             policies/findings/audit      pub/sub · queue · vectors
──────────────────────────────────────────────────────────────────────
              Bastion.Gate (FastAPI, data plane)
Client app ──► OpenAI-compatible /v1/chat/completions proxy ──► Upstream LLM
              input detection · policy decision · streaming
              output inspection · telemetry · semantic cache
                                                            host-native Ollama

              Bastion.Strike (on-demand red-team campaign runner)
              TAP planning · pruning · strategy retrieval
              attacks the protected SampleBank Copilot only
                                      │
                                      ▼
              confirmed bypass → proposed detection rule
                              → human review → live policy
```

## Repository layout

- `gate/` — FastAPI OpenAI-compatible interceptor proxy and detectors.
- `control/` — read-only .NET control-plane API.
- `strike/` — on-demand red-team campaigns and human review CLIs.
- `sample-target/` — deliberately vulnerable SampleBank Copilot.
- `dashboard/` — read-only React/Vite campaign and traffic dashboard.
- `docs/` — threat model, architectural decisions, and finding writeups.

The repository currently contains 14 ADR documents; they describe decisions,
not additional runtime dependencies.

## Quickstart

The supported path is Docker Compose plus host-native Ollama. Install Ollama
on the host, then set it to listen on all interfaces (Docker reaches the host
through `host.docker.internal`, not `localhost`, so the default
127.0.0.1-only bind will not work):

```bash
# macOS
launchctl setenv OLLAMA_HOST "0.0.0.0:11434"
# then quit and reopen the Ollama app (or `brew services restart ollama`
# if you installed it via Homebrew as a service)

# Linux (systemd)
sudo systemctl edit ollama.service
# add under [Service]: Environment="OLLAMA_HOST=0.0.0.0:11434"
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

Then pull the two required local models and install Bastion into a virtual
environment:

```bash
ollama pull llama3.1:8b
ollama pull nomic-embed-text
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
bastion gate up
```

`pip install -e .` must run inside a virtual environment: recent Python
distributions (Homebrew, python.org installers) reject system-wide installs
with an `externally-managed-environment` error (PEP 668). Reactivate the venv
(`source .venv/bin/activate`) in any new shell before running `bastion`.

`bastion gate up` waits for Postgres, Gate, SampleBank, Control, the dashboard,
and the model warmup service. `HF_TOKEN` is optional: without it, Gate prints
an explicit warning and runs with LLM02 and LLM07 while Prompt Guard LLM01 is
inactive.

**Timing, measured end to end from a fresh clone:** pulling the two Ollama
models cold (~5.2 GB total) took 6m15s on a ~14 MB/s connection — this
dominates first-run setup and varies with your link. `bastion gate up`
(Docker image build plus health waits, with base images already cached
locally) took ~30s; building the Strike image and running the smoke-test
campaign below took another ~45s. If your Docker base images
(`python:3.14-slim`, `node:22-alpine`, `nginx:1.27-alpine`,
`postgres:17.10-alpine`, `valkey:9.1.0-alpine`) aren't cached yet, add their
pull time on top. With both models already cached, the whole quickstart
through the smoke test after `git clone` is closer to a minute; the
branching campaign described next adds its own ~5 minutes on top of that.

### Two demo campaigns

Once the stack is healthy, there are two reviewed campaigns to run — they
demonstrate different things and take very different amounts of time.

**Smoke test (~15s):** a fixed list of 5 hand-written attempts against
Gate's output-stage redaction. It confirms Gate, SampleBank, Postgres, and
Strike are wired together end to end — nothing more. It does not exercise
the red-team engine.

```bash
bastion strike run --config strike/attempts/canary_leak.yaml
```

**The actual demonstration (~5 minutes):** a TAP-style branching campaign —
adaptive planning, PruneGate scoring candidates, and the Valkey-backed
StrategyLibrary — searching for the same objective within a 20-query / 600s
budget.

```bash
bastion strike run --config strike/attempts/canary_leak_branching.yaml
```

**Expect it to find nothing.** Against Gate's hardened default policy
profile, this is the correct outcome, not a failure: it means Gate held.
What it demonstrates is the search itself — branching candidates generated
and pruned each round, every attempt persisted with a scored outcome, and
the campaign completing cleanly within budget. Watch it live on the
dashboard (`http://localhost:5173` once `bastion gate up` is healthy) while
it runs. A found bypass would trigger the Rule Synthesizer's proposal flow
for human sign-off; that loop is real but not guaranteed on any given run
against a hardened target, and this repository does not claim it has been
demonstrated end to end.

The default planner is local Ollama. `--planner openai` is an explicit opt-in
that requires the caller's `OPENAI_API_KEY` and incurs that provider's cost;
there is no silent fallback. For the containerized Linux inference path, stop
host Ollama and use both `COMPOSE_OLLAMA_BASE_URL=http://ollama:11434` and
`docker compose --profile local-inference up`.

### Running more than one checkout

`bastion` derives its Compose project name from this checkout's absolute
path, so a second clone never recreates the first one's containers using the
second's `.env` — that used to happen silently (including disabling the
first checkout's `HF_TOKEN`-gated Prompt Guard) because `docker-compose.yml`
pinned a single literal project name. On first run, `bastion` writes that
derived name into this checkout's `.env` so a raw `docker compose` command
run in this directory later resolves to the same project. If you want a
stable, predictable name for a given checkout instead of the derived one,
set `COMPOSE_PROJECT_NAME` in its `.env` yourself before the first run;
`bastion` refuses to proceed with a clear error if that name is already
owned by a different checkout on the same machine.

**Raw `docker compose` commands are only as safe as this.** Compose resolves
its project name from `COMPOSE_PROJECT_NAME` in `.env` if present, and
otherwise falls back to the *current directory's name* — not anything
`bastion` computes. A checkout cloned into a directory literally named
`bastion` (the default `git clone` behavior) will collide with any other
`bastion`-named stack on the same machine if you run raw `docker compose`
commands (`down`, `up`, `ps`, ...) before `bastion` has had a chance to
write `COMPOSE_PROJECT_NAME` into `.env` — or if you run them from a
different directory than the one `bastion` wrote it into. This is not
theoretical: a raw `docker compose down -v` run this way once destroyed a
different checkout's containers and database volumes because no persisted
project name existed yet to tell them apart. Prefer `bastion gate up|down|status`;
if you must use raw Compose, pass `-p <name>` explicitly every time, or
confirm `.env` already has `COMPOSE_PROJECT_NAME` set to what you expect.

### Backing up the database

There is no automatic backup — the incident above is the reason this
exists. `scripts/backup_db.sh` dumps the `strike` and `gate` schemas (the
source-of-truth data; `control`'s schema is a read-only projection over the
same data) to a timestamped file under `backups/` (gitignored):

```bash
./scripts/backup_db.sh
```

Run it manually before anything that could disrupt the Postgres volume —
changing `COMPOSE_PROJECT_NAME`, experimenting with a second checkout, or
any raw `docker compose down -v`. To restore:

```bash
./scripts/restore_db.sh backups/bastion-<timestamp>.dump
```

Pass a second argument to restore into a different database instead of the
live one — useful for verifying a backup is good without touching real
data:

```bash
docker compose exec postgres psql -U bastion -d bastion -c \
  "CREATE DATABASE bastion_restore_scratch OWNER bastion;"
./scripts/restore_db.sh backups/bastion-<timestamp>.dump bastion_restore_scratch
```
