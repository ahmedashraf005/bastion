# Bastion

Bastion is a locally-run purple-team firewall for LLM applications: a
detection and policy gateway (Gate) paired with an autonomous red-team
engine (Strike) that attacks the protected app and feeds confirmed bypasses
back as proposed defensive rules for human sign-off. It never phones home —
everything runs on your machine against local infrastructure, with no
telemetry and no default outbound calls to anything Bastion-owned.

**Status: working local MVP.** Gate is a runnable FastAPI proxy with three
active detectors. Strike runs TAP-style branching campaigns with real
persisted evidence. Control is a read-only .NET API; the dashboard reads it.
`bastion report` renders a campaign's evidence, including near-misses and
known coverage gaps, without ever surfacing local diagnostics. No campaign
has yet produced a confirmed bypass against the hardened default profile —
see [Results](#results) — so the promoted-rule loop is implemented and
tested but not yet demonstrated end to end against live campaign evidence.

## Coverage

- **LLM01 (direct prompt injection)** — Meta's Prompt Guard 2, input stage.
  Degrades gracefully without `HF_TOKEN`: Gate logs an explicit startup
  warning and stays up with LLM02 and LLM07 active; Prompt Guard alone is
  inactive.
- **LLM02 (sensitive information disclosure)** — Presidio, input-side
  detection and redaction before the request reaches the upstream model.
  Scanning tool-role messages for the same PII/secret egress is available
  behind `GATE_SCAN_TOOL_OUTPUT` (opt-in, default off) — see
  [Known gaps](#known-gaps) for what it does and does not cover.
- **LLM07 (system prompt leakage)** — a value-anchored marker detector,
  output stage, on completed non-streaming responses.
- **LLM10 (unbounded consumption)** — planned, not implemented. Gate
  persists model-provided usage when the upstream emits it but does not
  account for, limit, or block on it. Not claimed as coverage anywhere in
  this repository.

Indirect prompt injection (LLM01's indirect half), tool-argument egress, and
multi-choice output scanning are open gaps — see [Known gaps](#known-gaps).

## Architecture

```text
                    React/Vite/TypeScript Dashboard (read-only)
                         campaigns · findings · traffic
                                      │ REST (fetch)
                                      ▼
              Bastion.Control (.NET 10 Web API, read-only)
                    campaigns · findings · proposed rules
                          │                         │
                      Postgres                 Valkey
              strike/gate/control schemas   StrategyLibrary
──────────────────────────────────────────────────────────────────────
              Bastion.Gate (FastAPI, data plane)
Client app ──► OpenAI-compatible /v1/chat/completions proxy ──► Upstream LLM
              input detection (LLM01, LLM02) · policy decision
              streaming passthrough · output inspection (LLM07)
                                                            host-native Ollama

              Bastion.Strike (on-demand red-team campaign runner)
              TAP planning · PruneGate · strategy retrieval
              attacks the protected SampleBank Copilot only
                                      │
                                      ▼
              confirmed bypass → proposed detection rule
                              → human review → live policy
```

Control has no authentication or RBAC — it is an internal, read-only
observability API, not a security boundary, and must not be exposed as a
production management interface. See `docs/threat-model.md`.

## Repository layout

- `gate/` — FastAPI OpenAI-compatible interceptor proxy and detectors.
- `control/` — read-only .NET control-plane API.
- `strike/` — on-demand red-team campaigns, `bastion report`, and human
  review CLIs.
- `sample-target/` — deliberately vulnerable SampleBank Copilot.
- `dashboard/` — read-only React/Vite campaign and traffic dashboard.
- `scripts/` — database backup/restore.
- `docs/` — threat model, architectural decisions, design notes, and
  benchmark writeups.

The repository currently contains 14 ADR documents; they describe decisions,
not additional runtime dependencies.

## Results

**AgentDojo banking suite** (external benchmark, ETH Zurich — chosen because
it's a target Bastion's author didn't write): llama3.1:8b lands **25.00%
benign utility / 0.00% targeted ASR**; qwen2.5:7b lands **50.00% / 18.75%**.
The injection-task-as-direct-user-task control (6/9 and 7/9 respectively) is
what makes those ASR figures readable — it confirms both models can perform
the underlying actions when asked directly, so llama3.1:8b's 0% reads as
resistance, not incapacity. **Not comparable** to AgentDojo's published
GPT-4o numbers — no hosted inference is used anywhere in this project. Full
method, reproduction steps, and the 45-second-timeout finding on
qwen2.5:7b: [`docs/benchmarks/agentdojo.md`](docs/benchmarks/agentdojo.md).

**Bypass corpus**: 33 of 35 saved evasion payloads matched by Gate's live
detector configuration; 2 individually pinned with recorded reasons — a
window-size limitation (a k=8 zero-width-space density payload spans 199
source characters against the detector's 160-character window) and Cyrillic/
Greek visual-confusable substitution (needs a UTS #39 confusables map,
separate work; NFKC normalization, which closed 4 other formerly-pinned
cases, provably does not touch either payload).

**Benign corpus**: 48 hand-authored cases across four bands — 20 ordinary,
10 adjacent-vocabulary, 12 structurally-awkward, 6 redaction-span — currently
zero false positives. Reported as corpus composition and count, not a rate:
0/48 has a wide confidence interval at this sample size.

**Live campaign evidence**: 45 adversarial queries across 3 campaigns
against Gate's hardened default profile, zero confirmed bypasses, evidence
retained (`bastion report --campaign <id>` renders any of them). This
includes a campaign run against the NFKC-promoted marker detector
specifically.

## Known gaps

Full detail: [`docs/threat-model.md`](docs/threat-model.md).

- **Indirect prompt injection.** Prompt Guard (LLM01) scans user-role
  message text only; it is never run over tool-role content, and
  assistant-role content is not input-scanned by anything. Payloads
  delivered through tool output or retrieved context are outside current
  LLM01 coverage — AgentDojo's `important_instructions` attack is the
  concrete known example, and its defense cells stay cancelled.
- **Tool-output PII scanning covers egress only, and only partially.**
  `GATE_SCAN_TOOL_OUTPUT` (opt-in, default off) runs Presidio over the
  latest tool-role message and redacts matches, closing part of the LLM02
  gap above — it adds no LLM01/injection coverage. Measured against a
  36-case, four-band benign tool-output corpus
  (`tests/corpus/benign_tool_output.yaml`: 12 ordinary, 8
  adjacent-vocabulary, 8 structurally-awkward, 8 redaction-span), one
  redaction-span case false-positived: a bank routing number, misread as a
  phone number, because Presidio has no financial-identifier recognizer.
  The same gap causes a false negative in the feature's main use case: an
  SSN in JSON field form (`{"ssn": "078-05-1120"}`) is not detected at all —
  the recognizer needs prose context. Full account, including a
  JSON-validity check on the redaction itself, in
  [`docs/threat-model.md`](docs/threat-model.md).
- **Tool-argument egress.** The output-stage leak detector does not scan
  tool-call arguments — a canary or PII value carried there is not caught
  the way one in message content is.
- **Multi-choice output scanning.** With `n > 1`, only the first choice is
  output-scanned.
- **LLM10.** Not implemented — see [Coverage](#coverage).
- **Promoted-rule reachability is not guaranteed by the promotion gates.**
  A rule can pass mechanical verification, bypass regression, and the
  benign-corpus check, and still be consulted by nothing, if the detector
  path it targets isn't the one currently active. This happened: a
  correctly-promoted Cf-category normalization had zero effect on live
  detection from the day it landed (2026-07-29) until it was found and
  deactivated (2026-08-03), because the active marker-matching path never
  called the mechanism it extended. Now covered by a reachability test
  requiring an individually-justified allowlist entry for any known
  exception. Full account:
  [`docs/design/value-anchored-marker-detection.md`](docs/design/value-anchored-marker-detection.md).

## Rule promotion pipeline

```
confirmed bypass → proposed rule
                 → mechanical verification (against the originating evidence)
                 → bypass regression (every retained known bypass still blocks)
                 → benign false-positive check (fixed corpus bands)
                 → reachability check (is the active pattern actually reachable)
                 → human sign-off
                 → live policy
```

No rule reaches live policy without a human approving it. The technical
gates catch correctness and blast radius; they do not replace the sign-off.

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
demonstrated end to end against a live campaign finding.

After either campaign, render its evidence:

```bash
bastion report --campaign <campaign-id>          # text
bastion report --campaign <campaign-id> --format json
```

The report covers campaign identity and provenance, coverage (every attempt
including pruned ones, not just matches), confirmed findings with a
four-way remediation split, near-misses with edit distance and positional
overlap, and the known coverage gaps above — restated so a clean report
reads as deliberate evidence, not silence. Local diagnostics (`error_type`,
tracebacks) never appear in its output, in either format.

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
