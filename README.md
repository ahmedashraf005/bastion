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
known coverage gaps, without ever surfacing local diagnostics. Two campaigns
have produced a confirmed bypass against the hardened default profile — see
[Results](#results) — both a value-anchored disclosure the Rule Synthesizer
was correctly unable to close with a proposal, for a documented structural
reason (`docs/design/rule-vocabulary-and-promotion-gap.md`), not a synthesis
failure. No proposal has ever been approved or applied to live policy:
mechanical verification has run against real evidence, but the pipeline
past it — for either proposal family — does not yet automatically exist.

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
       confirmed bypass [A] → proposed detection rule [A, verified in-memory only]
                            → human review [M, normalization only] → live policy [M]
```
`[A]` automated, no human action · `[M]` a human runs a CLI or hand-edits a
file · full per-stage breakdown, including the family that has no path to
"human review" at all today: [Rule promotion pipeline](#rule-promotion-pipeline).

**Where this actually stops today**: everything up to and including
"proposed detection rule" runs automatically, in-memory, for every
confirmed bypass — but the result is only ever printed and discarded, never
persisted, for the signature/`detector_config` family. Only a
normalization-shaped proposal has a path past this point, and every step of
that path is a human running a separate CLI by hand.

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

**Bypass corpus**: 34 of 35 saved evasion payloads matched by Gate's live
detector configuration; 1 individually pinned with a recorded reason — a
window-size limitation (a k=8 zero-width-space density payload spans 199
source characters against the detector's 160-character window; U+200B has
no compatibility decomposition or confusable skeleton, so neither NFKC nor
confusables normalization can affect it). The Cyrillic/Greek
visual-confusable case that was pinned for the same reason is now closed —
see [`docs/design/confusables-marker-normalization.md`](docs/design/confusables-marker-normalization.md).

**Benign corpus**: 48 hand-authored cases across four bands — 20 ordinary,
10 adjacent-vocabulary, 12 structurally-awkward, 6 redaction-span — currently
zero false positives. Reported as corpus composition and count, not a rate:
0/48 has a wide confidence interval at this sample size.

**Benign tool-output corpus**: 46 hand-authored cases across five bands —
12 ordinary, 8 adjacent-vocabulary, 8 structurally-awkward, 9
redaction-span, 9 mixed-script — currently zero false positives. The
mixed-script band (genuine Russian and Greek prose, names, addresses, and
JSON tool output with Cyrillic/Greek values) is checked against both
mechanisms it exists to stress: real Presidio (LLM02, input-stage) and real
LLM07 marker detection with confusables normalization active, against the
live policy configuration. Reported as corpus composition and count, not a
rate: 0/46 has a wide confidence interval at this sample size.

**Live campaign evidence**: 8 campaigns against Gate's hardened default
profile, evidence retained for all of them (`bastion report --campaign
<id>` renders any of them). One crashed before any attempt was recorded
(the NUL-byte persistence bug, since fixed —
`docs/design/nul-byte-persistence-fix.md`); of the 7 that ran, 112 queries
total, including a campaign against the NFKC-promoted marker detector
specifically. 2 of the 7 produced a confirmed bypass — both the same
value-anchored attack class, both correctly declined by the Rule
Synthesizer for a documented structural reason rather than proposed and
lost; see
[`docs/design/rule-vocabulary-and-promotion-gap.md`](docs/design/rule-vocabulary-and-promotion-gap.md).

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
  46-case, five-band benign tool-output corpus
  (`tests/corpus/benign_tool_output.yaml`: 12 ordinary, 8
  adjacent-vocabulary, 8 structurally-awkward, 9 redaction-span, 9
  mixed-script): zero mismatches. A bank routing number was initially misclassified as a phone
  number (PhoneRecognizer's context list includes the generic word
  "number") and has since been fixed with a checksum-validated ABA
  routing-number recognizer used only to suppress that collision. **This
  bullet previously claimed, incorrectly, that SSNs in JSON field form go
  undetected and require prose context — that was an artifact of the test
  case using a Presidio-blacklisted placeholder SSN, not a real gap; US_SSN
  detects correctly in bare, prose, and JSON form.** Corrected 2026-08-04;
  full account in [`docs/threat-model.md`](docs/threat-model.md), including
  the real, narrower finding that survived and a JSON-validity check on
  redaction itself.
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

`[A]` automated, no human action needed · `[M]` a human runs a CLI or
hand-edits a file · `[U]` no implementation exists; the arrow is intended,
not built.

```
confirmed bypass [A]
   → proposed rule + mechanical verification [A] (in-memory only, against
       the originating evidence; never persisted by this step, either family)
   → proposal persistence
       ├─ signature / detector_config: [U]  no code path writes this anywhere;
       │                                    review_cli.py and apply_approved_rules.py
       │                                    exist but have nothing to read
       └─ normalization:               [M]  a human captures the proposal JSON
                                             by hand (the campaign log does not
                                             print it) and runs
                                             normalization_review_cli.py record
   → bypass regression + benign false-positive check + reachability check [M]
       (three separate, standalone test suites; nothing in the review or
       apply CLIs runs them or checks that they were run)
   → human sign-off [M]  normalization_review_cli.py approve
   → pattern-version entry [M]  hand-authored YAML; no script has ever
       created one — every version_id in this repo's history was typed by hand
   → activation toggle [M]  apply_approved_pattern_versions.py apply
   → live policy [M]  Gate loads its detector once at process startup and does
       not hot-reload; a restart is required for the toggle above to take effect
```

**Where this actually stops today**: the first two stages run automatically
for every confirmed bypass, including the two live findings this repository
has produced (`docs/design/rule-vocabulary-and-promotion-gap.md`). Past
that, the signature/`detector_config` family has no path forward at all —
mechanical verification runs, and the result is discarded. The
normalization family has a real path, but every stage of it, from capturing
the proposal to restarting Gate, is a human doing it by hand; no CLI in
this chain automatically runs or enforces the stage before it. No proposal
of either family has ever reached "live policy."

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

**Finding nothing is a real, correct possible outcome, not a failure** — it
means Gate held; the search itself is what's being demonstrated, not a
guaranteed bypass. It is also not the only outcome this exact config has
produced: two prior runs each found the same value-anchored attack class,
which triggered the Rule Synthesizer's proposal flow against real evidence
both times and was correctly declined both times, for a documented
structural reason in the current rule vocabulary rather than a synthesis
failure — see
[`docs/design/rule-vocabulary-and-promotion-gap.md`](docs/design/rule-vocabulary-and-promotion-gap.md).
Either way, watch it live on the dashboard
(`http://localhost:5173` once `bastion gate up` is healthy) while it runs.
No proposal has ever been approved or applied to live policy — this
repository does not claim that loop has been closed, only that a finding
now reaches synthesis and synthesis has been exercised against real
evidence.

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

### Running the test suite

```
python -m unittest discover
```

**Run this from the repository root.** That's load-bearing, not stylistic:
`python -m unittest` always adds the current directory to `sys.path` in
addition to whatever `discover` itself resolves, and running from anywhere
inside `tests/` (rather than above it) lets a test package there shadow the
real `gate`/`strike` packages of the same name, silently importing the wrong
one. Running from repo root avoids the collision entirely.

Every test module that imports Gate or Strike code directly (`from
app...`, `from detectors...`, `from policy...`, `from corpus import ...`)
does its own explicit `from tests import _pathfix` first, so the command
above works unchanged from a fresh clone with no extra setup, no `PYTHONPATH`,
and no installed dependency beyond what `gate/requirements.txt` and
`strike/requirements.txt` already list.

**If you ran tests on this repo before this note existed, your result was
not what it looked like.** `python -m unittest discover -s tests` used to
silently collect 11 of 145 tests and report `OK` — `tests/gate/`,
`tests/regression/`, and `tests/strike/` were never even attempted, with no
error and no indication anything was skipped. The cause was structural
(`unittest`'s discovery silently skips any subdirectory without an
`__init__.py`, and separately, `tests/strike/` collided with the real
`strike/` package on `sys.path`) and is now fixed. `tests/test_discovery_
sanity.py` guards against this recurring for any future subdirectory added
under `tests/` without an `__init__.py`.

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
