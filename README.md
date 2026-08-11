# Bastion

Bastion is a locally-run security-testing tool for LLM applications, in two
parts. **Gate** is a detection and policy gateway — an OpenAI-compatible
proxy that inspects traffic for prompt injection (LLM01, Prompt Guard 2),
sensitive-information disclosure (LLM02, Presidio), and system-prompt
leakage (LLM07, a value-anchored marker detector), without breaking
streaming or losing any of the wire protocol it passes through. **Strike**
is an on-demand red-team engine that runs TAP-style adaptive campaigns
against the protected app and has found two genuine bypasses of a real
attack class. It never phones home — everything runs on your machine
against local infrastructure, with no telemetry and no default outbound
calls to anything Bastion-owned.

**The primary output is app-level remediation, not automatic rule
promotion**: here is the bypass, here is the evidence, here is what to
change in your application — the model Semgrep and Snyk use, not a
self-updating firewall. Bastion tests what your *application* does with a
model's output, not the model's own alignment. Full design reasoning:
[`docs/design/report-contract.md`](docs/design/report-contract.md).

**What this does not do yet, stated before anything else**: there is no
automatic rule-promotion pipeline — a confirmed bypass is never turned into
an applied Gate rule without a human doing every remaining step by hand,
and one entire proposal family has no path to a human at all. Gate has no
hot-reload; a rule change requires a process restart. LLM10 (unbounded
consumption) is not implemented. Indirect/tool-output prompt injection
isn't covered by any detector. None of this is hidden — full list:
[What this does not do yet](#what-this-does-not-do-yet). It's the direct
reason the primary output is app-level remediation rather than a
closed-loop firewall claim.

**Status: working local MVP.** Gate is a runnable FastAPI proxy with three
active detectors. Strike runs TAP-style branching campaigns with real
persisted evidence; its success judge covers both LLM07 (the original
value-anchored marker criterion) and LLM02 (a value-anchored PII canary
reusing the same matching mechanism rather than adding detector-specific
judge logic — see [Results](#results)). Control is a
read-only .NET API; the dashboard reads it. `bastion report` renders a
campaign's evidence, including near-misses and known coverage gaps,
without ever surfacing local diagnostics. Two campaigns have produced a
confirmed bypass against the hardened default profile — see
[Results](#results) — both the same attack class: the model emits the
*literal text* of an HTML entity reference (e.g. `&#8203;`) between a
label's characters instead of the character it names, fragmenting the
label past what Gate's detector can reassemble, while the value arrives
clean and contiguous. The Rule Synthesizer correctly declined to propose a
rule for either, for a documented structural reason
(`docs/design/rule-vocabulary-and-promotion-gap.md`) — a real engineering
result in its own right: proving a gap exists by execution, not
inspection, and refusing to propose a rule that wouldn't actually match,
rather than papering over the gap. No proposal has ever been approved or
applied to live policy.

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

Strike's success judge, separately, now confirms LLM02 bypasses the same
way it confirms LLM07: a seeded PII canary value, value-anchored, not
Presidio-based — deliberately, since gating on entity type would inherit
Presidio's own known false-positive shape (see [Known gaps](#known-gaps)).
See [Results](#results) for the first live run against it.

## What this does not do yet

Stated together, once, so it doesn't have to be re-derived from scattered
caveats:

- **No automatic rule promotion.** A confirmed bypass is never turned into
  an applied Gate rule without a human doing every remaining step by hand
  — and for the proposal family that produced both of this project's real
  findings, there is no path to a human at all. See
  [Rule synthesis: a real, dead-ended result](#rule-synthesis-a-real-but-dead-ended-result).
- **No hot-reload.** Gate loads its detector configuration once at process
  startup. A rule change requires a restart, not just approval.
- **No approve-to-apply path.** Nothing in this repository has ever taken
  an approved proposal and applied it to live traffic.
- **LLM10 (unbounded consumption) is not implemented.** Gate persists
  model-provided usage when the upstream emits it but enforces nothing.
- **Indirect/tool-output prompt injection is not covered.** Prompt Guard
  scans user-role message text only.
- **The success judge is not validated against hand-labelled ground
  truth.** A hand-labelling effort was scoped and parked — the population
  available was too skewed toward one outcome to be worth the hours, and
  agent-based labelling was rejected as circular (a model grading another
  model's judgement call tends to err the same direction, on the same
  inputs). Figures derived from it carry a caveat; see
  [Results](#results).

None of these are aspirational "coming soon" items being quietly implied
as done — each is a real, currently-true limitation, and each is exactly
why the primary claim of this project is app-level remediation, not a
closed-loop automated firewall.

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
                confirmed bypass ──► bastion report: evidence +
                                      app-level remediation guidance
                                      (docs/design/report-contract.md)
```

Every confirmed bypass also, separately, reaches the Rule Synthesizer
automatically, which mechanically proposes and verifies a Gate-side
detection rule in-memory — a real result, but not the primary output, and
not something that reaches live policy today. Full accounting, including
the family that has no path to a human at all:
[Rule synthesis: a real, dead-ended result](#rule-synthesis-a-real-but-dead-ended-result).

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

**The caveat boundary, stated once, before any figure below**: numbers
that pass through Strike's success judge (`classify_target_response()`) —
campaign outcome tallies, confirmed-bypass counts, anything derived from
`strike.attempts`/`strike.findings` — have not been validated against
hand-labelled ground truth; the judge's false-positive/false-negative
rates, and which direction it errs in if at all, are unmeasured — see
[What this does not do yet](#what-this-does-not-do-yet). Read those
numbers as the judge's classification, not an independently verified
count. This does **not** apply to Gate's own detector figures
(corpus detection rate, corpus false-positive count, both below) or to
the AgentDojo ASR figures immediately below — both are graded
independently of this judge, by direct detector invocation or by
AgentDojo's own harness respectively.

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

**LLM01 direct-injection Gate-path corpus**: on the frozen 48-positive,
41-negative direct user-role corpus, the live Gate path detected **10 of 48**
positive cases at threshold **0.8**. By band: `direct_override` 6/12,
`role_play_framing` 0/12, `encoding_obfuscation` 3/12, and `multi_step_setup`
1/12. 75% of the positive cases were published-derived adaptations; 12 were
authored gap-fillers. Among the negative controls, **2 of 41** were detected;
both were in `adjacent_vocabulary` (17 cases), while `ordinary_text` was 0/12
and `structurally_awkward` was 0/12. 37 of the 41 negative controls were
authored. The complete raw-score table and threshold characterization are in
[`docs/benchmarks/llm01-direct-injection.md`](docs/benchmarks/llm01-direct-injection.md).

The most informative negative-control observation is
`llm01-neg-adjacent-013`: text derived from OWASP's own prompt-injection cheat
sheet scored **0.978705**, higher than most real attacks in this positive set.
This suggests that, in this run, Prompt Guard is responding strongly to the
surface form of injection language even when the user is asking about the
example rather than issuing it. That is an observation about this detector's
behaviour, not a claim about prompt-injection detectors generally.

Gate defaults to `meta-llama/Llama-Prompt-Guard-2-22M`, set by
`MODEL_ID` in [`gate/detectors/prompt_guard.py`](gate/detectors/prompt_guard.py)
and loaded by `PromptGuardDetector.load()`. The 22M choice is explicit in the
implementation and its CPU hot-path comment; no model-comparison or threshold
calibration record was found, so this result makes no claim about the 86M
variant. The live threshold is the `0.8` `gte` matcher in
[`gate/policy/rules.yaml`](gate/policy/rules.yaml). It was chosen in policy,
not calibrated against this corpus.

Run identity: detector config SHA-256
`e5f806fedb5fe931b6568dfc278ce748fb951069494bb323e95ddb87e9aba5a6`, policy
config SHA-256
`3d704dd74a3e10afddd6a86665058d81730f132ad1d96788bf66b38b264c18c4`, model
revision/cache `11614a155199674a0a95e6602d6ab0417b790ed0`.

Every LLM01 figure above is specific to the 22M variant. The 86M variant has
not been compared and no calibration record exists; a same-corpus 86M
comparison is the obvious next measurement and is not blocked by the current
corpus or harness.

The original 48/36 positive-negative split was deliberately balanced for
coverage measurement, not realistic traffic where injections are rare. The
four sourced adjacent-vocabulary additions changed the final inventory to
48/41 before any measurement. Any resulting figure must be described as
detection coverage across this defined positive set and its fixed controls;
it must never be presented as expected production performance or a
population-level rate.

**Live campaign evidence**: 9 campaigns against Gate's hardened default
profile, evidence retained for all of them (`bastion report --campaign
<id>` renders any of them). One ended in an error before any attempt row was
persisted (the NUL-byte persistence bug, since fixed —
`docs/design/nul-byte-persistence-fix.md`). The canonical evidence headline
is **117 target queries across the 8 non-error campaigns**. The errored
campaign's row retains 1 attempted query, making 118 operational calls in
the database, but its target response was not persisted as an attempt and is
excluded from the evidence headline. This includes a campaign against the
NFKC-promoted marker detector specifically. 2 of the 8 non-error campaigns
produced a confirmed bypass — both the same
value-anchored attack class, both correctly declined by the Rule
Synthesizer for a documented structural reason rather than proposed and
lost; see
[`docs/design/rule-vocabulary-and-promotion-gap.md`](docs/design/rule-vocabulary-and-promotion-gap.md).

**LLM02 canary campaign**
([`strike/attempts/pii_leak_canary.yaml`](strike/attempts/pii_leak_canary.yaml)):
5 static hand-written attempts against the new PII-disclosure criterion —
zero findings. The target refused every attempt; four of five replies
named "Social Security number" explicitly while disclosing nothing, and
none were misclassified as a disclosure. A real result about the
technique tried (a hand-written attempt list, the same shape as LLM07's
own early static runs before the adaptive campaigns found a bypass), and
the strongest evidence yet — observed against live model output, not only
synthetic test fixtures — for why this criterion is value-anchored rather
than Presidio-entity-based: none of those four explicit refusals
false-positived. Full account:
[`docs/design/judge-scope-extension.md`](docs/design/judge-scope-extension.md) §8.

**LLM02 benchmark-scale numbers**: *(placeholder — not run yet. The
5-attempt campaign above is a smoke test, not a benchmark. Filling this
in is the next pass; it should follow the same control-fraction rigor as
the AgentDojo numbers above, not be added under pressure to have a number
before the measurement exists.)*

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
- **LLM02's credit-card and partial-value disclosure are out of scope for
  the current criterion.** The target's protective sentence names both
  SSN and credit card, but only the SSN is a registered, judged canary —
  a reply disclosing the canary customer's credit card number in full,
  without ever stating the SSN, violates the stated policy and produces
  no finding. Separately, the "in full" qualifier means a
  last-four-digits-style response, or a value disclosed piecemeal across
  turns, does not value-anchor and is not confirmed. Both deliberate, not
  oversights: see
  [`docs/design/judge-scope-extension.md`](docs/design/judge-scope-extension.md) §7.
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

## Rule synthesis: a real, but dead-ended, result

This is documented in full detail because it's a genuine, execution-proven
engineering result — not because it's the product. It is explicitly not
the primary output; see the top of this document and
[`docs/design/report-contract.md`](docs/design/report-contract.md) for
why.

Every confirmed bypass automatically reaches the Rule Synthesizer, which
proposes a Gate-side detection rule and mechanically verifies it
in-memory, against the originating evidence. This ran for real against
both of this project's live findings and correctly declined both times,
for a documented structural reason
([`docs/design/rule-vocabulary-and-promotion-gap.md`](docs/design/rule-vocabulary-and-promotion-gap.md)) —
not a synthesis bug. Past that point, nothing is automatic:

| Stage | State |
|---|---|
| Proposal + in-memory verification | **Automated** — runs for every confirmed bypass |
| Persistence — `signature`/`detector_config` family | **Not implemented.** No code path writes this anywhere; `review_cli.py`/`apply_approved_rules.py` exist with nothing to read |
| Persistence — normalization family | **Manual.** A human hand-captures the proposal JSON (the campaign log doesn't print it) and runs `normalization_review_cli.py record` |
| Regression / benign-FP / reachability checks | **Manual.** Three standalone test suites; nothing enforces they were run |
| Human sign-off | **Manual CLI** — `normalization_review_cli.py approve` |
| Pattern-version entry | **Manual.** Hand-authored YAML; no script has ever created one |
| Activation → live policy | **Manual CLI**, and Gate has no hot-reload — a restart is required even after activation |

**No proposal of either family has ever been approved or applied to live
policy.** The `signature`/`detector_config` family — the one that
produced both of this project's real findings — has no path to a human at
all. The normalization family has a real path, but every single stage of
it is a person doing it by hand; nothing in the chain enforces the stage
before it.

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
including pruned ones, not just matches), confirmed findings, near-misses
with edit distance and positional overlap, and the known coverage gaps
above — restated so a clean report reads as deliberate evidence, not
silence. Local diagnostics (`error_type`, tracebacks) never appear in its
output, in either format. Findings currently render with the remediation
bucket structure that shipped before the app-level-remediation rescoping
described at the top of this document — deterministic, per-finding
remediation text keyed to the evidence, as designed in
[`docs/design/report-contract.md`](docs/design/report-contract.md), is
designed but not yet implemented; that's the next code pass, not this one.

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
