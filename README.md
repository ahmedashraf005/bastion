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
