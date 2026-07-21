# Bastion

> Bastion is a self-hostable AI gateway that inspects and blocks malicious LLM
> traffic (blue team) while an autonomous adversarial engine continuously
> red-teams the protected app and feeds confirmed bypasses back as new
> defensive rules (red team) — attack and defense against the same target, in
> one product.

**Status: early, Phase 0.** This repository currently contains the project
structure, infrastructure stubs, and architectural scope documents. It does
not yet contain a working gateway or red-team worker.

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
                                                            Ollama / OpenAI /
                                                            Azure OpenAI / other

              Bastion.Strike (scheduled red-team worker)
              graphstrike planning · garak / PyRIT adapters
              attacks the protected SampleBank Copilot only
                                      │
                                      ▼
              confirmed bypass → proposed detection rule
                              → human review → live policy
```

## Repository layout

- `gate/` — FastAPI interceptor proxy, planned for Phase 1.
- `control/` — .NET control plane, planned for a later phase.
- `strike/` — red-team worker, planned for a later phase.
- `sample-target/` — deliberately vulnerable SampleBank Copilot, planned for
  a later phase.
- `dashboard/` — React/Vite dashboard, planned for a later phase.
- `docs/` — threat model, architectural decisions, and future finding
  writeups.
