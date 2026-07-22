# ADR-007: Adaptive planner and attempt-source abstraction

- Status: Accepted
- Date: 2026-07-22

## Context

Static attempt lists are reproducible but cannot adapt to the target's actual
responses or defensive outcomes during a campaign. A genuine red-team
capability needs to generate a new probe informed by what has already failed,
without duplicating the campaign lifecycle, target allowlist, or safety limits
between static and adaptive execution paths.

## Decision

Introduce an `AttemptSource` abstraction behind one shared campaign loop.
`StaticAttemptSource` replays the current YAML attempts list unchanged, while
`PlannerAttemptSource` asks an `AttackerPlanner` for one new single-turn user
message at each iteration.

The planner calls Ollama directly rather than through Bastion.Gate. The
planner is the attacker's own reasoning tool, not the protected system under
test; SampleBank Copilot remains the only target and still routes its model
traffic through Gate. The planner receives the campaign objective and a
truncated history of prior outcomes, but never the literal success-pattern
regex, preserving Bastion's black-box discipline.

Planner output is schema-constrained by Ollama's native JSON-schema `format`
parameter and validated as a Pydantic `PlannerAttempt`. A bounded retry budget
handles malformed or unavailable planner output and does not consume the
campaign query budget, which counts only real target requests. This step is
single-turn only; it does not create conversations, branches, pruning, or
cross-campaign memory.

## Consequences

A planner-sourced campaign cannot finish as `completed_no_bypass`, because it
has no finite list to exhaust. It can end only with `bypass_found`,
`query_limit_reached`, `timed_out`, or `error`; this is intentional behavior.

Prompt size grows with campaign length despite fixed reply excerpts. Very large
query budgets may eventually require history windowing, which is deferred until
it is an observed operational problem.
