# ADR-006: Strike campaign contract

- Status: Accepted
- Date: 2026-07-21

## Context

Bastion.Strike needs a first campaign mechanism that can safely exercise the
bundled SampleBank Copilot target and preserve useful evidence. ADR-001 assigns
findings and campaign management to Bastion.Control, but Control does not yet
exist. Strike and Gate are Python services with independent Alembic migration
histories, while Control will later use different tooling.

The red-team operating boundary is a safety-critical product invariant: Strike
may attack only the deliberately vulnerable, synthetic sample target in this
repository. The first objective is also narrow and deterministic: determine
whether a raw internal configuration marker can pass Gate's LLM07 output
redaction. Building a scheduler, adaptive planner, or LLM-based judge before
this bounded execution path works would add unproven complexity.

## Decision

Strike owns and exclusively migrates a `strike` Postgres schema using its own
Alembic history. This extends ADR-002's schema-per-service model. Campaigns
and findings remain architecturally Control concerns when that service exists,
but the interim ownership makes the first campaign independently operable.
Strike's uniquely named Alembic version ledger is migration metadata in
`public`, because Alembic must consult it before the initial migration can
create `strike`; all Strike domain objects remain exclusively in `strike`.
Cross-schema references, including a finding's optional `gate_request_id`, are
plain UUID values with no database-enforced foreign keys. Foreign keys inside
the `strike` schema remain valid, so a finding references its campaign there.

Strike's target allowlist is a hardcoded Python mapping from reviewed target
keys to URLs. It is intentionally not an environment value or configuration
file: changing a target requires a code change, commit, and review rather than
being possible through a typo or careless deployment override. The runner
refuses an unknown key before loading attempts, opening a database connection,
writing a row, or making a network request.

Campaigns run through direct script invocation with explicit query and
wall-clock limits, not through a Redis-backed job queue. Queueing is deferred
until the campaign mechanism itself is proven, and direct invocation preserves
an operator decision point before each red-team run.

The first campaign uses a static YAML list of hand-written attempts and a
regex success criterion. Extracting a known marker is objectively
string-matchable, so an LLM-as-judge would add complexity without improving
this first contract. Adaptive planning, probe adapters, and LLM-judged
objectives are future work.

Unlike Gate's discrete request audit records, Strike creates a campaign row at
start and updates it while execution progresses and when it terminates. A
campaign is multi-step and potentially long-running; its in-progress state and
current query count are meaningful operational facts, so the single-insert
after-completion convention used by `gate.requests` is not appropriate here.

Strike findings retain the full raw attack turns and raw target reply
verbatim. This is a deliberately narrow exception to Gate's audit-log
redaction discipline: Strike is constrained to the bundled synthetic target,
so any secret or PII in a finding is repository-invented test data, and raw
evidence is necessary to demonstrate a bypass. It does not change
`gate.requests` semantics: Gate can proxy real production traffic and its
audit retention and redaction requirements remain strict.

## Consequences

Strike's Alembic history owns only Strike domain objects in `strike`, with a
uniquely named migration ledger to prevent collisions with Gate's history and
Control's future migration tooling. Cross-service consistency is
application-level because cross-schema database foreign keys remain prohibited.

Because Alembic must consult its version-tracking table before the initial migration can create a service schema, Strike's `public.strike_alembic_version` ledger is deliberately distinct from Gate's existing `public.alembic_version`; every future service must use its own service-prefixed public ledger rather than another plain `alembic_version`, while domain tables remain exclusively in their owning schema.

Only an explicitly reviewed code change can expand the attack surface. The
runner is not a general-purpose scanner or scheduler, and it intentionally
does not attack arbitrary URLs. Its static attempts demonstrate the campaign
contract but do not claim adaptive red-team capability.

Campaign operators can observe a running campaign and its query consumption
in Postgres. Findings are useful raw evidence only under the synthetic-target
boundary; this exception must never be copied into Gate's general-purpose
audit logging or a future Strike target outside that boundary.
