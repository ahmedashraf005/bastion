# ADR-009: Cross-campaign strategy library

- Status: Accepted
- Date: 2026-07-22

## Context

Strike has now demonstrated static, linear adaptive, and branching adaptive
campaigns, but each campaign begins without access to techniques previously
shown to matter. The project has two genuine historical LLM07 findings—ASCII
separator formatting and Unicode-whitespace formatting—both from the broader
family of reformatting output to evade a literal-style detector. Reusing that
knowledge must not expand Strike's target boundary or prematurely require a
production-scale vector system.

## Decision

Strike stores flat JSON strategy blobs in Valkey and keeps their IDs in a
`strategy_index` set. Retrieval embeds the fixed campaign objective once and
performs brute-force cosine similarity in Python over the low-tens-scale
library. A native Valkey vector index is deliberately not introduced until the
library has a demonstrated scale problem.

Embeddings use `nomic-embed-text` through Ollama directly, like the planner's
own reasoning calls in ADR-007: this is attacker tooling, not the protected
system under test. Retrieval is available only to the branching source and is
performed once per campaign because its objective is invariant across rounds.
The resulting descriptions guide batch generation but never expose library
metadata or a success regex.

The genesis script manually seeds exactly two abstract LLM07 techniques from
this repository's historical separator findings, marked `manual_seed`. A real
planner/branching finding is automatically abstracted and written as
`campaign_promoted`; static findings are never promoted because treating a
human-authored attempt as a discovery would be circular. The historical
underlying bypasses are already patched in Gate, so seeding cannot honestly
claim to create a fresh live bypass. It can demonstrate whether retrieval
biases candidate generation toward the known technique family.

Promotion is intentionally automatic, unlike the future Rule Synthesizer's
human review. A synthesized Gate rule changes blocking/redaction for
potentially real production traffic; a strategy only influences Strike's own
planner inside the existing allowlisted, bundled-sample-target, black-box
boundary. The latter has categorically smaller blast radius.

Retrieval and embedding assistance failures log and return no strategy context
without stopping the campaign. This is intentionally different from
generation/pruning failures: losing memory does not change allowlisting or
query limits, while silently losing pruning could multiply unvetted target
queries. Promotion failure similarly never affects an already persisted
finding or terminal campaign state; its optional finding reference remains
NULL.

## Consequences

Brute-force retrieval must be revisited if the library grows beyond a scale
where fetching and comparing every JSON blob is cheap. `retrieved_strategy_ids`
records what was presented to a campaign's planner, not proof that a candidate
used it.

The strategy library cannot read, write, or affect Gate policy. It influences
only Strike candidate generation; translating a confirmed finding into a Gate
rule remains the future, human-reviewed Rule Synthesizer responsibility.
