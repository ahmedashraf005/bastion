# ADR-010: Rule Synthesizer v1

- Status: Accepted
- Date: 2026-07-22

## Context

Bastion's historical LLM07 bypasses were fixed through human judgment about
why a detector failed. The ASCII separator finding led to a normalization
concept; the Unicode-whitespace finding broadened that concept through
`isspace()`. Neither fix was merely an independent signature for the exact
observed output.

Strike now records confirmed bypass evidence, but the project needs a narrow,
auditable path from such evidence to a human-reviewable Gate configuration
proposal. That handoff must not overclaim that an LLM can infer root causes or
make autonomous production policy changes.

## Decision

Rule Synthesizer v1 proposes a narrow literal or regex leak-pattern signature
from a finding's own attack turns and target reply. It mechanically verifies
the candidate through Gate's existing leak-detector normalization and matching
implementation before it can enter `strike.proposed_rules`; failed candidates
are discarded. This is attack memory, not insight, in the spirit of Rebuff's
original attack-memory concept. It catches the exact evidence if repeated; it
does not attempt root-cause generalization, and genuine generalization is
explicitly out of scope for this component rather than a promised later v1
extension.

Only planner- and branching-sourced findings trigger synthesis. Static attempts
are human-authored, so treating their expected output as an independently
discovered candidate would be circular, consistent with ADR-009's strategy
promotion boundary.

Every verified proposal starts as `pending_review`. A human must approve it
before Gate's apply script appends it to `leak_patterns.yaml`. This deliberately
differs from ADR-009's automatic strategy promotion: a strategy changes only
Strike's future candidate generation against the allowlisted synthetic sample
target, while a Gate rule can alter blocking or redaction for potentially real
traffic.

For this repository's local setup, Gate's apply script reads Strike's proposal
table directly from the shared Postgres instance and appends to a shared local
filesystem. This is an interim shortcut, not a production handoff protocol.
A real deployment needs Bastion.Control to broker the transition rather than
having Gate reach directly into Strike's schema.

The synthesizer also imports Gate's actual `SystemPromptLeakDetector` module
from the shared repository so mechanical verification uses the exact live
normalization and matching behavior rather than a copied implementation. This
cross-package import is another local-development shortcut; a production
architecture needs a versioned shared detector contract or a Control-brokered
verification boundary instead of assuming one shared source tree.

## Consequences

`strike.proposed_rules` is a durable review queue, not an automatically live
policy store. A reviewer rejecting a narrow proposal because an existing,
more-general fix already covers it is a valuable result: it preserves evidence
and avoids redundant production configuration rather than marking the
mechanism as failed.

The synthesizer is best-effort after a finding has already been persisted. A
model, parser, or verification failure leaves the real finding and campaign
outcome unchanged, just as a failed strategy promotion does in ADR-009.

The local shared-database/shared-filesystem bridge must not be copied into a
distributed or production deployment. It would create cross-plane operational
coupling that ADR-001 and ADR-002 deliberately avoid; Control is the future
reviewed handoff owner.
