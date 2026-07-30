# ADR-013: Wider Rule Synthesizer vocabulary

- Status: Accepted
- Date: 2026-07-30

## Context

ADR-010's original synthesizer could propose only literal or regex signatures.
That was inadequate for a confirmed evasion caused by Unicode format
characters: the remediation was a constrained normalization change, not a
new string to match.

The first synthesis attempts did not fail because the local `llama3.1:8b`
model was intrinsically unable to reason about the evidence. The evidence was
presented badly in three material ways: invisible characters were rendered
invisibly, the system prompt forbade generalization, and the model was not
told the detector's current normalizer state. Once the response had a
codepoint table and category summary, normalization evidence, and explicit
already-stripped/not-stripped state, the same 8B model selected the evidence-
supported category-level remediation. Making evidence legible is therefore a
primary design requirement, not prompt polish.

## Decision

The Rule Synthesizer accepts and emits a schema-constrained discriminated
union with three proposal types: `signature`, `normalization`, and
`detector_config`. Normalization proposals are closed vocabulary: named
Unicode categories, named character classes, and bounded codepoint lists. The
model never supplies executable logic.

All proposals are additive-only and must include a mandatory blast-radius
report. Structural validation rejects invalid pattern-type combinations,
secret-bearing rules, and normalization proposals that are entirely redundant
with the detector's current normalizer. Partial overlap is reported rather
than silently accepted.

Promotion is tiered. Tier-3 normalization changes are blocked in code unless
a benign corpus is available, because mechanically closing the originating
evidence does not establish that legitimate traffic remains usable.

## Rejected alternatives

Keeping a signature-only vocabulary was rejected because it can only overfit
the observed bytes and cannot represent an evidenced normalization mechanism.
Allowing free-form model-authored detector code was rejected because it makes
the review surface unbounded and breaks reproducible mechanical verification.
Delegating this class of proposal to a stronger model by default was rejected:
the evidence-framing repair demonstrated that the existing 8B model succeeds
when given perceivable, non-contradictory evidence.

## Consequences

The synthesizer has more schema, validation, verification, and evidence-
rendering code than a free-text prompt. Closed vocabulary also deliberately
limits expressiveness; a genuinely new detector behavior may require an
engineering change rather than a synthesized proposal.

The blast-radius report and corpus prerequisite add time and operational
friction to remediation. They make the proposed change auditable, constrain
the model's authority, and ensure a proposal cannot be mistaken for a safe
live-policy change.

## Revisit trigger

Revisit this decision when a verified finding cannot be faithfully represented
by the three proposal types or the closed normalization vocabulary, or when
the review data shows that an additive-only remediation is insufficient for a
well-evidenced mechanism.
