# ADR-004: Output-stage detection and streaming limitation

- Status: Accepted
- Date: 2026-07-21

## Context

LLM07 system-prompt leakage requires inspection of model output, while the
existing Prompt Guard 2 detector only evaluates input before Bastion.Gate
contacts the upstream model. Rules therefore need to identify the pipeline
stage to which they apply. Streaming creates a separate constraint: tokens
are delivered to the client as they arrive, so a token cannot be withdrawn
after it has been sent.

## Decision

Policy rules carry a required `stage` value of `input` or `output`.
Non-streaming output-stage rules may mutate a fully received response before
it is delivered to the client. Streaming responses receive output detection
only after a normally completed stream has been reconstructed for the audit
record.

When a streamed response matches an output rule, Gate records the distinct
`policy_action` value `detected_after_stream`, rather than `redact`. This
ensures the audit log cannot be misread as claiming that a response was
prevented or cleaned before the client saw it.

## Consequences

Bastion currently cannot prevent a system-prompt leak in a streamed response;
it can only detect and audit the completed leak after delivery. Closing this
gap requires real-time windowed or incremental output inspection before each
chunk is released. That is a substantially larger streaming design and is
explicitly deferred rather than solved by this detector.

Because `response_body` always reflects what the client actually received, a
streamed leak is persisted verbatim in `gate.requests`; operators must
therefore treat the audit table as potentially containing leaked material and
apply appropriate retention and access controls in real deployments.

The leak detector can optionally normalize spaces, tabs, newlines, carriage returns, hyphens, underscores, and periods before matching, closing the separator-reformatting evasion found by Bastion.Strike's campaign against this detector using the same normalization technique Strike used to identify it.

Unicode non-breaking spaces (U+00A0), and likely other Unicode whitespace or separator variants, remain outside the current `strip_separators` character set and were observed to evade redaction during testing; expanding that set is a known follow-up requiring a separate scoped decision about boundaries such as Unicode whitespace, punctuation, and homoglyphs rather than silent scope creep here.
