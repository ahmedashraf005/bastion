# ADR-005: Input-side PII redaction and request-body semantics

- Status: Accepted
- Date: 2026-07-21

## Context

LLM02 requires detecting and redacting personally identifiable information in
user input before it reaches an upstream LLM. The initial Gate persistence
design specified `request_body` as the raw, unmodified incoming payload. That
semantics conflicts with real input redaction: forwarding the original PII to
the upstream model would defeat the feature.

## Decision

Gate uses Presidio to scan only the most recent user-role message for
`EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, and `US_SSN`. Matched spans
are replaced with `[REDACTED]`, and that redacted message is forwarded to the
upstream model.

## Consequences

`request_body` no longer always means the raw original request. It now records
whatever Gate actually forwarded upstream. For a redacted request, it therefore
does not contain the original PII-bearing text, by design. This follows the
same persist-what-actually-happened principle already used for `response_body`.

Anyone querying `gate.requests` for the original raw input of a redacted
request will not find it there. That data is intentionally not retained: keeping
it would defeat a PII-redaction feature, though it is a real query-capability
trade-off that operators and future control-plane features must account for.
