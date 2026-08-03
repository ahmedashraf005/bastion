# Bastion threat model and MVP scope

Bastion is an LLM security gateway with a separate, scheduled red-team worker.
The product is designed around a reviewed feedback loop: confirmed bypasses
may become proposed defensive rules, but they do not become production policy
without human approval.

Bastion.Control v1 is an internal, read-only observability API with no
authentication or RBAC. It is not a security boundary and must not be exposed
as a production management interface at this stage.

## OWASP scope

Every future detection rule and red-team probe must carry an OWASP Top 10 for
LLM Applications (2025) identifier. The MVP deliberately addresses only the
four risks marked in scope below. The remaining rows are deferred rather than
implicitly covered; Bastion must not claim protection for them until that work
is intentionally designed, implemented, and tested.

| ID | Risk | In MVP scope? |
| --- | --- | --- |
| LLM01 | Prompt Injection (direct and indirect) | Yes — core |
| LLM02 | Sensitive Information Disclosure | Yes |
| LLM05 | Improper Output Handling | No (later) |
| LLM06 | Excessive Agency | No (later) |
| LLM07 | System Prompt Leakage | Yes |
| LLM08 | Vector & Embedding Weaknesses | No (later) |
| LLM10 | Unbounded Consumption | No — planned; token/cost accounting and consumption limits are not implemented |

LLM10 is planned, not implemented. Gate persists model-provided usage when
the upstream emits it, but does not use that usage to account for, limit, or
block consumption. Bastion must not claim LLM10 protection until a measurable
cap and deterministic verification exist.

LLM02 input PII is detected and redacted before it reaches the upstream model.
When redaction occurs, the original unredacted text is intentionally not
persisted in Gate's request audit record.

LLM07 detection currently redacts configured leak patterns from completed
non-streaming responses before they are returned. Patterns configured for
separator normalization also catch secrets reformatted with the original
curated separators and Unicode whitespace generally. Invisible zero-width
characters and homoglyphs remain known, distinct gaps outside this change.
Streaming responses are audited for those leaks only after the stream
finishes; tokens already sent to the client cannot be retracted, so streaming
is not yet protected from a leak.

### Indirect prompt-injection boundary

Gate's input-stage Prompt Guard detector inspects user-role message text
only; it is never run over tool-role content, and assistant-role content is
not input-scanned by any detector. Consequently, indirect prompt injection
delivered through tool output or retrieved context is outside current Gate
coverage, regardless of the tool-output PII scanning described below.
AgentDojo's `important_instructions` attack is the concrete known example:
its payload is inserted into tool output, where Gate's input-stage injection
detection cannot observe it. This is a known gap, not a claim that the
existing LLM01 policy protects indirect injection, and it is why the
AgentDojo defense cells for `important_instructions` remain cancelled.

#### Tool-output PII scanning (GATE_SCAN_TOOL_OUTPUT, opt-in, default off)

Presidio (LLM02) can optionally scan the latest tool-role message for PII and
secret egress. This closes part of the input-stage gap above for LLM02
egress only — it provides no LLM01/injection coverage, redacts rather than
blocks (a tool-role message a client receives as malformed or as a 400 is
indistinguishable from a transport failure to a standard agent loop), and is
opt-in because Presidio's false-positive behavior on structured tool content
was unmeasured before it was. Measured against a 36-case, four-band benign
tool-output corpus (`tests/corpus/benign_tool_output.yaml`: 12 ordinary, 8
adjacent-vocabulary, 8 structurally-awkward, 8 redaction-span cases) with the
real Presidio detector, one case in the redaction-span band mismatched.

Two coverage gaps this measurement surfaced, both structural to Presidio's
configured recognizer set (`gate/detectors/pii_entities.yaml`: EMAIL_ADDRESS,
PHONE_NUMBER, CREDIT_CARD, US_SSN only — no financial-identifier recognizer):

- No financial-identifier coverage. A bank routing number is misclassified
  as PHONE_NUMBER via digit-pattern overlap and gets redacted even though it
  is not PII (measured: `span-account-routing-001`). IBANs and plain account
  numbers were not misclassified in this corpus, but that is an absence of a
  recognizer, not a verified absence of risk.
- SSNs in the JSON field shape that dominates real tool output
  (`{"ssn": "078-05-1120"}`) are not detected at all — the US_SSN recognizer
  as configured requires prose context. This is a false negative in the
  feature's primary use case, not just an edge case. Even when an SSN is
  detected via spelled-out prose context, it is labelled PHONE_NUMBER rather
  than US_SSN, so `entities` in `detector_signals` cannot be relied on for
  grouping or reporting by entity type.

Redaction is a literal string splice: Presidio's matched span excludes the
surrounding quote characters and the replacement text `[REDACTED]` contains
no JSON-special characters, so every redacted case observed during
measurement — including the routing-number false positive — remained valid
JSON after redaction. This was checked empirically against the cases in the
corpus above; it is not a structural guarantee for arbitrary payloads.

Tool-output PII scanning therefore provides **partial** PII egress coverage,
not comprehensive coverage, and provides no protection against tool-output
prompt injection.

Tool-call arguments are also not scanned by the output-stage leak detector.
Restoring faithful tool-call SSE passthrough therefore restores an unmonitored
egress path for canary or PII values carried in tool arguments. The earlier
lossy stream reconstruction only closed that path by breaking protocol
conformance; it was not a security control. Tool-argument inspection is a
separate detection decision and is not implemented here.

For responses with multiple choices, the output-stage leak detector scans only
the first choice. Content in additional choices is unscanned. Multi-choice
output inspection is a separate detection decision and is not implemented
here.

## Red-team operating boundary

Any future Bastion.Strike component may attack only SampleBank Copilot, the
small deliberately vulnerable sample application shipped in this repository.
It must never probe third-party infrastructure, customer systems, or services
outside this repository.
The strategy library can influence only Strike's own candidate generation
against that bundled target; it never reads, writes, or changes Gate policy,
which remains the future Rule Synthesizer's human-reviewed responsibility.
The Rule Synthesizer proposes narrow signatures mechanically verified against
confirmed bypass evidence. A human must approve a proposal before it is applied
to Gate's live configuration; it does not attempt general root-cause fixes.
Branching campaigns preserve this same boundary: the reviewed allowlist is
checked before any generation, pruning, database write, or target request,
regardless of attempt source.

SampleBank Copilot routes all model traffic exclusively through Bastion.Gate.
It currently has no tool-calling surface because LLM06 (Excessive Agency) is
deferred past MVP scope; tools may be added only alongside the future phase
that implements LLM06 defenses.

Red-team operation is black-box only. The worker may use the sample target's
documented public API surface, as an external attacker would, but it must not
read the target's source code, model weights, hidden prompts, or other internal
implementation details to construct an attack. Gradient- and logit-based
white-box attacks are permanently out of scope because they violate this
boundary.

This discipline applies both to automated campaigns and to adapters added in
future phases. New probes outside the MVP risks require an explicit scope
decision before implementation.

Adaptive campaigns use the same hardcoded SampleBank-only target allowlist as
static campaigns. Attempt generation never expands the target boundary: the
allowlist check still runs first, before any campaign database write or target
request, regardless of attempt source.
