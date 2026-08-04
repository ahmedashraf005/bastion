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
was unmeasured before it was. Measured against a 46-case, five-band benign
tool-output corpus (`tests/corpus/benign_tool_output.yaml`: 12 ordinary, 8
adjacent-vocabulary, 8 structurally-awkward, 9 redaction-span, 9
mixed-script cases) with the real Presidio detector: zero mismatches. The
mixed-script band is also checked against real LLM07 marker detection with
confusables normalization active (see
[`docs/design/confusables-marker-normalization.md`](design/confusables-marker-normalization.md)) —
zero mismatches there too.

A bank routing number was initially misclassified as PHONE_NUMBER and
redacted despite not being PII (measured: `span-account-routing-001`). Root
cause: `PhoneRecognizer`'s context word list
(`gate/detectors/presidio_pii.py`, via `presidio-analyzer`) includes the
generic word "number" — `PhoneRecognizer.CONTEXT = ["phone", "number",
"telephone", "cell", "cellphone", "mobile", "call"]` — so any JSON key
containing "number" (`routing_number`, `account_number`, and by extension
any future financial-identifier field named similarly) boosts a
phone-shaped digit run's score identically to a genuine phone number in the
same shape of context (measured: both 0.750). No confidence threshold
separates them, because the scores are identical; anyone extending this
detector to other financial identifiers will hit the same collision if the
field name contains "number". Fixed by registering
`presidio_analyzer.predefined_recognizers.AbaRoutingRecognizer` (ships with
`presidio-analyzer`, checksum-validates ABA routing numbers) and, in
`PresidioPiiDetector._scan_blocking`, suppressing any configured-entity
candidate whose span is fully contained in a checksum-validated ABA match
before thresholding. `ABA_ROUTING_NUMBER` itself is never added to a
`DetectorSignal`'s `entities` or redacted — it exists purely as an internal
disambiguation signal. Verified co-located in the same document
(`span-phone-and-routing-colocated-001`): a genuine phone number and a
routing number in one payload redact and pass through correctly,
independently of each other.

Known residual tradeoff of the checksum-based fix, not eliminated: the ABA
check digit is a single mod-10 digit over 9 digits, so roughly 1 in 10
arbitrary 9-digit strings pass it by chance. A genuine phone number that
happened to be a bare contiguous 9-digit run *and* coincidentally pass the
checksum would be wrongly suppressed. This does not bite today because US
phone numbers are 10 or 11 digits (with a country code) and never form a
bare contiguous 9-digit run, so they never enter the suppression path in the
first place — re-verify if `PhoneRecognizer`'s supported regions or patterns
ever change.

Presidio's configured recognizer set otherwise remains
`gate/detectors/pii_entities.yaml`: EMAIL_ADDRESS, PHONE_NUMBER,
CREDIT_CARD, US_SSN, plus the suppression-only ABA_ROUTING_NUMBER above — no
general financial-identifier (IBAN, generic account number) recognizer.
IBANs and plain account numbers were not misclassified in this corpus, but
that is an absence of a recognizer, not a verified absence of risk.

- **Corrected 2026-08-04 — the claim below was false as written and shipped
  in this document.** It previously said SSNs in JSON field form
  (`{"ssn": "078-05-1120"}`) are not detected and that US_SSN requires prose
  context. Both are wrong. The value `078-05-1120` is one of three canonical
  placeholder SSNs (`123456789`, `987654320`, `078051120`) that
  presidio-analyzer's `UsSsnRecognizer.invalidate_result()` deliberately
  blacklists, since they are widely-reused textbook/example values rather
  than real SSNs — the corpus case happened to use exactly one of them.
  With a non-blacklisted value (`234-56-7890`), US_SSN is correctly detected
  in bare (score 0.500), prose (0.850), and JSON field (0.850) form alike:
  the surrounding JSON key text is read as recognizer context the same way
  prose is, so there is no JSON-specific gap. Anyone authoring PII test data
  against Presidio should know about this blacklist — an example/placeholder
  SSN used as "real" test PII will silently and by design not fire.
- A narrower entity-type finding survives, and is unrelated to the blacklist
  above: a digit sequence shaped like `078-05-11xx` (the same family as the
  blacklisted value) independently registers as PHONE_NUMBER-plausible to
  Presidio's phone recognizer, and can surface as PHONE_NUMBER instead of or
  alongside US_SSN when the generic context word "number" appears nearby
  (see the routing-number entry below for the shared root cause). This is a
  coincidence of specific digit shapes, not a general property of SSN
  detection — the corrected corpus case (`234-56-7890`) does not reproduce
  it, and `entities` correctly reports only `US_SSN` for it. Entity types in
  `detector_signals` are reliable for grouping in the general case measured
  here; they are not guaranteed reliable for every possible digit sequence.

Redaction is a literal string splice: Presidio's matched span excludes the
surrounding quote characters and the replacement text `[REDACTED]` contains
no JSON-special characters, so every redacted case observed during
measurement — including the routing-number false positive before it was
fixed — remained valid JSON after redaction. This was checked empirically
against the cases in the corpus above; it is not a structural guarantee for
arbitrary payloads.

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

Prompt Guard's own user-message selection (`gate/app/main.py:759-765`)
filters on `isinstance(message.get("content"), str)` (line 764), silently
excluding any user-role message that uses the standard OpenAI multi-part
content-block shape instead of a plain string — no error, no log. If every
user turn in a request uses that shape, the filtered join produces `""` and
Prompt Guard scores an empty string against a real request. This is a
silent LLM01 coverage hole in shipped behavior, not a hypothetical. The
Presidio paths do not have this gap: `most_recent_user_message`
(`gate/app/main.py:205-222`) selects the latest user message by role alone,
with no content-type check, and `extract_text_content`
(`gate/app/main.py:243-271`) handles both the plain-string and
content-block-array shapes once a message is selected. `main.py:208-212`'s
own docstring records that the string-only restriction was deliberately
removed from that exact path for this exact reason — so this is a
known-pattern regression surviving in the one place it wasn't yet fixed,
not an unknown failure mode.

### Input-stage block response shape

Gate's input-stage block (`block-high-confidence-injection`, LLM01) returns
HTTP 400 with a non-OpenAI body: `{"error": "...", "rule_id": "..."}`.
Standard OpenAI SDK clients map this to `BadRequestError` by status code
alone, but because the body's `"error"` value is a string rather than a
mapping, the SDK leaves `e.code` and `e.param` unset. A client that inspects
those fields to distinguish recoverable errors from genuine failures cannot
identify a policy block that way — a block is indistinguishable from a
malformed request. Traced concretely, not assumed: AgentDojo's benchmark
harness (`agentdojo/benchmark.py`) excludes `BadRequestError` from retry, and
its one recovery path checks `e.code`/`e.param` against known values (e.g.
`context_length_exceeded`); neither is set, so it re-raises and the benchmark
crashes rather than degrading gracefully. This affects the existing LLM01
block path in shipped behavior today — it is not a hypothetical
future-blocking concern.

### Tool-output injection: resolved design note (detection not yet built)

Rejecting tool content does not require a rejection response. A tool-role
message is part of the request Gate forwards upstream, not the model's
response, so Gate can substitute placeholder content for a detected
injection and return an ordinary HTTP 200 — the agent client sees nothing
unusual at the protocol level, unlike the block path above. This is the same
mechanism already used for tool-output PII redaction (`GATE_SCAN_TOOL_OUTPUT`).
`finish_reason: content_filter` and `message.refusal` are output-shape
concepts (they describe the assistant's own response) and do not apply here.

What remains open is the detector, not the response mechanism: Prompt Guard
2's model card scopes it to prompts attempting to override instructions, with
no guidance on tool output, so running it over tool content is off-label with
unmeasured behavior. A labelled tool-output injection corpus is required
before any detector is wired to that path — this has not been built.

### Evidence persistence integrity

Postgres cannot store an embedded NUL byte (U+0000) in any text or JSONB
column at all. Planner- or target-generated content containing one used to
crash the write outright — in Strike this terminated the whole campaign
(`UntranslatableCharacterError`); in Gate it was caught and logged, silently
dropping that request's audit row instead. Fixed: both now sanitize
immediately before each write and record a `sanitized` flag on the row
rather than altering evidence silently. See
[`docs/design/nul-byte-persistence-fix.md`](design/nul-byte-persistence-fix.md).

**Lone UTF-16 surrogates (U+D800–U+DFFF) hit the identical crash-and-terminate
failure mode, via a sibling exception — reproduced, not fixed.** Same
persistence boundary, same unresolved exposure until it is.

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
