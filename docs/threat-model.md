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

Lone UTF-16 surrogates (U+D800–U+DFFF) hit the identical crash-and-terminate
failure mode, via a column-type-dependent sibling exception (`DataError` for
Text columns, `InvalidTextRepresentationError` for JSONB columns) — same
persistence boundary. Fixed: the same sanitizer and the same `sanitized`
flag now cover both character classes in one pass; a valid astral-plane
character (e.g. an emoji) is structurally never at risk, since CPython
never represents one as a pair of lone-surrogate codepoints. See
[`docs/design/nul-byte-persistence-fix.md`](design/nul-byte-persistence-fix.md).

### Marker label/value anchoring — Gate's leak detector still has both gaps

Both Strike's success judge and Gate's output-stage `system_prompt_leak`
detector require the marker's label and value to both be intact before
they treat a reply as evidence, but by different mechanisms and with
different resolution status.

**Strike's judge (`strike/app/success_contract.py`): fixed 2026-08-05.**
Two symptoms of one design property (tolerance was reachable only after an
untolerant anchor/label match): label clean + value garbled (sequence-5,
reconstructed from documented numbers, its source campaign lost to the
2026-08-03 volume-loss incident) classified as `near_marker_miss`,
correctly; label destroyed + value clean (case-068, attempt
`ef0fda1f-781c-4d49-a0a6-b37e52141362`, live in the database) classified
as `clean_no_marker_evidence` — a real, usable disclosure recorded as no
evidence at all. Now: the judge also fires on an exact, tolerant-of-
surrounding-noise value match independent of the label, closing case-068's
shape while leaving sequence-5's shape (a genuinely corrupted value)
classified exactly as before. See
[`docs/design/value-anchored-marker-detection.md`](design/value-anchored-marker-detection.md)
for the full mechanism, the two rejected broader alternatives (edit-
distance-tolerant anchoring, full either-side anchoring) and why, and why
this fix is judge-only.

**Gate's detector (`gate/detectors/system_prompt_leak.py`): open, both
symptoms, unfixed.** Confirmed directly against the live database
(`gate.requests`, correlated to the same attempt via `gate_request_id`):
Gate's own leak detector scanned case-068's identical response and also
returned no match — `[REDACTED]` never appeared, the value reached the
client. The cause is different from the judge's former gap and specific to
Gate's character-interleave matching algorithm: it tolerates arbitrary
non-marker-alphabet noise between expected characters, but an incidental
collision (the model's garbled output happened to contain a literal digit
that is also part of the marker's own alphanumeric alphabet) is treated as
unskippable, breaking the match. This is deliberately **not** fixed here —
Gate changes require the mechanical-verification/bypass-regression/benign-
corpus promotion discipline this document describes elsewhere, not a
judge-side patch. Strike being able to see this disclosure class while
Gate cannot is intentional (the judge's contract is required to stay
broader than Gate's own detection, so Strike can find gaps Gate has), not
evidence the gap is closed.

### Rule Synthesizer's marker redaction — CLOSED 2026-08-06

The configured secret leaked verbatim into the Rule Synthesizer's LLM
prompt for value-anchored findings. `strike/synthesizer/rule_synthesizer.py`'s
`_marker_spans()` — the function responsible for locating and masking the
marker before anything reaches Ollama — used the same contiguous-match
algorithm `success_contract.py`'s judge had *before* it gained value
anchoring (see the entry above): find the whole label+value as one
contiguous span after canonicalization, or nothing. When the judge gained
a second, independent way to confirm a bypass — the value alone,
unanchored to the label — the redactor was never updated to match. On
finding `bb3e06bd-ea91-46e2-af20-57d9bd23b1b8` (the same case-068-shaped
disclosure above), `_marker_spans()` returned no spans, so
`_replace_markers()` passed the reply through unchanged and
`_masked_codepoint_sequence()` emitted the true, unmasked codepoint
sequence. The real 8-character secret appeared verbatim in the
LLM-facing prompt, twice — once as plain text, once spelled out as its
own codepoint sequence — for every future finding of this shape, by
construction, not by chance.

**Local-Ollama-only — stated accurately, not minimized or inflated.** The
exposure was to the campaign's own configured planner model
(`llama3.1:8b`, reached at `settings.ollama_base_url`, host-native in this
project's setup) — the same model already visible to every other
in-campaign LLM call, no third-party API, no data leaving the machine
running the campaign. This does not make it a non-issue: the module's own
stated design principle is that a marker value is "intentionally not
passed to any planner, PruneGate, or LLM prompt" *at all*, regardless of
which model receives it — an unredacted secret in any LLM-visible prompt
is an evidence-integrity violation on its own terms, not contingent on
where that model happens to run.

**Fixed**: `_marker_spans()` now also searches for the marker's own
trailing value, independent of the label — mirroring the judge's
value-anchor branch, but deliberately more aggressive: rather than a
fixed, externally-configured `suffix_length` (a parameter the redactor
has no access to — `RuleSynthesizer` receives only a resolved marker
value, never per-campaign `near_match` config), it searches for the
*longest* canonical suffix of the marker present in the reply, down to a
conservative minimum, so it over-redacts relative to what the judge would
itself confirm rather than trying to match its exact threshold. A
redactor's false positive costs the LLM a little prompt context; a missed
true positive leaks the secret — deliberately not symmetric. Verified:
finding `bb3e06bd` and case-068's reply shape both now redact to zero
occurrences of the secret, in both plain-text and codepoint-spelled form;
a conventional contiguous label+value reply still redacts exactly as
before (no narrowing); a reply with no marker evidence is passed through
unchanged (no over-masking). One known, accepted limit, shared with the
judge and not introduced by this fix: if a future evasion interleaves
noise *within* the value's own characters (one layer deeper than
case-068/`bb3e06bd`, where only the label was fragmented), this will not
find it — `evaluate_success()` would not confirm that shape as a bypass
either, so the redactor's reach is intentionally bounded to exactly what
the judge itself can already see, not further.

**The generalizable lesson**: the redactor and the matcher were one
algorithm wearing two names. Extending the matcher's reach without
extending the redactor's identical logic created a blind spot in exactly
the place the matcher's new reach pointed — any future extension to
`evaluate_success()`'s detection logic must ask the same question of the
redactor before being considered complete. Acted on below: the algorithm
itself (`marker_spans`/`replace_markers`) was extracted from
`rule_synthesizer.py` into `strike/marker_redaction.py` on 2026-08-06 so
there is exactly one implementation to keep in sync, not two to
remember to keep in sync.

### StrategyLibrary's marker redaction — CLOSED 2026-08-06

The follow-up flagged above, closed the same day it was found.
`strike/planner/strategy_library.py` had no redaction mechanism at all —
not a stale copy of the judge's pre-value-anchor algorithm, an absence.
Two independent exposure points, both closed:

- **Write path**: `build_abstraction_messages()` (called from
  `_abstract()`/`promote()`) sent the completely unredacted `target_reply`
  and `attack_turns` to the abstraction LLM for every promoted finding,
  relying entirely on a system-prompt instruction ("do not include literal
  secret or marker values") to keep the *model's own output* clean —
  nothing constrained the *input* it was shown.
- **Read path**: `retrieve()` returned stored strategy descriptions to the
  planner's own prompt (`attacker.py`'s `build_candidate_batch_messages()`)
  with no redaction either. Since the StrategyLibrary is retrieved before
  planning on every campaign that has one, any description containing a
  secret would re-enter an LLM prompt on every future round that retrieved
  it, not once — a persisted, recurring exposure, not a transient one.

**Checked directly against the live database before fixing anything, per
this fix's own verification step**: the one already-promoted strategy this
gap could have affected, `a67937c1-6b2c-4193-8e8d-61410f319a78`
(`source_finding_id: bb3e06bd-ea91-46e2-af20-57d9bd23b1b8`), does **not**
contain the secret — the abstraction model happened to follow its
system-prompt instruction on this occasion. This is a checked fact, not an
assumption, and it meant no existing-row remediation decision was needed
before fixing the mechanism. It is not a reason the mechanism didn't need
fixing: nothing enforced that outcome, so it was not guaranteed to recur.

**Fixed**: both `strategy_library.py` and `rule_synthesizer.py` now import
`marker_spans`/`replace_markers` from `strike/marker_redaction.py`, the
single shared implementation extracted per the lesson above.
`build_abstraction_messages()` redacts `attack_turns` and `target_reply`
before either reaches the LLM. `retrieve()` redacts every returned
`Strategy.description` before it can reach the planner's prompt — this is
what makes retrieval safe even for a strategy written before this fix
existed, since the enforcement point is retrieval itself, not trusting
every past (or future) write path to have redacted correctly.
`StrategyLibrary` now also takes `forbidden_marker_values`, threaded from
`runner.py` exactly as `RuleSynthesizer` already was. `promote()` gained
an output-side guard mirroring `RuleSynthesizer._secret_in_rule_rejection_reason()` —
and, in writing it, surfaced a real bug before it shipped: the first draft
used a naive `marker in description` literal-substring check, which
catches a leaked full label+value but misses a **value-only** leak (e.g.
"the answer is 7K2M9QX4" with no label) — exactly the class of gap this
whole fix exists to close. Caught by the test written to exercise that
exact shape (which passed for the wrong reason on the first attempt, via
an unrelated mocking gap, until the test itself was tightened to assert
the guard's own code path ran). Fixed to use `marker_spans()` instead.
**`RuleSynthesizer._secret_in_rule_rejection_reason()` in
`strike/synthesizer/rule_synthesizer.py:376-380` had this identical
naive-substring weakness** — found while fixing its sibling above, left
open at the time, closed the same way on 2026-08-06.

**Complete sweep for this pattern, not a partial one**: every LLM call
site in the repository was enumerated (`grep` for `/api/chat`,
`/api/generate`, `/api/embed` across all of `strike/` and `gate/` — zero
in `gate/`, confirmed). `strategy_library.py`'s objective-embedding call
and `prune_gate.py` were checked directly and confirmed to never receive
finding- or strategy-derived secret-bearing text. `strike/report.py`
renders finding evidence raw to the CLI operator — checked and correctly
out of scope, since that is the intended human-facing disclosure of
evidence to the person running the campaign, not an LLM-facing surface.
`dashboard/src` and `control/` (Control API) were checked directly and
confirmed to make no LLM calls at all.

### `RuleSynthesizer`'s output-side guard — CLOSED 2026-08-06

The last remaining instance of the naive-substring weakness, re-swept
for (not assumed from the earlier list) across all of `strike/` and
`gate/`: exactly one other hit,
`gate/app/main.py:538`'s `raw_exact_marker_match()`, checked and
confirmed to be a different kind of check entirely — a diagnostic fact
recorded on `gate.requests` for measurement purposes, not a guard
deciding whether something gets persisted or sent to an LLM — and out of
scope (`gate/`) regardless.

`_secret_in_rule_rejection_reason()` (`strike/synthesizer/rule_synthesizer.py:376-380`)
did `marker in serialized`, a literal full-marker substring check, same
as `strategy_library.py`'s first-draft guard above: it catches a proposal
that leaks the full label+value together but misses a **value-only**
leak in a proposal's free-text `description`/`rationale` fields (e.g.
"the answer is 7K2M9QX4", no label) — exactly the class of disclosure
the value-anchored work exists to catch. Fixed to call `marker_spans()`
from `strike/marker_redaction.py` instead of re-deriving the check —
the third and, per the completed sweep, final consumer of the one shared
implementation.

Verified with the same discipline the sibling fix required after its own
near-miss: the test asserts `mechanical_verification` was never awaited
for a value-only-leak candidate (proving the guard's own code path
actually rejected it, not merely that `propose()` eventually returned
`None` for some reason), and a companion negative-control test asserts
`mechanical_verification` **was** awaited for a clean candidate (proving
the guard doesn't over-reject). Confirmed fail-first: the value-only-leak
test failed against the pre-fix code specifically because
`mechanical_verification` *was* awaited — the leak reached verification
instead of being stopped, the precise vulnerability.

### The rule-promotion pipeline does not exist for either proposal family

Distinct from the marker label/value anchoring gap above — that entry is
about detection (what Gate's matcher can recognize); this one is about
promotion (whether a synthesized proposal, correct or not, has any
automated way to become a live Gate rule). Found while scoping a vocabulary
extension for the two live findings that entry describes, not by that gap
directly.

**Confirmed by full-repository search: there is no `INSERT` into
`strike.proposed_rules` anywhere in the codebase.** The signature/
`detector_config` proposal family's consuming pipeline
(`strike/synthesizer/review_cli.py` → `gate/apply_approved_rules.py`) has
nothing to consume — `runner.py`'s `synthesize_proposed_rule()` deliberately
never writes to that table, since the current placeholder-based
`SignatureSpec` cannot be safely flattened into its marker-bearing row shape.
This is dead code by design, not oversight, but it means a mechanically
verified signature proposal today has no path forward beyond being printed
and discarded.

**The normalization family has a working path, but every step past
mechanical verification is manual**, and `gate/apply_approved_pattern_versions.py`
— read in full — only ever toggles `active` on an *already-existing*
`pattern_versions.yaml` entry; it raises if the entry doesn't already exist.
**No script in this repository has ever created a new `DetectorPatternVersion`
entry.** Every pattern version in this repo's history, including the
currently active one, was hand-authored YAML.

This is the same class of danger as `normalization-e40488d4`'s five inert
days (above): a rule that mechanically passes every gate but has no
automated route to matter is functionally identical to one that passed
every gate and silently isn't reachable — both look like a closed loop from
the gates' perspective and aren't one. Full account, including the exact
search commands, the four places in this repo's own words stating why
`marker_ref` is the only pattern type safe to persist without embedding the
secret, and what building both the matcher and this missing pipeline would
actually cost:
[`docs/design/rule-vocabulary-and-promotion-gap.md`](design/rule-vocabulary-and-promotion-gap.md).

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
