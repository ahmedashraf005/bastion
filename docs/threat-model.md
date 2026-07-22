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
| LLM10 | Unbounded Consumption | Yes |

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
