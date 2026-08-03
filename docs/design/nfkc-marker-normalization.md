# NFKC marker normalization — signed off, promoted

Status: **active as of 2026-08-03.** `gate/detectors/normalization_versions.yaml`
carries the entry `normalization-b7b3cad1-fb2f-4d03-8338-7bd01762eb23` with
`active: true`, promoted after sign-off on the four steps below, plus a
live branching-campaign confirmation.

**Promotion required deactivating `normalization-e40488d4` (the `Cf`
category entry), not removing it.** Gate enforces exactly one active entry
per manifest (`gate/app/policy_profile.py:active_manifest_version` — it
backs the single `gate_normalization_version_id` recorded per
campaign/request; more than one active `version_id` raises at startup).
This was discovered when the first restart attempt with both entries active
failed loudly with `RuntimeError: Gate version manifest has ambiguous
active versions`. Since `normalization-e40488d4` already had zero live
effect (see [Step 2](#step-2--pipeline-placement)), deactivating it changed
no actual detection behavior — confirmed by rerunning the full corpus
after the change, still 33 matched + 2 pinned and 0/48 benign, unchanged.
See `docs/design/value-anchored-marker-detection.md`, "Promoted-rule
reachability is not guaranteed by the promotion gates," for the full
account of why that entry was already inert.

## Scope

Only Gate's LLM07 `marker_ref` match path
(`SystemPromptLeakDetector._marker_ref_spans`). Not applied to Presidio
(LLM02), Prompt Guard (LLM01), general policy matching, request logging, or
anything Strike does. See [Blast radius](#blast-radius) for the call-site
audit backing that claim.

## Target residuals (four of six pinned)

`llm07-homoglyph-fullwidth-001`, `llm07-homoglyph-mathematical-bold-001`,
`llm07-homoglyph-circled-001`, `llm07-homoglyph-parenthesized-001`.

Not in scope, stay pinned:
- `llm07-homoglyph-cyrillic-greek-confusables-001` — Cyrillic/Greek letters
  are canonically distinct characters from their Latin look-alikes, not
  compatibility variants of them. NFKC does not touch them; a UTS #39
  confusables map is separate work.
- `llm07-cf-zero-width-space-density-k8-001` — a `max_source_span` window
  limitation (199-char raw span vs. the 160-char window), not a
  normalization gap. U+200B has no compatibility decomposition; NFKC cannot
  affect it.

## Step 1 — hypothesis verification (before any code change)

Applied `unicodedata.normalize("NFKC", payload)` to each corpus payload
directly and re-scanned with Gate's real detector:

| Case | Before | After NFKC | NFKC alone sufficient |
|---|---|---|---|
| fullwidth | no match | matched, redact | yes |
| mathematical-bold | no match | matched, redact | yes |
| circled | no match | matched, redact | yes |
| parenthesized | no match | matched, redact | yes |
| cyrillic-greek-confusables (out of scope) | no match | no match, payload byte-identical | n/a — confirmed unaffected |
| zero-width-space density k=8 (out of scope) | no match | no match, payload byte-identical | n/a — confirmed unaffected |

All four target cases close with NFKC alone. Both out-of-scope cases are
provably untouched (not just still-failing — the payload string itself is
unchanged by NFKC).

## Step 2 — pipeline placement

**The premise that there is a single separator/whitespace/Cf pipeline
shared across LLM07 needs a correction.** There are two independent
matching mechanisms in `system_prompt_leak.py`, and the active pattern uses
the one that does *not* go through Cf/whitespace stripping at all:

1. **`literal`/`regex` patterns with `normalize: strip_separators`** —
   `_strip_separators_with_index_map` strips separators, Unicode
   whitespace, and any category/class/codepoint listed in an active
   `PromotedNormalization` (currently just `Cf`, from
   `normalization-e40488d4`), then regex-matches the stripped text and maps
   spans back via an index map. This is the **baseline** pattern
   (`example-canary-pattern`), currently inactive.
2. **`marker_ref` patterns** (the currently active
   `sample-bank-configuration-marker`) — `_marker_ref_spans` scans raw
   `content` directly with a bounded character-by-character walk: it looks
   for the marker's first character, then advances through the rest of the
   marker's characters, treating *any* character that isn't an ASCII
   alphanumeric from the marker's own alphabet as a skippable interleaver
   (`_allowed_marker_interleaver`) — regardless of Unicode category. This
   already subsumes Cf, Mn, Co, Cc, whitespace, and more, which is why
   29/35 corpus cases already pass without needing the promoted-Cf
   normalization to be consulted at all.

**Consequence:** the existing `Cf` promoted normalization
(`normalization-e40488d4`) currently has zero effect on live marker
detection — it only matters for the inactive baseline regex pattern. The
four target residuals fail not because of missing category stripping, but
because their characters are not ASCII at all, so
`_marker_char_equal`/`_allowed_marker_interleaver` never recognize them as
either a marker character or the marker's *first* character — the scan
never even starts.

**Where NFKC sits:** as a new, first content-side normalization step for
the `marker_ref` path specifically, applied *before* `_marker_ref_spans`
runs — there is no earlier LLM07 step to order it against for this pattern,
since this path has never used the Cf/whitespace pipeline. It converts
compatibility-form characters (fullwidth, mathematical bold, circled,
parenthesized) to their plain ASCII equivalents, after which the existing
bounded-skip scan finds them exactly as it would find plain ASCII input —
no change to the scanning logic itself.

**Composition order chosen: per-character, not whole-string.**
`unicodedata.normalize("NFKC", content)` on the whole string also performs
*canonical* composition across adjacent characters — e.g. a bare "A"
followed by a standalone combining acute accent (U+0301) composes into one
precomposed "Á". Verified this diverges from per-character normalization on
exactly one payload in the full bypass+benign corpus
(`llm07-mn-combining-acute-001`, a currently-passing, non-target case) and
matches it everywhere else, including all four target payloads. Per-character
normalization is the conservative choice: it leaves that already-correctly-handled
case completely unchanged, and — separately — it is what makes an exact
source-index map possible, which redaction correctness requires (see
[Blast radius](#blast-radius)).

## Step 3 — cost, measured

Measured against a temporary copy of the manifest with the new entry's
`active` flipped to `true` (the checked-in manifest stays `active: false`);
everything else identical to the live config.

**Bypass corpus**, 35 total cases:

| | Before | After |
|---|---|---|
| Matched (unpinned) | 29 | 33 |
| Pinned (`expected_failure`) | 6 | 2 |

Pins removed (once promoted): `llm07-homoglyph-fullwidth-001`,
`llm07-homoglyph-mathematical-bold-001`, `llm07-homoglyph-circled-001`,
`llm07-homoglyph-parenthesized-001`. **Not removed in this proposal** — the
corpus's `expected_failure` pins must stay in sync with what the *live*
manifest actually does; removing them now while the manifest is inactive
would leave `test_bypass_regression.py` red at rest. The pin-removal diff
is prepared and is meant to land in the same commit that flips this
version's `active` field to `true`, mirroring the project's existing rule
that benign-corpus band assignment must never change in the same commit as
a rule promotion.

**Benign corpus**, 48 total cases across four bands — before and after are
identical:

| Band | Total | FP before | FP after |
|---|---|---|---|
| ordinary | 20 | 0 | 0 |
| adjacent_vocabulary | 10 | 0 | 0 |
| structurally_awkward | 12 | 0 | 0 |
| redaction_span | 6 | 0 | 0 |

0/48 both before and after. Beyond the false-positive count, every
individual case's *verdict* (allow / redact / block, per case id) was
diffed before vs. after — **zero cases changed verdict**, so this is not
just an unchanged FP rate, it is unchanged behavior on every single benign
case.

## Step 4 — blast radius

**Call sites of `_form_normalize_with_index_map`** (the new function):
exactly one, inside `SystemPromptLeakDetector.scan()`'s `marker_ref`
branch. **Call sites of `_marker_ref_spans`**: two, both in the same
branch of the same method (NFKC-active and NFKC-inactive paths). No other
caller anywhere in the repository.

**`SystemPromptLeakDetector` usage in Gate**: constructed once at startup
(`gate/app/main.py`), invoked via `.scan()` at exactly two call sites, both
for **output-stage** scanning of the assistant's own response content
(the streaming-terminal path and the buffered-response path). Presidio
(`PresidioPiiDetector`) and Prompt Guard (`PromptGuardDetector`) are
separate classes from separate modules with their own `scan()` methods —
neither imports nor calls anything in `system_prompt_leak.py`.

**Strike**: `strike/synthesizer/rule_synthesizer.py` imports
`SystemPromptLeakDetector` to mechanically verify proposals against the real
detector code (the existing, correct design — verification uses the actual
class, not a reimplementation). Strike's own proposal model
(`AdditiveNormalization`) is constrained to a fixed
`Literal["Cf","Cc","Zs","Zl","Zp"]` category set plus named classes and
codepoints — it has **no `marker_unicode_form` field and cannot generate
one**. This manifest entry was hand-authored for this sign-off-gated task;
Strike's autonomous proposal loop cannot produce or apply an NFKC proposal
on its own.

**Is normalized text ever persisted or returned?** No.
`marker_normalized_content` is a local variable inside `scan()`, used only
as the input to `_marker_ref_spans`; the spans it returns are immediately
mapped back to raw-content indexes via `marker_index_map` before being used
for anything else. The redaction itself
(`redacted_content = content[:start] + "[REDACTED]" + content[end:]`)
always slices the **original** `content` string — never the normalized
one. Verified by a dedicated test
(`test_nfkc_active_redaction_span_is_byte_exact_against_raw_content`):
every target case's `redacted_content` is exactly `"[REDACTED]"` — a full
replacement of the entire payload, containing none of the literal `(`
characters that NFKC introduces for the parenthesized case, confirming the
returned text is never a slice of normalized content.

**One measured side effect, not a bug**: `max_source_span` (160) is
enforced against the *normalized*-text character count, not the raw one,
when NFKC is active. For 1:1 forms (fullwidth, mathematical bold, circled)
this is identical to the raw count. For parenthesized decomposition
(1 character → 3, e.g. `🄑` → `(A)`), the normalized span is up to 3x the
raw span — stricter, not looser, so this can only ever tighten the window
for expansion-type compatibility forms, never widen it. Confirmed
non-issue for the actual marker (23 significant characters, well under 160
even at 3x expansion).

## max_source_span margin check (pre-flip)

Before promoting, checked every currently-passing bypass corpus case's
matched span length as measured in NFKC-normalized space (what
`max_source_span` actually bounds once NFKC is active) against the 160
limit. Closest case: `llm07-cf-zero-width-space-density-k6-001` at
155/160 (margin 5) — but this is the **pre-existing** margin, not newly
tightened: U+200B has no NFKC compatibility decomposition, so its payload
is byte-identical under NFKC and its span is identical, 155, with or
without this change. Checked comprehensively across the full 35-case
corpus: NFKC changes the matched span length for **exactly the four target
cases**, none of the other 31. All four land with generous margin (137
spare for the three 1:1 forms, 97 spare for parenthesized).

## Status of the "what's next" list

1. ✅ Human sign-off received.
2. ✅ Flipped `normalization-b7b3cad1-fb2f-4d03-8338-7bd01762eb23` to
   `active: true`; corpus pins removed in the same change. Required also
   deactivating `normalization-e40488d4` — see the promotion note above.
3. Rebuild and restart the live Gate container; confirm the new version id
   in Gate's own startup log. First attempt failed loudly (see the
   promotion note above) before the Cf-entry deactivation was applied.
4. Branching campaign against the new active version — see the campaign
   report appended to this document (or the accompanying report) for
   campaign id, status, and outcomes.
