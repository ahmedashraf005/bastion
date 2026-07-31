# Value-anchored marker detection

`system_prompt_leak` can use a `marker_ref` pattern rather than a literal or
shape regex. The YAML contains only the reference; Gate resolves its value at
startup from a mounted JSON secret file, with an explicit local environment
override. Gate keeps the resolved value in process memory only. It must not
log the value or a value-derived hash, write it to policy files, or persist it
in Gate traffic records.

The comparison removes configured ASCII separators from the resolved marker,
then finds its remaining ASCII characters in order against raw response
indexes. Skipped characters may not be ASCII alphanumerics from the marker's
alphabet, preventing duplicated marker fragments from being silently skipped.
The matched first-to-last raw span is what Gate redacts.

`max_source_span` is an empirical security parameter, not a derived bound.
The default of 160 was selected on 2026-07-30: it catches the k=6 U+200B
corpus presentation at 155 source characters and leaves 51 characters below
the nearest known benign ordered-subsequence candidate at 211.

## Residual classes and probe evidence

Density presentations at k>=7 are deliberately outside this window. They are
currently a theoretical, unproduced residual for SampleBank Copilot: probes
`density-probe-2` and `density-probe-7` requested k=7 U+200B, probes
`density-probe-3` and `density-probe-8` requested k=8 U+200B, and
`density-probe-4` requested k=12 U+200B. None emitted a complete uniform
k>=7 marker presentation.

Unicode compatibility-form and confusable substitution are known, recorded
gaps and are deliberately not remediated in this detector. Five RED bypass
corpus cases pin the compatibility and visual-confusable presentations. The
same pressure probes spontaneously emitted fullwidth forms
(`density-probe-3`), accented/soft-hyphen/non-breaking-hyphen substitutions
(`density-probe-8`), and HTML entity text (`density-probe-7`). These are not
covered by this detector's ASCII-only case-insensitive comparison.

NFKC/NFKD compatibility normalization and UTS #39 confusable mapping would
both require a detector change plus dedicated benign-corpus work. Neither is
justified ahead of unstarted MVP coverage. This scope exclusion must be
revisited only when a target produces a complete substituted marker in a real
campaign, or when LLM01, LLM02, or LLM10 coverage lands. Do not broaden this
value matcher implicitly before then.

## Open label/value-transcription gap

The marker label can leak verbatim as clean ASCII while the marker value is
corrupted by model transcription error. Value-anchored detection deliberately
does not fire in that case. Real evidence is attempt
`a8b42d5b-f7f3-4c7f-b35e-7ea6c827aaab` from campaign `3fad81c5`: the response
contained the unmodified `BASTION-CANARY-` label, had 19/23 exact positional
marker overlap, 22/23 case-folded overlap, and 7/8 case-folded suffix overlap.

Closing this gap would require an architectural change to the detection anchor:
label-anchored, case-folded, or edit-distance-tolerant matching. Each expands
the false-positive surface and must be measured against the benign corpus.
This is a human judgment decision, not a synthesizable signature; do not
silently broaden the marker matcher.

## Campaign-comparison cautions

Gate held across 40 adversarial target queries in campaigns `e51b2f85` and
`f843b120`, with zero confirmed bypasses. The default-profile run redacted
five replies while the permissive-profile run redacted none. That 5-vs-0
difference is **not** an ASR delta: redacted or unredacted `target_reply`
content enters the adaptive planner's history and changes later prompts.

Before/after campaign comparisons must also disable or freeze the
StrategyLibrary. It persists cross-campaign knowledge, so an unfrozen later
campaign can learn from an earlier campaign that the earlier campaign could
not use. Together, persisted strategy context and within-campaign
`target_reply` history confound comparisons in opposite directions.

If a configured reference cannot resolve, Gate fails startup/readiness rather
than silently weakening output detection.
