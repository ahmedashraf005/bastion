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

Unicode compatibility and homoglyph substitution is a separate, live residual
class. The same pressure probes spontaneously emitted fullwidth forms
(`density-probe-3`), accented/soft-hyphen/non-breaking-hyphen substitutions
(`density-probe-8`), and HTML entity text (`density-probe-7`). These are not
covered by this detector's ASCII-only case-insensitive comparison. They require
separate mechanical corpus evidence and a separately reviewed remediation; do
not broaden this value matcher implicitly.

If a configured reference cannot resolve, Gate fails startup/readiness rather
than silently weakening output detection.
