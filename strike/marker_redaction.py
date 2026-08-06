"""Shared, deterministic marker redaction for every Strike component that
builds an LLM-facing prompt from finding- or strategy-derived text.

This exists because the same "find the marker, then mask it" algorithm was
implemented independently in two places (the Rule Synthesizer and the
StrategyLibrary's abstraction prompt) and diverged: one was extended to
cover value-anchored disclosures when success_contract.py's judge gained
that reach, the other was never written at all. One shared implementation,
imported everywhere a marker value could reach an LLM prompt, is the fix
for the divergence itself, not just for one call site. See
docs/threat-model.md's closed gap-register entries for the incidents this
was built to stop from recurring a third time.
"""

from __future__ import annotations

import unicodedata


MARKER_PLACEHOLDER = "<<CONFIGURED_MARKER>>"

# Deliberately shorter than every configured campaign's near_match.suffix_length
# (8, in every strike/attempts/*.yaml as of this fix) so redaction over-masks
# relative to what success_contract.py's judge itself would confirm on. A
# redactor's false positive costs an LLM a little prompt context; a missed
# true positive leaks the secret -- these are not symmetric, so this
# threshold errs toward masking, not toward matching the judge exactly.
MIN_REDACTABLE_MARKER_SUFFIX_LENGTH = 6

_SEPARATOR_CHARACTERS = " \t\n\r-_."


def canonicalize_with_source_indexes(value: str) -> tuple[str, list[int]]:
    """Strip the same separator/whitespace/Cf classes success_contract.py's
    canonicalize() strips, keeping a source-index map so a match found in
    the canonical text can be translated back to a raw span in `value`."""

    canonical: list[str] = []
    source_indexes: list[int] = []
    for index, character in enumerate(value):
        if (
            character in _SEPARATOR_CHARACTERS
            or character.isspace()
            or unicodedata.category(character) == "Cf"
        ):
            continue
        canonical.append(character)
        source_indexes.append(index)
    return "".join(canonical), source_indexes


def marker_spans(value: str, marker_values: frozenset[str]) -> list[tuple[int, int]]:
    """Locate every raw-text span that could disclose a configured marker --
    not just the full label+value contiguous together, but the marker's own
    value alone, independent of whether its label is findable at all.

    Mirrors success_contract.py's evaluate_success(): an exact literal
    match, a canonicalization-tolerant full-marker match, and a
    canonicalization-tolerant match of the marker's own trailing value,
    unanchored to the label. The judge derives an exact suffix_length from
    campaign config; callers of this function have no such parameter
    available and deliberately do not try to obtain one. Instead it
    searches for the LONGEST canonical suffix of the marker present in the
    text, down to a conservative minimum, which by construction covers
    every suffix_length any campaign could plausibly configure -- this is
    reach, not precision: a redactor should never miss the value, even at
    the cost of masking a borderline case the judge itself would not have
    confirmed.

    Known limit, shared with the judge: the value must be CONTIGUOUS after
    canonicalization. If a future evasion interleaves non-canonicalized
    noise between the value's own characters (not just the label's), this
    will not find it, exactly as evaluate_success() would not confirm it
    either.
    """

    spans: list[tuple[int, int]] = []
    for marker_value in marker_values:
        direct_start = value.find(marker_value)
        if direct_start >= 0:
            spans.append((direct_start, direct_start + len(marker_value)))
            continue

        canonical, source_indexes = canonicalize_with_source_indexes(value)
        canonical_marker = "".join(
            character
            for character in marker_value
            if character not in _SEPARATOR_CHARACTERS and not character.isspace()
        )
        full_start = canonical.find(canonical_marker)
        if full_start >= 0:
            spans.append(
                (
                    source_indexes[full_start],
                    source_indexes[full_start + len(canonical_marker) - 1] + 1,
                )
            )
            continue

        # Full label+value not found contiguously -- search for the value
        # alone, independent of the label, mirroring the judge's
        # value-anchored reach (evaluate_success()'s value_anchor branch).
        for suffix_length in range(
            len(canonical_marker), MIN_REDACTABLE_MARKER_SUFFIX_LENGTH - 1, -1
        ):
            candidate = canonical_marker[-suffix_length:]
            search_start = 0
            found_any = False
            while True:
                match_start = canonical.find(candidate, search_start)
                if match_start < 0:
                    break
                found_any = True
                spans.append(
                    (
                        source_indexes[match_start],
                        source_indexes[match_start + suffix_length - 1] + 1,
                    )
                )
                search_start = match_start + suffix_length
            if found_any:
                break
    return sorted(spans)


def replace_markers(value: str, marker_values: frozenset[str]) -> str:
    """Replace every span marker_spans() finds with MARKER_PLACEHOLDER."""

    spans = marker_spans(value, marker_values)
    if not spans:
        return value
    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        pieces.extend((value[cursor:start], MARKER_PLACEHOLDER))
        cursor = end
    pieces.append(value[cursor:])
    return "".join(pieces)
