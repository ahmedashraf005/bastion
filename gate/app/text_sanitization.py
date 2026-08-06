"""Persistence-boundary sanitization for two Postgres-fatal character
classes: NUL bytes and lone UTF-16 surrogates.

Both are storage-level limitations, not specific to either text or JSONB
columns, but the two classes fail differently and were investigated
separately (see docs/design/nul-byte-persistence-fix.md for the full
record of both).

NUL bytes (U+0000): a Text-destined value raises
CharacterNotInRepertoireError; a JSONB-destined value raises
UntranslatableCharacterError ("unsupported Unicode escape sequence").
Postgres cannot store an embedded NUL in either column type — internal
text values are NUL-terminated.

Lone UTF-16 surrogates (U+D800-U+DFFF, i.e. a surrogate codepoint that is
not part of a valid pair): a Text-destined value never reaches Postgres at
all — asyncpg's own UTF-8 encoder raises DataError (a UnicodeEncodeError,
client-side) before the query is sent. A JSONB-destined value does reach
Postgres, whose JSON parser rejects the malformed escape server-side with
InvalidTextRepresentationError ("invalid input syntax for type json",
detail "Unicode low surrogate must follow a high surrogate"). Both are
confirmed by direct reproduction against a real Postgres instance through
the actual SQLAlchemy async engine + asyncpg dialect stack this project
uses (docs/design/nul-byte-persistence-fix.md), not assumed from either
class's name.

A genuinely valid astral-plane character (e.g. an emoji) is NEVER at risk:
CPython represents it as a single codepoint outside the D800-DFFF range,
not as two separate lone-surrogate codepoints — a lone surrogate only
exists in a Python str when something upstream (planner output,
malformed encoding/decoding) produced one directly. Filtering by
codepoint range therefore cannot mistake a valid pair for two lone
surrogates; there is no pair to mistake, because Python strings do not
represent astral characters as UTF-16 surrogate pairs in the first place.

Used at every write boundary that can carry planner- or target-generated
text (strike.attempts, strike.findings, gate.requests) — never earlier.
Success-contract scoring and Gate's detectors always run against the
original, unsanitized content; this module is only ever applied to a local
copy built immediately before an INSERT, so a sanitized payload scores
exactly as it would have.
"""

from __future__ import annotations

from typing import Any


def _is_lone_surrogate(character: str) -> bool:
    """True for a single-character string whose codepoint is in the UTF-16
    surrogate range (U+D800-U+DFFF). Every element produced by iterating a
    Python str is exactly one codepoint, so this never needs to consider
    pairing -- a valid astral character was never two surrogate codepoints
    to begin with (see the module docstring)."""

    return 0xD800 <= ord(character) <= 0xDFFF


def strip_nul_bytes(value: Any) -> tuple[Any, bool]:
    """Recursively strip NUL bytes and lone UTF-16 surrogates from strings
    in a JSON-compatible value. Function name kept as strip_nul_bytes
    (rather than renamed to reflect the wider scope) because this module,
    its call sites in gate/app/main.py and strike/app/runner.py, and its
    existing test coverage were already shipped before the surrogate class
    was investigated -- renaming would churn already-reviewed, already-
    pushed code for a purely cosmetic reason. This docstring is the
    accurate description of what the function does today.

    Returns (sanitized_value, was_sanitized). Never mutates the input in
    place — always returns new containers — so the original evidence object
    held by the caller is untouched; only the copy handed to the database
    write is altered. was_sanitized is True if any string anywhere in the
    structure contained a NUL byte or a lone surrogate; the caller must
    record that, not persist it silently.
    """

    if isinstance(value, str):
        filtered = "".join(
            character
            for character in value
            if character != "\x00" and not _is_lone_surrogate(character)
        )
        if filtered != value:
            return filtered, True
        return value, False
    if isinstance(value, dict):
        sanitized_dict: dict[Any, Any] = {}
        changed = False
        for key, item in value.items():
            sanitized_item, item_changed = strip_nul_bytes(item)
            sanitized_dict[key] = sanitized_item
            changed = changed or item_changed
        return sanitized_dict, changed
    if isinstance(value, list):
        sanitized_list: list[Any] = []
        changed = False
        for item in value:
            sanitized_item, item_changed = strip_nul_bytes(item)
            sanitized_list.append(sanitized_item)
            changed = changed or item_changed
        return sanitized_list, changed
    return value, False


def strip_nul_bytes_from_all(*values: Any) -> tuple[list[Any], bool]:
    """Sanitize several independent values for one write, one combined flag."""

    sanitized_values: list[Any] = []
    any_changed = False
    for value in values:
        sanitized_value, changed = strip_nul_bytes(value)
        sanitized_values.append(sanitized_value)
        any_changed = any_changed or changed
    return sanitized_values, any_changed
