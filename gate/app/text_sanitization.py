"""NUL-byte sanitization at the Postgres persistence boundary.

Postgres text and JSONB columns cannot store an embedded NUL byte (U+0000)
at all — this is a storage-level limitation (internal text values are
NUL-terminated), not specific to either column type. asyncpg surfaces it as
UntranslatableCharacterError ("\\u0000 cannot be converted to text").
Lone UTF-16 surrogates hit a related but distinct error
(InvalidTextRepresentationError) and are NOT handled here — investigated,
deliberately out of scope; see docs/design/nul-byte-persistence-fix.md.

Used at every write boundary that can carry planner- or target-generated
text (strike.attempts, strike.findings, gate.requests) — never earlier.
Success-contract scoring and Gate's detectors always run against the
original, unsanitized content; this module is only ever applied to a local
copy built immediately before an INSERT, so a sanitized payload scores
exactly as it would have.
"""

from __future__ import annotations

from typing import Any


def strip_nul_bytes(value: Any) -> tuple[Any, bool]:
    """Recursively strip U+0000 from strings in a JSON-compatible value.

    Returns (sanitized_value, was_sanitized). Never mutates the input in
    place — always returns new containers — so the original evidence object
    held by the caller is untouched; only the copy handed to the database
    write is altered. was_sanitized is True if any string anywhere in the
    structure contained a NUL byte; the caller must record that, not persist
    it silently.
    """

    if isinstance(value, str):
        if "\x00" in value:
            return value.replace("\x00", ""), True
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
