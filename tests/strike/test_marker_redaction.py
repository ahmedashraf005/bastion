"""marker_spans()/replace_markers() must find and mask every occurrence of a
configured marker in one string, not just the first.

HANDOFF.md §7/§9: marker_spans()'s exact-literal and canonicalized-full-match
branches each call .find() once and continue to the next marker_value,
finding only the first occurrence. A target response containing the marker
twice would have its raw second occurrence reach an LLM-facing prompt
(strategy_library.py's abstraction call, rule_synthesizer.py's synthesis
call) unmasked -- not yet exercised by either confirmed finding, but nothing
upstream prevents it.
"""

from __future__ import annotations

import unittest

from tests import _pathfix  # noqa: F401
from strike.marker_redaction import MARKER_PLACEHOLDER, marker_spans, replace_markers


MARKER = "BASTION-CANARY-7K2M9QX4"


class DoubledMarkerTests(unittest.TestCase):
    def test_marker_spans_finds_both_exact_literal_occurrences(self) -> None:
        text = f"first: {MARKER} later, again: {MARKER} end"
        spans = marker_spans(text, frozenset({MARKER}))

        self.assertEqual(len(spans), 2, f"expected 2 spans, got {spans}")
        for start, end in spans:
            self.assertEqual(text[start:end], MARKER)

    def test_replace_markers_masks_both_exact_literal_occurrences(self) -> None:
        text = f"first: {MARKER} later, again: {MARKER} end"
        redacted = replace_markers(text, frozenset({MARKER}))

        self.assertNotIn(MARKER, redacted, "second occurrence survived redaction")
        self.assertEqual(redacted.count(MARKER_PLACEHOLDER), 2)

    def test_marker_spans_finds_both_canonicalized_occurrences(self) -> None:
        # Obfuscated the same way the two real confirmed findings were:
        # zero-width spaces between characters, canonicalization-tolerant
        # rather than a literal substring match.
        obfuscated = "​".join("BASTION-CANARY-7K2M9QX4")
        text = f"one: {obfuscated} two: {obfuscated}"
        spans = marker_spans(text, frozenset({MARKER}))

        self.assertEqual(len(spans), 2, f"expected 2 spans, got {spans}")

    def test_replace_markers_masks_both_canonicalized_occurrences(self) -> None:
        obfuscated = "​".join("BASTION-CANARY-7K2M9QX4")
        text = f"one: {obfuscated} two: {obfuscated}"
        redacted = replace_markers(text, frozenset({MARKER}))

        self.assertEqual(redacted.count(MARKER_PLACEHOLDER), 2)


if __name__ == "__main__":
    unittest.main()
