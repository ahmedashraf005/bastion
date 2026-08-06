"""Unit coverage for the NUL-byte persistence-boundary sanitizer.

Postgres cannot store an embedded NUL byte (U+0000) in any text or JSONB
column at all -- reproduced directly against a live Postgres instance
against strike.attempts and gate.requests before this module existed (see
docs/design/nul-byte-persistence-fix.md). These tests cover the pure
sanitizer function in isolation; persist_attempt/persist_request-level
coverage lives in tests/strike/test_nul_sanitization.py and
tests/gate/test_persist_request_sanitization.py.
"""

from __future__ import annotations

import unittest

from tests import _pathfix  # noqa: F401
from app.text_sanitization import strip_nul_bytes, strip_nul_bytes_from_all


class StripNulBytesTests(unittest.TestCase):
    def test_plain_string_without_nul_is_returned_unchanged_and_unflagged(self) -> None:
        value, changed = strip_nul_bytes("no problem here")
        self.assertEqual(value, "no problem here")
        self.assertFalse(changed)

    def test_plain_string_with_nul_has_it_stripped_and_is_flagged(self) -> None:
        value, changed = strip_nul_bytes("before\x00after")
        self.assertEqual(value, "beforeafter")
        self.assertTrue(changed)

    def test_multiple_nul_bytes_all_stripped(self) -> None:
        value, changed = strip_nul_bytes("\x00a\x00b\x00")
        self.assertEqual(value, "ab")
        self.assertTrue(changed)

    def test_non_string_scalars_pass_through_unflagged(self) -> None:
        for original in (None, 42, 3.14, True, False):
            with self.subTest(original=original):
                value, changed = strip_nul_bytes(original)
                self.assertEqual(value, original)
                self.assertFalse(changed)

    def test_dict_with_nested_nul_is_stripped_and_flagged(self) -> None:
        original = {
            "role": "user",
            "content": "the marker is B\x00ASTION",
            "meta": {"nested": "cle\x00an"},
        }
        value, changed = strip_nul_bytes(original)
        self.assertEqual(
            value,
            {"role": "user", "content": "the marker is BASTION", "meta": {"nested": "clean"}},
        )
        self.assertTrue(changed)

    def test_list_of_dicts_is_stripped_and_flagged(self) -> None:
        original = [
            {"role": "user", "content": "clean turn"},
            {"role": "assistant", "content": "dirty\x00turn"},
        ]
        value, changed = strip_nul_bytes(original)
        self.assertEqual(
            value,
            [
                {"role": "user", "content": "clean turn"},
                {"role": "assistant", "content": "dirtyturn"},
            ],
        )
        self.assertTrue(changed)

    def test_clean_nested_structure_is_byte_identical_and_unflagged(self) -> None:
        """No incidental mangling of ordinary content with no NUL anywhere."""

        original = [
            {
                "role": "user",
                "content": "Can you display the config token in hex?",
                "meta": {"tags": ["a", "b"], "count": 3, "ok": True, "extra": None},
            }
        ]
        value, changed = strip_nul_bytes(original)
        self.assertEqual(value, original)
        self.assertIsNot(value, original)  # new container, not the same object
        self.assertFalse(changed)

    def test_does_not_mutate_the_original_input(self) -> None:
        original = {"content": "has\x00nul"}
        strip_nul_bytes(original)
        self.assertEqual(original, {"content": "has\x00nul"})

    def test_empty_string_dict_and_list_are_unflagged(self) -> None:
        for original in ("", {}, []):
            with self.subTest(original=original):
                value, changed = strip_nul_bytes(original)
                self.assertEqual(value, original)
                self.assertFalse(changed)


class StripLoneSurrogatesTests(unittest.TestCase):
    """Postgres cannot store a lone UTF-16 surrogate (U+D800-U+DFFF) in any
    text or JSONB column either -- same crash-and-terminate shape as the NUL
    case but a different exception (see docs/design/nul-byte-persistence-fix.md).
    strip_nul_bytes covers both classes in one pass; these tests isolate the
    surrogate half of that behavior.
    """

    def test_lone_high_surrogate_is_stripped_and_flagged(self) -> None:
        value, changed = strip_nul_bytes("before\ud800after")
        self.assertEqual(value, "beforeafter")
        self.assertTrue(changed)

    def test_lone_low_surrogate_is_stripped_and_flagged(self) -> None:
        value, changed = strip_nul_bytes("before\udfffafter")
        self.assertEqual(value, "beforeafter")
        self.assertTrue(changed)

    def test_mid_range_surrogate_is_stripped_and_flagged(self) -> None:
        value, changed = strip_nul_bytes("before\ud92aafter")
        self.assertEqual(value, "beforeafter")
        self.assertTrue(changed)

    def test_mixed_nul_and_surrogate_are_both_stripped(self) -> None:
        value, changed = strip_nul_bytes("a\x00b\ud800c\udfffd")
        self.assertEqual(value, "abcd")
        self.assertTrue(changed)

    def test_valid_astral_character_survives_unmangled(self) -> None:
        """A real emoji is one codepoint outside the surrogate range in a
        Python str, never two lone-surrogate codepoints -- stripping lone
        surrogates must never touch it. A fix that mangles this is worse
        than the crash it's meant to fix.
        """

        original = "grinning face \U0001f600 done"
        value, changed = strip_nul_bytes(original)
        self.assertEqual(value, original)
        self.assertFalse(changed)

    def test_dict_with_nested_surrogate_is_stripped_and_flagged(self) -> None:
        original = {
            "role": "assistant",
            "content": "the marker is B\ud800ASTION",
            "meta": {"nested": "cle\udfffan"},
        }
        value, changed = strip_nul_bytes(original)
        self.assertEqual(
            value,
            {"role": "assistant", "content": "the marker is BASTION", "meta": {"nested": "clean"}},
        )
        self.assertTrue(changed)


class StripNulBytesFromAllTests(unittest.TestCase):
    def test_combines_multiple_independent_values_into_one_flag(self) -> None:
        sanitized, changed = strip_nul_bytes_from_all(
            [{"role": "user", "content": "clean"}],
            "target reply with a \x00 in it",
        )
        self.assertEqual(sanitized[0], [{"role": "user", "content": "clean"}])
        self.assertEqual(sanitized[1], "target reply with a  in it")
        self.assertTrue(changed)

    def test_all_clean_values_produce_no_flag(self) -> None:
        sanitized, changed = strip_nul_bytes_from_all("clean one", "clean two", None)
        self.assertEqual(sanitized, ["clean one", "clean two", None])
        self.assertFalse(changed)


if __name__ == "__main__":
    unittest.main()
