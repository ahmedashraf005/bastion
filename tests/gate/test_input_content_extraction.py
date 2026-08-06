"""Content-shape handling for input-stage scanning: extract_text_content()
and the removal of most_recent_user_message()'s string-only restriction.

Before this, a user message with OpenAI-style content-block-array content
was silently skipped by Presidio in favor of an earlier string-content
message (or None) — PII in that shape went unscanned regardless of any
tool-output feature. This is a fix to shipped LLM02 behavior, not new
coverage.
"""

from __future__ import annotations

import unittest

from tests import _pathfix  # noqa: F401
from app.main import extract_text_content, most_recent_user_message


class ExtractTextContentTests(unittest.TestCase):
    def test_plain_string_returned_as_is(self) -> None:
        self.assertEqual(extract_text_content("hello"), "hello")

    def test_openai_content_block_array_extracts_text_key(self) -> None:
        content = [{"type": "text", "text": "hello"}, {"type": "text", "text": "world"}]
        self.assertEqual(extract_text_content(content), "hello\nworld")

    def test_content_key_fallback_when_text_key_absent(self) -> None:
        content = [{"type": "text", "content": "fallback shape"}]
        self.assertEqual(extract_text_content(content), "fallback shape")

    def test_non_text_blocks_are_skipped_not_scanned(self) -> None:
        content = [
            {"type": "image_url", "image_url": {"url": "http://example.com/x.png"}},
            {"type": "text", "text": "the actual text"},
        ]
        self.assertEqual(extract_text_content(content), "the actual text")

    def test_none_and_unknown_shapes_return_empty_string(self) -> None:
        self.assertEqual(extract_text_content(None), "")
        self.assertEqual(extract_text_content(42), "")
        self.assertEqual(extract_text_content({"not": "a list"}), "")


class MessageSelectionTests(unittest.TestCase):
    def test_most_recent_user_message_no_longer_requires_string_content(self) -> None:
        body = {
            "messages": [
                {"role": "user", "content": "first"},
                {"role": "user", "content": [{"type": "text", "text": "second"}]},
            ]
        }
        selected = most_recent_user_message(body)
        self.assertIsNotNone(selected)
        self.assertEqual(selected["content"], [{"type": "text", "text": "second"}])


if __name__ == "__main__":
    unittest.main()
