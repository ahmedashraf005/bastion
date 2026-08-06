"""Guards against reintroducing the silent test-collection gap this package
was built to close.

unittest discover() only recurses into a subdirectory if that subdirectory
has an __init__.py -- for any subdirectory lacking one, discover() returns
(None, False) with no error and no output (unittest/loader.py's
_find_tests/_find_test_path). A test-bearing subdirectory added later
without an __init__.py would vanish from the suite exactly the way
tests/gate, tests/regression, and tests/strike used to: `discover -s tests`
would keep reporting OK, just measuring less. This test makes that failure
loud instead of silent.
"""

from __future__ import annotations

import unittest
from pathlib import Path


TESTS_ROOT = Path(__file__).resolve().parent


class DiscoverySanityTests(unittest.TestCase):
    def test_every_test_bearing_subdirectory_has_an_init_file(self) -> None:
        offenders = []
        for entry in sorted(TESTS_ROOT.iterdir()):
            if not entry.is_dir() or entry.name == "__pycache__":
                continue
            has_test_file = any(entry.glob("test_*.py"))
            has_init = (entry / "__init__.py").is_file()
            if has_test_file and not has_init:
                offenders.append(entry.name)

        self.assertEqual(
            offenders,
            [],
            f"tests/{{{', '.join(offenders)}}} contain test_*.py files but no "
            "__init__.py -- unittest discover() will silently skip them "
            "(no error, no output, just fewer tests collected). Add an "
            "empty __init__.py to each.",
        )


if __name__ == "__main__":
    unittest.main()
