"""Puts this repo's non-package source roots on sys.path so bare imports
like `from app...`, `from detectors...`, `from policy...`, and
`from corpus import ...` resolve regardless of the invocation's cwd or
top-level directory.

Import this explicitly in every test module that does one of those bare
imports:

    from tests import _pathfix  # noqa: F401

Do NOT skip this in a new file because a sibling test module already does
it. sys.path mutation is process-wide and module imports are cached, so a
file that omits this import can still pass -- by accident -- purely
because some other module happened to be collected first in the same
unittest discovery run and already performed the mutation. That accidental
pass is invocation-order-dependent: rename a file, add a new one earlier in
sort order, or run this module in isolation (`python -m unittest
tests.gate.test_whatever`) instead of via full-suite discovery, and the
import silently breaks again with no trace back to this file. This is
exactly the shape of bug the rest of this package was built to eliminate --
do not reintroduce a narrower version of it here by treating this import as
optional.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_GATE_ROOT = _REPO_ROOT / "gate"
_REGRESSION_ROOT = _REPO_ROOT / "tests" / "regression"

for _extra_root in (_GATE_ROOT, _REGRESSION_ROOT):
    _extra_root_str = str(_extra_root)
    if _extra_root_str not in sys.path:
        sys.path.insert(0, _extra_root_str)
