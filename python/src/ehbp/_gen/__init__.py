"""The Dafny output of dafny/ehbp_events.dfy (runtime patches included).

In a checkout the bundle is read from dafny/gen-events/py; a wheel carries a
copy next to this file (pyproject force-include). The generated modules import
each other by top-level name, so their directory joins sys.path."""

import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_bundle = _here if os.path.exists(os.path.join(_here, "EHBPEvents.py")) else os.path.normpath(
    os.path.join(_here, "..", "..", "..", "..", "dafny", "gen-events", "py")
)
sys.path.insert(0, _bundle)

import _dafny  # noqa: E402
import EHBP  # noqa: E402
import EHBPEvents  # noqa: E402

__all__ = ["EHBP", "EHBPEvents", "_dafny"]
