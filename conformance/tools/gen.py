#!/usr/bin/env python3
"""Renders (or, with --check, drift-checks) the generated code of every port:

    gen.py [--check] [target ...]

Targets: errors, core, ffi, all (the default).
A target is one module of the `gen` package; the per-language spellings are
`gen/profiles/<lang>.py` and the code templates `gen/templates/<lang>/`.
Exit 1 on drift with --check, or on a target that cannot render."""
from __future__ import annotations

import importlib
import sys

TARGETS = ["errors", "core", "ffi"]


def main(argv: list[str]) -> int:
    check = "--check" in argv
    names = [a for a in argv if a != "--check"] or ["all"]
    if names == ["all"]:
        names = TARGETS
    unknown = [n for n in names if n not in TARGETS]
    if unknown:
        print(f"gen.py: unknown target {', '.join(unknown)}; one of {', '.join(TARGETS)}, all", file=sys.stderr)
        return 2
    status = 0
    for name in names:
        status |= importlib.import_module(f"gen.{name}").main(["--check"] if check else [])
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
