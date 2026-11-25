#!/usr/bin/env python3
"""Forwards to `gen.py core` (the generator is conformance/tools/gen/core.py);
kept so the file headers naming this script stay true. Arguments: [--check] [lang ...]."""
import sys

from gen import core

if __name__ == "__main__":
    sys.exit(core.main(sys.argv[1:]))
