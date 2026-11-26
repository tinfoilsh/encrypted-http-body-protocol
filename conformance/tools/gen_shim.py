#!/usr/bin/env python3
"""Forwards to `gen.py shim` (the generator is conformance/tools/gen/shim.py);
kept so the file headers naming this script stay true. Arguments: [--check] [lang ...]."""
import sys

from gen import shim

if __name__ == "__main__":
    sys.exit(shim.main(sys.argv[1:]))
