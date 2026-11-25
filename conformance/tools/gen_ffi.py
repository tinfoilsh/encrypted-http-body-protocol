#!/usr/bin/env python3
"""Forwards to `gen.py ffi` (the generator is conformance/tools/gen/ffi.py);
kept so the file headers naming this script stay true. Arguments: [--check] [lang ...]."""
import sys

from gen import ffi

if __name__ == "__main__":
    sys.exit(ffi.main(sys.argv[1:]))
