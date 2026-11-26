#!/usr/bin/env python3
"""Forwards to `gen.py adapter` (the generator is conformance/tools/gen/adapter.py);
kept so the file headers naming this script stay true. Arguments: [--check] [lang ...]."""
import sys

from gen import adapter

if __name__ == "__main__":
    sys.exit(adapter.main(sys.argv[1:]))
