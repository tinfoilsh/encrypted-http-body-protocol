#!/usr/bin/env python3
"""Forwards to `gen.py residue` (the generator is conformance/tools/gen/residue.py);
kept so the file headers naming this script stay true. Arguments: [--check] [lang ...]."""
import sys

from gen import residue

if __name__ == "__main__":
    sys.exit(residue.main(sys.argv[1:]))
