#!/usr/bin/env python3
"""Forwards to `gen.py errors` (the generator is conformance/tools/gen/errors.py);
kept so the file headers naming this script stay true. Arguments: [--check] [lang ...]."""
import sys

from gen import errors

if __name__ == "__main__":
    sys.exit(errors.main(sys.argv[1:]))
