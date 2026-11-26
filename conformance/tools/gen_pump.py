#!/usr/bin/env python3
"""Forwards to `gen.py pump` (the generator is conformance/tools/gen/pump.py);
kept so the file headers naming this script stay true. Arguments: [--check] [lang ...]."""
import sys

from gen import pump

if __name__ == "__main__":
    sys.exit(pump.main(sys.argv[1:]))
