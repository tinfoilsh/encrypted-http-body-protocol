#!/bin/sh
# Writes test-vectors/conformance/<family>.json for every family fixtures.dfy
# emits (config, e2e, shape, client-api, server-security) and crypto.json from
# conformance/tools/gen_fixtures.py, which seals frames natively.
# conformance/tools/fixture_check.py diffs the Go and Python backends' output
# and the committed files against this program.
set -eu
cd "$(dirname "$0")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
dafny translate py --no-verify --include-runtime --output "$TMP/fixtures" fixtures.dfy > /dev/null
python3 "$TMP/fixtures-py" > "$TMP/out"
awk '/^=== /{f="../test-vectors/conformance/" $2 ".json"; next} f{print > f}' "$TMP/out"
PYTHONPATH=../python/src ../conformance/.venv/bin/python ../conformance/tools/gen_fixtures.py
