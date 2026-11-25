#!/bin/sh
# Regenerates the Go output of the pure module dafny/ehbp.dfy (gen/go), which the
# event-driven bundle from generate-events.sh imports, and the Go runtime it
# needs (gen/go/dafny, gen/go/System_), kept in-tree so patch-runtime.py can
# patch it and importers of this module get the patched copy. Every other
# language takes the event bundle from gen-events/. Commit the result.
# Pass --no-verify to skip verification (CI verifies; local iteration can skip).
set -eu
cd "$(dirname "$0")"
# dafny formats Go output with goimports, which lives in GOPATH/bin.
export PATH="$PATH:$(go env GOPATH)/bin"
MOD=github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

[ "${1:-}" = "--no-verify" ] || dafny verify ehbp.dfy

dafny translate go --no-verify --include-runtime --go-module-name "$MOD" --output "$TMP/ehbp" ehbp.dfy
mkdir -p gen/go/EHBP
cp "$TMP/ehbp-go/EHBP/EHBP.go" gen/go/EHBP/EHBP.go
rm -rf gen/go/dafny gen/go/System_
cp -R "$TMP/ehbp-go/dafny" "$TMP/ehbp-go/System_" gen/go/
sed -i.bak "s#_dafny \"dafny\"#_dafny \"$MOD/dafny\"#" gen/go/System_/System_.go && rm gen/go/System_/System_.go.bak
python3 patch-runtime.py

