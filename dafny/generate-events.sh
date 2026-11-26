#!/bin/sh
# Regenerates the Go output of dafny/ehbp_server.dfy (modules EHBPEvents and
# EHBPServer; Go is the only server) into gen-events/go. The included EHBP
# module and the runtime are not copied: the generated imports are rewritten
# to dafny/gen/go so both cores share one set of Go types and the patched
# runtime (see generate.sh). Every other language gets the client core alone,
# translated from ehbp_events.dfy. Tests live in ehbp_tests.dfy and are never
# translated.
# Pass --no-verify to skip verification.
set -eu
cd "$(dirname "$0")"
export PATH="$PATH:$(go env GOPATH)/bin"
MOD=github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen-events/go
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# spec_rules.dfy is ghost only: verified with the core, never translated.
[ "${1:-}" = "--no-verify" ] || dafny verify ehbp_server.dfy spec_rules.dfy

dafny translate go --no-verify --go-module-name "$MOD" --output "$TMP/ehbp_server" ehbp_server.dfy
for m in EHBPEvents EHBPServer; do
  mkdir -p "gen-events/go/$m"
  sed -E -e 's#dafny/gen-events/go/(EHBP|dafny|System_)"#dafny/gen/go/\1"#' -e 's#github.com/dafny-lang/DafnyRuntimeGo/v4/(dafny|System_)"#github.com/tinfoilsh/encrypted-http-body-protocol/dafny/gen/go/\1"#' "$TMP/ehbp_server-go/$m/$m.go" > "gen-events/go/$m/$m.go"
done
gofmt -w gen-events/go

# The other targets get the client modules (EHBP and EHBPEvents) in one bundle
# under gen-events/<lang>; an SDK on the event core uses that bundle instead of gen/.
dafny translate js --no-verify --include-runtime --output "$TMP/ehbp_events" ehbp_events.dfy
mkdir -p gen-events/js
{ cat "$TMP/ehbp_events.js"; echo 'module.exports = { EHBP, EHBPEvents, _dafny };'; } > gen-events/js/ehbp.js
cat > gen-events/js/package.json <<'JSON'
{
  "name": "ehbp-dafny-gen",
  "private": true,
  "description": "Dafny-generated EHBP event core for JavaScript; regenerate with ../../generate-events.sh",
  "dependencies": {
    "bignumber.js": "^9.3.0"
  }
}
JSON

dafny translate py --no-verify --include-runtime --output "$TMP/ehbp_events" ehbp_events.dfy
rm -rf gen-events/py && mkdir -p gen-events/py
cp -R "$TMP/ehbp_events-py/." gen-events/py/
rm -f gen-events/py/__main__.py

dafny translate rs --no-verify --enforce-determinism --rust-sync --include-runtime --output "$TMP/ehbp_events" ehbp_events.dfy
rm -rf gen-events/rs && mkdir -p gen-events/rs
cp -R "$TMP/ehbp_events-rust/src" gen-events/rs/
cat > gen-events/rs/Cargo.toml <<'TOML'
[package]
name = "ehbp-events-core"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
path = "src/ehbp_events.rs"

[dependencies]
dafny_runtime = { package = "dafny-runtime", version = "=0.3.1", features = ["small-int", "sync"] }
TOML

dafny translate java --no-verify --output "$TMP/ehbp_events" ehbp_events.dfy
rm -rf gen-events/java && mkdir -p gen-events/java
cp -R "$TMP/ehbp_events-java/." gen-events/java/

# The JS and Python runtimes get the performance patches the SDKs rely on
# (see patch-runtime.py); it fails if the Dafny runtime no longer matches.
python3 patch-runtime.py

