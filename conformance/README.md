# EHBP Conformance Suite

One fixture set runs on every client (Go, JavaScript, Python, Rust, Swift). Each
run emits a normalized result. The harness asserts all languages agree with each
other and with the fixture. Any disagreement fails CI.

Built in steps:

- [x] Step 1 — Contract: error enum, result schema, fixture schema, requirements
- [x] Step 2 — Fixtures: crypto + config (and multi-frame, streaming, e2e, shape)
- [x] Step 3 — Oracle server (Go)
- [x] Step 4 — Go adapter + orchestrator
- [x] Step 5 — Native adapters: Python, Rust, JS-node, Swift
- [x] Step 6 — Browser adapter + Playwright (Chromium + Firefox)
- [x] Step 7 — CI: strict, fails on any divergence, uploads the report
- [ ] Step 8 — Fix each reported divergence in its client (or amend the spec)

## Running

Regenerate fixtures (needs the ehbp Python package for multi-frame bodies):

```
conformance/.venv/bin/python conformance/tools/gen_fixtures.py
```

Run the matrix (each `--adapter` is optional; omit to reduce toolchains):

```
python3 conformance/harness/run.py \
  --adapter go --adapter python --adapter js --adapter rust --adapter swift \
  --adapter js-chromium --adapter js-firefox
```

The harness builds each adapter, starts the oracle for e2e/shape fixtures, and
exits non-zero if any runner diverges from the spec expectation or the runners
disagree. Every divergence is written to `report.md` and `report.json`. A genuine
`skipped` is exempt only when the fixture authorizes that runner and exact
reason. CI runs
the full matrix on macOS and uploads the report (see
`.github/workflows/conformance.yml`).

## Scope

The suite splits the protocol into three surfaces.

- **Crypto.** Key derivation, response decryption, config parse/marshal, token
  JSON. Deterministic. Run in-process against golden vectors. No HTTP.
- **Transport.** Headers, pass-through, 422 recovery, streaming, truncation,
  replay/reordering, malformed nonces, undersized/oversized chunks. Run
  end-to-end against the oracle server.
- **Server boundary.** Duplicate encapsulation headers, hostile request frame
  lengths, empty-frame bursts, and trailing-frame authentication. Run through
  the Go server's public API in an isolated adapter process.

## Layout

```
test-vectors/conformance/*.json     fixtures (source of truth)
conformance/spec/errors.md          canonical error enum
conformance/spec/error-mapping.md   native error -> code, per language
conformance/schema/*.schema.json    result and fixture formats
conformance/server/                 Go oracle server
conformance/adapters/{go,js,py,rs,swift}/   CLI runners (public API only)
conformance/adapters/js-browser/    Playwright page
conformance/harness/                orchestrator: run, collect, diff, report
```

Native adapters are CLIs: read a fixture on stdin, call the public API, print one
JSON result. The browser adapter is the same logic in a Playwright page. The
protocol always runs over HTTP; CLI versus page is only how the harness invokes a
runner.

## Requirements

Normative. A change that weakens one MUST be rejected.

1. Equality is asserted over `outcome`, `status`, the normalized header subset,
   `body_hex`, `passthrough`, `plaintext_emitted_before_error`,
   `bytes_emitted_before_error`, and `error_code`. `native_error` MUST NOT be
   asserted. Two clients can share a code while one leaked plaintext first.
2. Crypto correctness MUST be pinned to golden bytes in-process, independent of
   the server. e2e responses are bound to each request's random `enc` and so
   cannot be byte-pinned; instead every adversarial route MUST be a deterministic
   transform of a correctly derived response (drop a header, flip a tag byte,
   truncate a frame). A tolerant peer MUST NOT be a path's only evidence.
3. Every request-decryption path MUST also be checked in-process against vectors.
   A Go-client / Go-server round-trip MUST NOT be a path's only evidence; both
   ends share the reference crypto.
4. On an error fixture, `plaintext_emitted_before_error` MUST be `false` and
   `bytes_emitted_before_error` MUST be `0`, unless the fixture states otherwise.
5. An unobservable fixture MUST be reported `skipped` with a machine-readable
   reason. A skip MUST NOT count as a pass.
6. Adapters MUST call only the public API.
7. The oracle server MUST write exact byte sequences. Fixtures MUST NOT depend on
   timing. A flaky fixture MUST be fixed, never muted.
8. Every divergence from the spec expectation fails CI and is listed in the
   report (`report.md` / `report.json`). Known divergences are not suppressed or
   allow-listed; only a genuine `skipped` (operation unsupported by a library)
   is exempt.
9. Every requested adapter MUST be present. Adapter timeout, crash, malformed
   JSON, duplicate/missing result, wrong fixture id, and invalid result schema
   MUST fail closed as `ADAPTER_CRASH`; the harness may not silently reduce the
   matrix.
10. A runner may return `skipped` only when the fixture's `allowed_skips` map
    names that runner and exact reason. Implementation-specific surfaces use
    `runners`; non-applicable runners are not treated as passes or skips.

## Known blind spots

- Request bytes are not byte-comparable; each request uses a fresh random `enc`.
  Request fixtures assert round-trip plaintext, not golden request bytes.
- Browsers coalesce duplicate headers. The duplicate-nonce fixture is `skipped` in
  browser mode and covered by native adapters.
- Only Go has a server. The suite tests five clients against one reference server.
- Because framing has no authenticated end marker, truncation exactly on a
  valid frame boundary is indistinguishable from a complete shorter message.
  This protocol-level limitation is documented in `SECURITY-AUDIT.md` rather
  than disguised as a test a conforming implementation could pass.
