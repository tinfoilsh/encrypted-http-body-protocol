#!/usr/bin/env python3
"""EHBP conformance orchestrator.

Runs one or more language adapters over every fixture, compares each result to
the fixture's spec-correct expectation, and (with >1 adapter) compares adapters
pairwise. Prints a matrix and exits non-zero on any difformance.

Usage:
    python3 conformance/harness/run.py [--adapter go] [--adapter python] ...

Adapters are configured in ADAPTERS. Each adapter is a command reading one
fixture JSON on stdin and printing one normalized result on stdout. e2e fixtures
require the oracle server; the harness starts it and passes ORACLE_URL.
"""

from __future__ import annotations

import argparse
import copy
import html
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

OBS_FIELDS = ["transfer_encoding", "content_length", "body_bytes",
              "frame_count", "proto", "user_agent"]

# Batch adapters launch once and process all fixtures as JSONL (browsers are
# expensive to start per fixture). They do not produce observation rows.
BATCH_ADAPTERS = {"js-chromium", "js-firefox"}

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "test-vectors" / "conformance"
ORACLE_ADDR = "127.0.0.1:8087"
ORACLE_URL = f"http://{ORACLE_ADDR}"
_HOST, _PORT = ORACLE_ADDR.split(":")
# Auxiliary key-config endpoints for discovery-robustness fixtures (see the oracle).
ORACLE_BAD_CT_URL = f"http://{_HOST}:{int(_PORT) + 1}"
ORACLE_NON200_URL = f"http://{_HOST}:{int(_PORT) + 2}"

ADAPTER_TIMEOUT_SECONDS = 30
BATCH_TIMEOUT_SECONDS = 180

CANONICAL_ERROR_CODES = {
    "INVALID_KEY_CONFIG", "UNSUPPORTED_SUITE",
    "INVALID_ENCAPSULATED_KEY", "HPKE_SETUP_FAILED",
    "MISSING_RESPONSE_NONCE", "INVALID_RESPONSE_NONCE",
    "DUPLICATE_RESPONSE_NONCE", "KEY_CONFIG_MISMATCH",
    "FRAMING_TRUNCATED", "CHUNK_TOO_LARGE", "AEAD_DECRYPT_FAILED",
    "SEQUENCE_OVERFLOW", "INVALID_TOKEN", "INVALID_INPUT",
}

RESULT_FIELDS = {
    "fixture_id", "outcome", "error_code", "status", "response_headers",
    "body_hex", "passthrough", "plaintext_emitted_before_error",
    "bytes_emitted_before_error", "skip_reason", "native_error", "runner",
}

FIXTURE_CATEGORIES = {"crypto", "config", "e2e", "shape", "client-api", "server"}
FIXTURE_OPERATIONS = {
    "derive_keys", "decrypt_response", "decrypt_response_streaming",
    "compute_nonce", "token_roundtrip", "parse_config",
    "marshal_config", "request", "discover", "reject_reserved_header",
    "reject_cross_origin", "reject_url_credentials", "decrypt_request",
    "middleware_request",
}

FIXTURE_FIELDS = {
    "id", "description", "category", "operation", "inputs", "chunking",
    "server_scenario", "request", "browser", "runners", "allowed_skips",
    "expect",
}
EXPECT_FIELDS = {
    "outcome", "error_code", "status", "body_hex", "passthrough",
    "plaintext_emitted_before_error", "bytes_emitted_before_error",
    "response_headers_absent", "response_headers_present",
}


def adapter_env():
    return {**os.environ, "ORACLE_URL": ORACLE_URL,
            "ORACLE_BAD_CT_URL": ORACLE_BAD_CT_URL,
            "ORACLE_NON200_URL": ORACLE_NON200_URL}

# Fields compared for cross-language equality and (as a subset) against expect.
ASSERTED = [
    "outcome", "error_code", "status", "body_hex", "passthrough",
    "plaintext_emitted_before_error", "bytes_emitted_before_error",
]


def build_adapters(names):
    """Return {name: argv}. Building happens here so a compile error fails loudly."""
    adapters = {}
    if "go" in names:
        out = ROOT / "conformance" / ".bin" / "go-adapter"
        out.parent.mkdir(exist_ok=True)
        subprocess.run(["go", "build", "-o", str(out), "./conformance/adapters/go"],
                       cwd=ROOT, check=True)
        adapters["go"] = [str(out)]
    if "python" in names:
        py = ROOT / "conformance" / ".venv" / "bin" / "python"
        if py.exists():
            adapters["python"] = [str(py), str(ROOT / "conformance/adapters/python/adapter.py")]
    if "js" in names:
        if (ROOT / "js" / "dist" / "esm" / "index.js").exists():
            adapters["js"] = ["node", str(ROOT / "conformance/adapters/js/adapter.mjs")]
    if "rust" in names:
        import shutil
        cargo = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
        if Path(cargo).exists():
            subprocess.run([cargo, "build", "--release"],
                           cwd=ROOT / "conformance/adapters/rust", check=True)
            adapters["rust"] = [str(ROOT / "conformance/adapters/rust/target/release/ehbp-adapter")]
    if "swift" in names:
        swift_dir = ROOT / "conformance/adapters/swift"
        bin_path = swift_dir / ".build/release/ehbp-adapter"
        try:
            subprocess.run(["swift", "build", "-c", "release"], cwd=swift_dir, check=True,
                           stdout=subprocess.DEVNULL)
            if bin_path.exists():
                adapters["swift"] = [str(bin_path)]
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
    for eng in ("chromium", "firefox"):
        nm = f"js-{eng}"
        if nm in names:
            runner = ROOT / "conformance/adapters/js-browser/runner.mjs"
            bundle = ROOT / "js/dist/browser.js"
            playwright = ROOT / "conformance/adapters/js-browser/node_modules/playwright"
            if runner.exists() and bundle.exists() and playwright.exists():
                adapters[nm] = ["node", str(runner), f"--browser={eng}"]
    return adapters


def adapter_failure(fixture_id, message):
    return {
        "fixture_id": fixture_id, "outcome": "error",
        "error_code": "ADAPTER_CRASH", "native_error": message[:500],
        "status": None, "body_hex": None, "passthrough": False,
        "plaintext_emitted_before_error": False,
        "bytes_emitted_before_error": 0,
    }


def validate_result(result, fixture_id):
    """Return None for a schema-shaped adapter result, otherwise a reason."""
    if not isinstance(result, dict):
        return "result is not a JSON object"
    unknown = set(result) - RESULT_FIELDS
    if unknown:
        return f"result has unknown fields: {', '.join(sorted(unknown))}"
    if result.get("fixture_id") != fixture_id:
        return f"fixture_id {result.get('fixture_id')!r} != {fixture_id!r}"
    outcome = result.get("outcome")
    if outcome not in {"ok", "error", "skipped"}:
        return f"invalid outcome {outcome!r}"
    code = result.get("error_code")
    if outcome == "error" and code not in CANONICAL_ERROR_CODES:
        return f"error result has invalid error_code {code!r}"
    if outcome != "error" and code is not None:
        return f"{outcome} result must not carry error_code {code!r}"
    if outcome == "skipped" and (not isinstance(result.get("skip_reason"), str)
                                 or not result["skip_reason"]):
        return "skipped result lacks skip_reason"
    body_hex = result.get("body_hex")
    if body_hex is not None and (not isinstance(body_hex, str)
                                 or re.fullmatch(r"[0-9a-f]*", body_hex) is None):
        return "body_hex is not lowercase hex"
    status = result.get("status")
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        return f"invalid HTTP status {status!r}"
    for field in ("passthrough", "plaintext_emitted_before_error"):
        if field in result and type(result[field]) is not bool:
            return f"{field} is not boolean"
    emitted = result.get("bytes_emitted_before_error")
    if emitted is not None and (type(emitted) is not int or emitted < 0):
        return "bytes_emitted_before_error is not a non-negative integer"
    headers = result.get("response_headers")
    if headers is not None and (not isinstance(headers, dict)
                                or any(not isinstance(k, str) or not isinstance(v, str)
                                       for k, v in headers.items())):
        return "response_headers is not a string map"
    return None


def run_batch(argv, fixtures, timeout=BATCH_TIMEOUT_SECONDS):
    """Run a batch adapter once over all fixtures; return {fixture_id: result}."""
    payload = "\n".join(json.dumps(fx) for fx in fixtures)
    fixture_ids = [fx["id"] for fx in fixtures]
    try:
        proc = subprocess.run(argv, input=payload, capture_output=True, text=True,
                              env=adapter_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        return {fid: adapter_failure(fid, f"batch adapter timed out after {timeout}s")
                for fid in fixture_ids}
    if proc.returncode != 0:
        message = f"batch adapter exited {proc.returncode}: {(proc.stderr or '').strip()}"
        return {fid: adapter_failure(fid, message) for fid in fixture_ids}
    results = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                r = json.loads(line)
            except json.JSONDecodeError as err:
                message = f"batch adapter emitted malformed JSON: {err}"
                return {fid: adapter_failure(fid, message) for fid in fixture_ids}
            fid = r.get("fixture_id") if isinstance(r, dict) else None
            if fid not in fixture_ids:
                message = f"batch adapter emitted unknown fixture_id {fid!r}"
                return {expected: adapter_failure(expected, message) for expected in fixture_ids}
            if fid in results:
                message = f"batch adapter emitted duplicate result for {fid}"
                return {expected: adapter_failure(expected, message) for expected in fixture_ids}
            invalid = validate_result(r, fid)
            results[fid] = adapter_failure(fid, invalid) if invalid else r
    for fid in fixture_ids:
        results.setdefault(fid, adapter_failure(fid, "batch adapter emitted no result"))
    return results


def load_fixtures():
    fixtures = []
    ids = set()
    for f in sorted(FIXTURE_DIR.glob("*.json")):
        loaded = json.loads(f.read_text())
        if not isinstance(loaded, list):
            raise ValueError(f"{f}: fixture file must contain a JSON array")
        for index, fixture in enumerate(loaded):
            validate_fixture(fixture, f, index)
            if fixture["id"] in ids:
                raise ValueError(f"duplicate fixture id: {fixture['id']}")
            ids.add(fixture["id"])
            fixtures.append(fixture)
    return fixtures


def validate_fixture(fixture, source="fixture", index=0):
    """Minimal dependency-free validation of the normative fixture schema."""
    where = f"{source}[{index}]"
    if not isinstance(fixture, dict):
        raise ValueError(f"{where}: fixture must be an object")
    unknown = set(fixture) - FIXTURE_FIELDS
    if unknown:
        raise ValueError(f"{where}: unknown fields: {', '.join(sorted(unknown))}")
    for field in ("id", "category", "operation", "expect"):
        if field not in fixture:
            raise ValueError(f"{where}: missing {field}")
    if not isinstance(fixture["id"], str) or not re.fullmatch(r"[a-z0-9-]+", fixture["id"]):
        raise ValueError(f"{where}: invalid fixture id")
    if fixture["category"] not in FIXTURE_CATEGORIES:
        raise ValueError(f"{where}: invalid category {fixture['category']!r}")
    if fixture["operation"] not in FIXTURE_OPERATIONS:
        raise ValueError(f"{where}: invalid operation {fixture['operation']!r}")
    expect = fixture["expect"]
    if not isinstance(expect, dict) or expect.get("outcome") not in {"ok", "error"}:
        raise ValueError(f"{where}: invalid expectation")
    unknown_expect = set(expect) - EXPECT_FIELDS
    if unknown_expect:
        raise ValueError(f"{where}: unknown expectation fields: {', '.join(sorted(unknown_expect))}")
    if expect["outcome"] == "error" and expect.get("error_code") not in CANONICAL_ERROR_CODES:
        raise ValueError(f"{where}: error expectation needs a canonical error_code")
    if expect["outcome"] == "ok" and expect.get("error_code") is not None:
        raise ValueError(f"{where}: ok expectation cannot carry an error code")
    body_hex = expect.get("body_hex")
    if body_hex is not None and (not isinstance(body_hex, str)
                                 or re.fullmatch(r"[0-9a-f]*", body_hex) is None):
        raise ValueError(f"{where}: expected body_hex is not lowercase hex")
    if "inputs" in fixture and not isinstance(fixture["inputs"], dict):
        raise ValueError(f"{where}: inputs must be an object")
    if "chunking" in fixture and (not isinstance(fixture["chunking"], list)
                                  or any(type(v) is not int or v < 1
                                         for v in fixture["chunking"])):
        raise ValueError(f"{where}: chunking must contain positive integers")
    runners = fixture.get("runners")
    if runners is not None and (not isinstance(runners, list) or not runners
                                or any(not isinstance(v, str) for v in runners)
                                or len(set(runners)) != len(runners)):
        raise ValueError(f"{where}: runners must be a non-empty unique string list")
    skips = fixture.get("allowed_skips", {})
    if not isinstance(skips, dict) or any(not isinstance(k, str) or not isinstance(v, str) or not v
                                          for k, v in skips.items()):
        raise ValueError(f"{where}: allowed_skips must map runners to non-empty reasons")
    if fixture["category"] == "e2e" and not all(k in fixture for k in ("server_scenario", "request")):
        raise ValueError(f"{where}: e2e fixture lacks server_scenario/request")


def configure_oracle_addresses():
    """Choose three consecutive loopback ports without killing other processes."""
    global ORACLE_ADDR, ORACLE_URL, ORACLE_BAD_CT_URL, ORACLE_NON200_URL
    for _ in range(100):
        sockets = []
        try:
            first = socket.socket()
            first.bind(("127.0.0.1", 0))
            sockets.append(first)
            port = first.getsockname()[1]
            if port > 65533:
                continue
            for candidate in (port + 1, port + 2):
                probe = socket.socket()
                probe.bind(("127.0.0.1", candidate))
                sockets.append(probe)
            ORACLE_ADDR = f"127.0.0.1:{port}"
            ORACLE_URL = f"http://{ORACLE_ADDR}"
            ORACLE_BAD_CT_URL = f"http://127.0.0.1:{port + 1}"
            ORACLE_NON200_URL = f"http://127.0.0.1:{port + 2}"
            return
        except OSError:
            pass
        finally:
            for bound in sockets:
                bound.close()
    raise RuntimeError("could not reserve three consecutive loopback ports")


def start_oracle():
    out = ROOT / "conformance" / ".bin" / "oracle"
    subprocess.run(["go", "build", "-o", str(out), "./conformance/server"], cwd=ROOT, check=True)
    proc = subprocess.Popen([str(out), "-l", ORACLE_ADDR], cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            urllib.request.urlopen(f"{ORACLE_URL}/health", timeout=0.5).read()
            return proc
        except Exception:
            time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("oracle server did not become ready")


def run_adapter(argv, fixture, timeout=ADAPTER_TIMEOUT_SECONDS):
    try:
        proc = subprocess.run(argv, input=json.dumps(fixture), capture_output=True,
                              text=True, env=adapter_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        return adapter_failure(fixture["id"], f"adapter timed out after {timeout}s")
    if proc.returncode != 0 or not proc.stdout.strip():
        return adapter_failure(
            fixture["id"],
            f"adapter exited {proc.returncode}: {(proc.stderr or 'no output').strip()}")
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as err:
        return adapter_failure(fixture["id"], f"adapter emitted malformed JSON: {err}")
    invalid = validate_result(result, fixture["id"])
    return adapter_failure(fixture["id"], invalid) if invalid else result


def check_expect(result, expect):
    """Return list of failure strings; empty means the result matches expect."""
    fails = []
    outcome = expect["outcome"]
    if result.get("outcome") != outcome:
        fails.append(f"outcome {result.get('outcome')} != {outcome}")
    exp_code = expect.get("error_code") if outcome == "error" else None
    if result.get("error_code") != exp_code:
        fails.append(f"error_code {result.get('error_code')} != {exp_code}")
    for key in ("status", "body_hex", "passthrough"):
        if key in expect and result.get(key) != expect[key]:
            fails.append(f"{key} {result.get(key)!r} != {expect[key]!r}")
    for name in expect.get("response_headers_absent", []):
        if name in (result.get("response_headers") or {}):
            fails.append(f"header {name} present but must be absent")
    for name in expect.get("response_headers_present", []):
        if name not in (result.get("response_headers") or {}):
            fails.append(f"header {name} absent but must be present")
    # Fail-closed default (requirement 4): errors emit no plaintext unless stated.
    if outcome == "error":
        if result.get("plaintext_emitted_before_error", False) != expect.get(
                "plaintext_emitted_before_error", False):
            fails.append("plaintext_emitted_before_error mismatch")
        if result.get("bytes_emitted_before_error", 0) != expect.get(
                "bytes_emitted_before_error", 0):
            fails.append("bytes_emitted_before_error mismatch")
    return fails


def is_allowed_skip(fixture, runner, result):
    reason = fixture.get("allowed_skips", {}).get(runner)
    return bool(reason and result.get("outcome") == "skipped"
                and result.get("skip_reason") == reason)


# On an error outcome, only these fields are meaningful. Pre-auth status, body,
# and headers reflect buffered-vs-streaming implementation details, not behavior,
# so comparing them would flag non-divergences.
ERROR_ASSERTED = ["outcome", "error_code",
                  "plaintext_emitted_before_error", "bytes_emitted_before_error"]


def cross_equal(results):
    """Return True if all adapter results agree on the asserted subset."""
    def key(r):
        fields = ERROR_ASSERTED if r.get("outcome") == "error" else ASSERTED
        return tuple(_hashable(r.get(f)) for f in fields)
    return len({key(r) for r in results.values()}) <= 1


REPORT_MD = ROOT / "conformance" / "report.md"
REPORT_JSON = ROOT / "conformance" / "report.json"
REPORT_HTML = ROOT / "conformance" / "report.html"

_HTML_CSS = """
body{font:14px/1.45 system-ui,sans-serif;margin:24px;color:#222}
h1{font-size:20px;margin:0 0 8px}h2{font-size:16px;margin:24px 0 8px}
.summary{margin:0 0 16px}
.status{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-weight:600;margin-right:8px}
.status.FAIL{background:#c62828}.status.PASS{background:#2e7d32}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f5f5f5;position:sticky;top:0}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
.ok{background:#e8f5e9}.div{background:#ffebee}.na{background:#f5f5f5;color:#999}
td.div{font-weight:600}td.na{text-align:center}td.exp{background:#e3f2fd}
.cross{font-size:11px;color:#b26a00;margin-left:6px}
details{margin:6px 0}summary{cursor:pointer}li{margin:2px 0}
.sw{display:inline-block;width:12px;height:12px;border:1px solid #ccc;vertical-align:middle;margin-right:4px}
.legend{margin-top:16px;color:#555;font-size:12px}
"""


def build_html(diverging, status, total, cells, cross_fails, skipped, runners):
    """Fixture x runner matrix. Divergent cells carry the native error as a
    tooltip and are repeated in full below, so nothing requires hovering."""
    esc = html.escape
    cols = list(runners or [])
    if not cols:
        for fx in diverging:
            for r in fx["rows"]:
                if r["language"] not in cols:
                    cols.append(r["language"])
    out = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>EHBP Conformance Report</title><style>{_HTML_CSS}</style></head><body>",
        "<h1>EHBP Conformance Report</h1>",
        f"<p class='summary'><span class='status {status}'>{status}</span>"
        f"{total} fixtures &middot; {cells} divergent cells &middot; "
        f"{cross_fails} cross-diff fixtures &middot; {skipped} skipped</p>",
    ]
    if not diverging:
        out.append("<p>No divergences. Every runner agrees with the spec expectation.</p>")
    else:
        out.append("<table><thead><tr><th>Fixture</th><th>Category</th><th>Expected</th>")
        out.extend(f"<th>{esc(c)}</th>" for c in cols)
        out.append("</tr></thead><tbody>")
        for fx in diverging:
            e = fx["expect"]
            expected = e.get("error_code") or e.get("outcome")
            by = {r["language"]: r for r in fx["rows"]}
            cross = " <span class='cross' title='implementations disagree'>cross-diff</span>" if fx["cross"] else ""
            out.append(f"<tr><td><code>{esc(fx['id'])}</code>{cross}</td>"
                       f"<td>{esc(fx['category'])}</td>"
                       f"<td class='exp'><code>{esc(str(expected))}</code></td>")
            for c in cols:
                r = by.get(c)
                if r is None:
                    out.append("<td class='na'>&mdash;</td>")
                elif r["divergent"]:
                    out.append(f"<td class='div' title='{esc(r['native'] or '')}'>"
                               f"&#x2717; <code>{esc(str(r['actual']))}</code></td>")
                else:
                    out.append(f"<td class='ok'>&#x2713; <code>{esc(str(r['actual']))}</code></td>")
            out.append("</tr>")
        out.append("</tbody></table>")
        out.append("<h2>Native errors</h2>")
        for fx in diverging:
            out.append(f"<details><summary><code>{esc(fx['id'])}</code></summary><ul>")
            for r in fx["rows"]:
                if not r["divergent"]:
                    continue
                native = r["native"] or "(no error: the library accepted the input)"
                out.append(f"<li><b>{esc(r['language'])}</b> &rarr; "
                           f"<code>{esc(str(r['actual']))}</code>: {esc(native)}</li>")
            out.append("</ul></details>")
    out.append("<p class='legend'><span class='sw ok'></span>conforms &nbsp; "
               "<span class='sw div'></span>divergent &nbsp; "
               "<span class='sw na'></span>skipped / not applicable</p>")
    out.append("</body></html>")
    return "\n".join(out) + "\n"


def write_report(diverging, total, cells, cross_fails, skipped, runners=None):
    """Write a human report (report.md) and a machine report (report.json)."""
    status = "FAIL" if diverging else "PASS"
    lines = [
        "# EHBP Conformance Report", "",
        f"**{status}** — {total} fixtures | divergent cells {cells} | "
        f"cross-diff fixtures {cross_fails} | skipped {skipped}", "",
    ]
    if not diverging:
        lines.append("No divergences. Every runner agrees with the spec expectation.")
    for fx in diverging:
        e = fx["expect"]
        expected = e.get("error_code") if e.get("outcome") == "error" else e.get("outcome")
        lines.append(f"## {fx['id']}  ({fx['category']})")
        if fx["cross"]:
            lines.append("Implementations disagree (cross-diff).")
        lines.append(f"Expected: `{expected}`")
        lines.append("")
        lines.append("| runner | result | note |")
        lines.append("| --- | --- | --- |")
        for r in fx["rows"]:
            mark = "**DIVERGENT**" if r["divergent"] else "ok"
            note = (r["native"] or "") if r["divergent"] else ""
            lines.append(f"| {r['language']} | {mark} `{r['actual']}` | {note} |")
        lines.append("")
    REPORT_MD.write_text("\n".join(lines) + "\n")
    REPORT_JSON.write_text(json.dumps({
        "status": status, "total": total, "divergent_cells": cells,
        "cross_diff_fixtures": cross_fails, "skipped": skipped,
        "divergences": diverging,
    }, indent=2) + "\n")
    REPORT_HTML.write_text(build_html(diverging, status, total, cells, cross_fails, skipped, runners))


def _hashable(v):
    return json.dumps(v, sort_keys=True) if isinstance(v, (dict, list)) else v


def observe(fx, adapters):
    """Comparison-only: run the request per adapter and print the wire shape the
    oracle received. Never fails CI."""
    print(f"[obs ] {fx['id']}")
    for name, argv in adapters.items():
        marker = f"{fx['id']}:{name}"
        fxc = copy.deepcopy(fx)
        fxc["request"].setdefault("headers", {})["X-Conformance-Marker"] = marker
        run_adapter(argv, fxc)
        try:
            raw = urllib.request.urlopen(f"{ORACLE_URL}/observations/{marker}", timeout=2).read()
            o = json.loads(raw)
            summary = "  ".join(f"{f}={o.get(f)}" for f in OBS_FIELDS)
        except Exception as e:
            summary = f"(no observation: {e})"
        print(f"         {name:<12} {summary}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", action="append", dest="adapters", default=None)
    args = ap.parse_args()
    names = args.adapters or ["go"]

    adapters = build_adapters(names)
    missing = [n for n in names if n not in adapters]
    if missing:
        print(f"requested adapters unavailable: {', '.join(missing)}", file=sys.stderr)
        sys.exit(2)

    fixtures = load_fixtures()
    needs_oracle = any(fx["category"] in ("e2e", "shape", "client-api") for fx in fixtures)
    if needs_oracle:
        configure_oracle_addresses()
    oracle = start_oracle() if needs_oracle else None

    batch_names = [n for n in adapters if n in BATCH_ADAPTERS]
    per_fixture = {n: a for n, a in adapters.items() if n not in BATCH_ADAPTERS}
    batch_results = {}
    if batch_names:
        for n in batch_names:
            runnable = [fx for fx in fixtures
                        if fx["category"] in ("crypto", "config", "e2e")
                        and (not fx.get("runners") or n in fx["runners"])
                        and fx.get("browser", {}).get("runnable", True)]
            batch_results[n] = run_batch(adapters[n], runnable)

    total = cells = cross_fails = skipped = 0
    diverging = []
    try:
        for fx in fixtures:
            if fx["category"] == "shape":
                observe(fx, per_fixture)  # batch adapters do not produce observations
                continue
            if fx.get("runners") and not any(name in fx["runners"] for name in adapters):
                print(f"[n/a ] {fx['id']:<38} no selected applicable runner")
                continue
            total += 1
            results = {}
            for name, argv in per_fixture.items():
                if fx.get("runners") and name not in fx["runners"]:
                    continue
                results[name] = run_adapter(argv, fx)
            for name in batch_names:
                if fx.get("runners") and name not in fx["runners"]:
                    continue
                if not fx.get("browser", {}).get("runnable", True):
                    skipped += 1
                    continue
                results[name] = batch_results.get(name, {}).get(
                    fx["id"], adapter_failure(fx["id"], "no batch result"))

            # A skipped result (operation unsupported by that library) is counted
            # and excluded from comparison; never folded into pass or divergence.
            for name in list(results):
                if results[name].get("outcome") == "skipped":
                    if is_allowed_skip(fx, name, results[name]):
                        skipped += 1
                        del results[name]

            # Strict: every divergence from the spec expectation fails and is
            # reported. Only genuine skips (operation unsupported by a library) skip.
            line = []
            div_names = set()
            for name, res in results.items():
                if check_expect(res, fx["expect"]):  # non-empty = failures = divergent
                    div_names.add(name)
                    cells += 1
                    line.append(f"{name}=DIVERGENT({res.get('error_code') or res.get('outcome')})")
                else:
                    line.append(f"{name}=ok")

            cross = len(results) > 1 and not cross_equal(results)
            if cross:
                cross_fails += 1
                line.append("CROSS-DIFF")

            fixture_failed = bool(div_names) or cross
            print(f"[{'FAIL' if fixture_failed else 'pass'}] {fx['id']:<38} {' '.join(line)}")

            if fixture_failed:
                diverging.append({
                    "id": fx["id"], "category": fx["category"], "expect": fx["expect"],
                    "cross": cross,
                    "rows": [{"language": n,
                              "actual": r.get("error_code") or r.get("outcome"),
                              "divergent": n in div_names,
                              "native": r.get("native_error")}
                             for n, r in results.items()],
                })
    finally:
        if oracle:
            oracle.terminate()
            try:
                oracle.wait(timeout=3)
            except subprocess.TimeoutExpired:
                oracle.kill()
                oracle.wait(timeout=3)

    write_report(diverging, total, cells, cross_fails, skipped, list(adapters))
    print(f"\n{total} fixtures | divergent cells {cells} | cross-diff fixtures {cross_fails} | "
          f"skipped {skipped} | report: {REPORT_HTML.relative_to(ROOT)} (+ .md, .json)")
    sys.exit(1 if diverging else 0)


if __name__ == "__main__":
    main()
