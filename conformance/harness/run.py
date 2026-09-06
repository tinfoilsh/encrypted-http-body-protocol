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
import json
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


def adapter_env():
    import os
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


def run_batch(argv, fixtures):
    """Run a batch adapter once over all fixtures; return {fixture_id: result}."""
    import os
    payload = "\n".join(json.dumps(fx) for fx in fixtures)
    proc = subprocess.run(argv, input=payload, capture_output=True, text=True,
                          env=adapter_env())
    results = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                r = json.loads(line)
                results[r["fixture_id"]] = r
            except json.JSONDecodeError:
                pass
    if not results and proc.returncode != 0:
        print(f"batch adapter crashed: {(proc.stderr or '').strip()[:500]}", file=sys.stderr)
    return results


def load_fixtures():
    fixtures = []
    for f in sorted(FIXTURE_DIR.glob("*.json")):
        fixtures.extend(json.loads(f.read_text()))
    return fixtures


def start_oracle():
    out = ROOT / "conformance" / ".bin" / "oracle"
    subprocess.run(["go", "build", "-o", str(out), "./conformance/server"], cwd=ROOT, check=True)
    # Free the main and both auxiliary ports from any leaked server so a stale
    # binary cannot shadow this run.
    base_port = int(ORACLE_ADDR.split(":")[1])
    freed = False
    for port in (base_port, base_port + 1, base_port + 2):
        try:
            pids = subprocess.run(["lsof", "-ti", f"tcp:{port}"],
                                  capture_output=True, text=True).stdout.split()
            for pid in pids:
                subprocess.run(["kill", "-9", pid], check=False)
                freed = True
        except FileNotFoundError:
            pass
    if freed:
        time.sleep(0.3)
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


def run_adapter(argv, fixture):
    import os
    proc = subprocess.run(argv, input=json.dumps(fixture), capture_output=True,
                          text=True, env=adapter_env())
    if proc.returncode != 0 or not proc.stdout.strip():
        return {"outcome": "error", "error_code": "ADAPTER_CRASH",
                "native_error": (proc.stderr or "no output").strip()[:500]}
    return json.loads(proc.stdout)


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


def write_report(diverging, total, cells, cross_fails, skipped):
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
        print(f"adapters not available yet: {', '.join(missing)}", file=sys.stderr)

    fixtures = load_fixtures()
    needs_oracle = any(fx["category"] in ("e2e", "shape", "client-api") for fx in fixtures)
    oracle = start_oracle() if needs_oracle else None

    batch_names = [n for n in adapters if n in BATCH_ADAPTERS]
    per_fixture = {n: a for n, a in adapters.items() if n not in BATCH_ADAPTERS}
    batch_results = {}
    if batch_names:
        runnable = [fx for fx in fixtures
                    if fx["category"] in ("crypto", "config", "e2e")
                    and fx.get("browser", {}).get("runnable", True)]
        for n in batch_names:
            batch_results[n] = run_batch(adapters[n], runnable)

    total = cells = cross_fails = skipped = 0
    diverging = []
    try:
        for fx in fixtures:
            if fx["category"] == "shape":
                observe(fx, per_fixture)  # batch adapters do not produce observations
                continue
            total += 1
            results = {}
            for name, argv in per_fixture.items():
                results[name] = run_adapter(argv, fx)
            for name in batch_names:
                if not fx.get("browser", {}).get("runnable", True):
                    skipped += 1
                    continue
                results[name] = batch_results.get(name, {}).get(fx["id"], {
                    "outcome": "error", "error_code": "ADAPTER_CRASH",
                    "native_error": "no batch result"})

            # A skipped result (operation unsupported by that library) is counted
            # and excluded from comparison; never folded into pass or divergence.
            for name in list(results):
                if results[name].get("outcome") == "skipped":
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

    write_report(diverging, total, cells, cross_fails, skipped)
    print(f"\n{total} fixtures | divergent cells {cells} | cross-diff fixtures {cross_fails} | "
          f"skipped {skipped} | report: {REPORT_MD.relative_to(ROOT)}")
    sys.exit(1 if diverging else 0)


if __name__ == "__main__":
    main()
