#!/usr/bin/env python3
"""Drives each language's conformance adapter against the oracle with timed
workloads and reports wall time and the adapter's own peak RSS. Run it on two
checkouts to compare them: `bench.py --tree /path --label before`.

The adapters are not built here; build them first (see harness/run.py
build_adapters). Python uses the shared conformance venv with PYTHONPATH
pointing at the tree's python/src."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

MIB = 1 << 20


def adapters(tree: Path, venv: Path, java_home: str | None):
    env = dict(os.environ)
    if java_home:
        env["JAVA_HOME"] = java_home
        env["PATH"] = f"{java_home}/bin:" + env["PATH"]
    out = {}
    go = tree / "conformance/.bin/go-adapter"
    if go.exists():
        out["go"] = ([str(go)], env)
    py = tree / "conformance/adapters/python/adapter.py"
    if py.exists() and (venv / "bin/python").exists():
        penv = dict(env, PYTHONPATH=str(tree / "python/src"))
        out["python"] = ([str(venv / "bin/python"), str(py)], penv)
    js = tree / "conformance/adapters/js/adapter.mjs"
    if js.exists() and (tree / "js/dist/esm/index.js").exists():
        out["js"] = (["node", str(js)], env)
    rs = tree / "conformance/adapters/rust/target/release/ehbp-adapter"
    if rs.exists():
        out["rust"] = ([str(rs)], env)
    kt = tree / "conformance/adapters/kotlin/build/install/ehbp-adapter/bin/ehbp-adapter"
    if kt.exists() and (java_home or env.get("JAVA_HOME")):
        out["kotlin"] = ([str(kt)], env)
    return out


def start_oracle(tree: Path):
    binary = Path("/tmp") / f"ehbp-oracle-{tree.name}"
    subprocess.run(["go", "build", "-o", str(binary), "./conformance/server"], cwd=tree, check=True)
    proc = subprocess.Popen([str(binary), "-l", "127.0.0.1:0"], cwd=tree, stdout=subprocess.PIPE, text=True)
    line = proc.stdout.readline()
    main = [p for p in line.split() if p.startswith("main=")][0].split("=", 1)[1]
    return proc, f"http://{main}"


def run(argv, env, fixture: dict, oracle: str):
    env = dict(env, ORACLE_URL=oracle)
    start = time.monotonic()
    done = subprocess.run(argv, input=json.dumps(fixture), capture_output=True, text=True, env=env)
    elapsed = time.monotonic() - start
    try:
        result = json.loads(done.stdout.strip().splitlines()[-1])
    except Exception:
        return elapsed, None, (done.stderr or done.stdout)[-300:]
    return elapsed, result, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--venv", default=str(Path(__file__).resolve().parents[1] / ".venv"))
    ap.add_argument("--java-home", default=os.environ.get("JAVA_HOME"))
    ap.add_argument("--sizes", default="1,16,128", help="large_body sizes in MiB")
    ap.add_argument("--echo-iterations", type=int, default=20)
    ap.add_argument("--out", default=None)
    ap.add_argument("--oracle-tree", default=None, help="build the oracle from another checkout")
    args = ap.parse_args()
    tree = Path(args.tree).resolve()
    adapters_ = adapters(tree, Path(args.venv), args.java_home)
    proc, oracle = start_oracle(Path(args.oracle_tree).resolve() if args.oracle_tree else tree)
    try:
        rows = []
        echo_body = ("61" * 65536)
        for lang, (argv, env) in adapters_.items():
            # Warm-up and latency: 64 KiB echo round trips.
            lat = []
            for _ in range(args.echo_iterations):
                fx = {"id": "bench-echo", "operation": "request", "server_scenario": "echo",
                      "request": {"method": "POST", "path": "/s/echo", "body_hex": echo_body, "headers": {}}, "inputs": {}}
                elapsed, result, err = run(argv, env, fx, oracle)
                if err or not result or result.get("outcome") != "ok":
                    rows.append({"lang": lang, "workload": "echo-64KiB", "error": err or (result or {}).get("native_error")})
                    break
                lat.append(elapsed)
            if lat:
                lat.sort()
                rows.append({"lang": lang, "workload": "echo-64KiB", "iterations": len(lat),
                             "median_s": round(lat[len(lat) // 2], 4), "min_s": round(lat[0], 4)})
            for mib in [int(s) for s in args.sizes.split(",")]:
                fx = {"id": f"bench-{mib}", "operation": "large_body", "server_scenario": "digest",
                      "inputs": {"size_bytes": mib * MIB, "block_seed": 42},
                      "request": {"method": "POST", "path": "/s/digest", "headers": {}}}
                elapsed, result, err = run(argv, env, fx, oracle)
                row = {"lang": lang, "workload": f"upload-{mib}MiB", "wall_s": round(elapsed, 3)}
                if err or not result or result.get("outcome") != "ok":
                    row["error"] = err or (result or {}).get("native_error")
                else:
                    row["mib_per_s"] = round(mib / elapsed, 1)
                    rss = result.get("peak_rss_bytes")
                    row["peak_rss_mib"] = round(rss / MIB, 1) if rss else None
                rows.append(row)
                print(json.dumps({"label": args.label, **row}), flush=True)
    finally:
        proc.terminate()
    if args.out:
        Path(args.out).write_text(json.dumps({"label": args.label, "tree": str(tree), "rows": rows}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
