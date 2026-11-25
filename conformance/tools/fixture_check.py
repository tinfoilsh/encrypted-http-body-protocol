#!/usr/bin/env python3
"""Runs dafny/fixtures.dfy through the Go and Python backends and checks that
both print the same bytes and that the committed test-vectors/conformance
files match: the cross-runtime check of the fixture program. Exit 1 on a
difference. Regenerate with dafny/gen-fixtures.sh. Not part of
check.py: the Go backend takes about ten seconds to build and run."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DFY = ROOT / "dafny/fixtures.dfy"


def emit(target: str) -> dict[str, str]:
    """family -> JSON text, as Main prints it on `target`."""
    with tempfile.TemporaryDirectory() as tmp:
        if target == "go":
            # `dafny run --target go` compiles in GOPATH mode, which the module at
            # the repository root defeats; translate and run the program ourselves.
            gopath = subprocess.run(["go", "env", "GOPATH"], check=True, capture_output=True, text=True).stdout.strip()
            env = {**os.environ, "PATH": os.environ["PATH"] + os.pathsep + f"{gopath}/bin"}
            subprocess.run(["dafny", "translate", "go", "--no-verify", "--include-runtime", "--output", f"{tmp}/fixtures", str(DFY)],
                           check=True, capture_output=True, env=env)
            env.update(GO111MODULE="off", GOPATH=f"{tmp}/fixtures-go")
            text = subprocess.run(["go", "run", f"{tmp}/fixtures-go/src/fixtures.go"],
                                  check=True, capture_output=True, text=True, env=env).stdout
        else:
            subprocess.run(["dafny", "translate", "py", "--no-verify", "--include-runtime", "--output", f"{tmp}/fixtures", str(DFY)],
                           check=True, capture_output=True)
            text = subprocess.run([sys.executable, f"{tmp}/fixtures-py"], check=True, capture_output=True, text=True).stdout
    families: dict[str, str] = {}
    name = None
    for line in text.splitlines(keepends=True):
        if line.startswith("=== "):
            name = line[4:].strip()
            families[name] = ""
        elif name:
            families[name] += line
    return families


def main() -> int:
    outs = {t: emit(t) for t in ("go", "py")}
    ok = True
    if outs["go"] != outs["py"]:
        print("fixture_check: FAIL the Go and Python backends print different fixtures")
        ok = False
    for name, text in outs["py"].items():
        path = ROOT / "test-vectors/conformance" / f"{name}.json"
        if not path.exists() or path.read_text() != text:
            print(f"fixture_check: FAIL {path.relative_to(ROOT)} drifts from dafny/fixtures.dfy; run dafny/gen-fixtures.sh")
            ok = False
    print(f"fixture_check: {'ok' if ok else 'FAIL'} {len(outs['py'])} families, go == py == committed" if ok else "")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
