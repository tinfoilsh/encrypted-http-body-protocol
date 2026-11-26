#!/usr/bin/env python3
"""The gate over every port's committed code, one section per rule of
conformance/spec/handler.md (sections 4, 5, 7, 8, 9):

    check.py [section ...]        every section by default; exit 1 on any failure

layout      the six residue sections (`crypto:` .. `mapping:` headers) in order
bindings    the canonical bindings of section 4 declared in order (names up to
            case and underscores)
budgets     each residue within its line budget
actions     every action tag handled: by the Performer methods of a port on
            `Perform`, by `perform` and `run` elsewhere
operations  every operation of operations.md named in every adapter's dispatch
api         every member of the section 7 table spelled in the port's shim files
generated   `gen.py --check` of errors, core and ffi (what is still rendered)
docs        every path handler.md and swift-ffi.md name exists
rules       the SPEC table of section 3 names lemmas, fixtures and tests that
            exist, and lists every `Spec_*` lemma"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from gen import core, errors, ffi, operations_md

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "conformance/spec"
LANGS = ["go", "python", "kotlin", "rust", "js", "swift"]

SECTIONS = ["crypto", "http", "session", "pump", "conversions", "mapping"]
CANONICAL = [
    "x25519", "hmacSha256", "aeadSeal", "aeadOpen", "randomBytes",
    "send", "write", "read", "close",
    "beginSession", "publishToken", "clearToken", "token",
    "perform", "run",
    "seq", "bytes", "str", "string", "headerSeq", "headerPairs",
    "code", "error",
]
ACTION_TAGS = ["BeginSession", "PublishToken", "ClearToken", "RandomBytes", "X25519", "HmacSha256",
               "AeadSeal", "AeadOpen", "Send", "Write", "Read", "Close", "EmitPlaintext"]
ON_PERFORM = {"go", "python", "kotlin"}  # the loop calls the core's Perform over a Performer

# declaration regex per language (group 1 = name)
PATTERNS = {
    "go": r"^(?:type|func(?: \([^)]*\))?) (\w+)",
    "python": r"^\s*(?:class|def) (\w+)",
    "kotlin": r"^\s*(?:internal |private |override |open )*(?:class|object|fun) (\w+)",
    "rust": r"^\s*(?:pub(?:\(crate\))? )?(?:struct|enum|trait|fn|impl(?: [\w:]+ for)?) (\w+)",
    "js": r"^\s*(?:export )?(?:(?:class|function|async function|const) (\w+)|(?:async |static |private |readonly )*(\w+)\([^)]*\)(?:: [^{]+)? \{)",
    "swift": r"^\s*(?:public |private |internal |fileprivate |static |final |mutating |override )*(?:func|class|struct|enum|typealias) (\w+)",
}
# residue file, line budget, the canonical names the port has no need for
# (Swift's bytes and strings cross the FFI as they are; a port on Perform has
# no perform of its own).
RESIDUES = {
    "go": ("internal/eventresidue/residue.go", 510, set()),
    "python": ("python/src/ehbp/_residue.py", 370, set()),
    "kotlin": ("kotlin/src/main/kotlin/sh/tinfoil/ehbp/residue/Residue.kt", 390, set()),
    "rust": ("rust/src/residue.rs", 500, set()),
    "js": ("js/src/residue.ts", 410, set()),
    "swift": ("swift/Sources/EHBP/Residue.swift", 400, {"seq", "bytes", "str", "string"}),
}
# the files of the section 7 table's column per port, in column order
SHIMS = {
    "go": ["client/client.go", "client/core.go"],
    "python": ["python/src/ehbp/client.py", "python/src/ehbp/identity.py"],
    "js": ["js/src/client.ts", "js/src/identity.ts"],
    "rust": ["rust/src/client.rs", "rust/src/identity.rs", "rust/src/lib.rs"],
    "kotlin": ["kotlin/src/main/kotlin/sh/tinfoil/ehbp/client/Client.kt", "kotlin/src/main/kotlin/sh/tinfoil/ehbp/Core.kt"],
    "swift": ["swift/Sources/EHBP/Client.swift", "swift/Sources/EHBP/Identity.swift", "swift/Sources/EHBP/Core.swift"],
}
ADAPTERS = {
    "go": "conformance/adapters/go/main.go",
    "python": "conformance/adapters/python/adapter.py",
    "js": "conformance/adapters/js/adapter.mjs",
    "rust": "conformance/adapters/rust/src/main.rs",
    "kotlin": "conformance/adapters/kotlin/src/main/kotlin/Adapter.kt",
    "swift": "conformance/adapters/swift/Sources/ehbp-adapter/main.swift",
}
SERVER_OPS = {"decrypt_request", "middleware_request"}  # Go only: the other SDKs have no server


def norm(name: str) -> str:
    return name.replace("_", "").lower()


def declarations(path: Path, pattern: str) -> list[str]:
    names = []
    for line in path.read_text().splitlines():
        m = re.match(pattern, line)
        if m:
            name = next((g for g in m.groups() if g), None)
            if name:
                names.append(name)
    return names


def bodies(path: Path, pattern: str) -> dict[str, str]:
    """Normalised declaration name -> its text up to the next declaration (first occurrence)."""
    out, current = {}, None
    for line in path.read_text().splitlines():
        m = re.match(pattern, line)
        if m and (name := next((g for g in m.groups() if g), None)) and norm(name) not in out:
            current = norm(name)
            out[current] = ""
        if current:
            out[current] += line + "\n"
    return out


def report(section: str, lang: str, problems: list[str], note: str = "") -> bool:
    print(f"{section:11}{lang:13}{'ok  ' if not problems else 'FAIL'}  {note}{'; '.join(problems)}")
    return not problems


# --- sections ---------------------------------------------------------------

def layout() -> bool:
    ok = True
    for lang in LANGS:
        rel, _, _ = RESIDUES[lang]
        text = (ROOT / rel).read_text()
        found = re.findall(r"^\s*(?://|#)\s*(%s):" % "|".join(SECTIONS), text, re.M)
        order = [s for s in dict.fromkeys(found)]
        ok &= report("layout", lang, [] if order == SECTIONS else [f"sections {order}"], rel)
    return ok


def bindings() -> bool:
    ok = True
    for lang in LANGS:
        rel, _, absent = RESIDUES[lang]
        found = [norm(n) for n in declarations(ROOT / rel, PATTERNS[lang])]
        missing, cursor = [], 0
        for want in CANONICAL:
            if want in absent or (want == "perform" and lang in ON_PERFORM):
                continue
            try:
                cursor = found.index(norm(want), cursor) + 1
            except ValueError:
                missing.append(want)
        ok &= report("bindings", lang, [f"missing or misordered {missing}"] if missing else [])
    return ok


def budgets() -> bool:
    ok = True
    for lang in LANGS:
        rel, budget, _ = RESIDUES[lang]
        lines = sum(1 for _ in (ROOT / rel).open())
        ok &= report("budgets", lang, [] if lines <= budget else ["over budget"], f"{lines}/{budget} lines")
    return ok


def actions() -> bool:
    ok = True
    for lang in LANGS:
        rel, _, _ = RESIDUES[lang]
        path = ROOT / rel
        if lang in ON_PERFORM:
            names = set(declarations(path, PATTERNS[lang]))
            missing = [t for t in ACTION_TAGS if t not in names]
            note = "Performer methods; "
        else:
            b = bodies(path, PATTERNS[lang])
            text = (b.get("perform", "") + b.get("run", "")).lower()
            missing = [t for t in ACTION_TAGS if t.lower() not in text]  # Swift's cases are lowerCamel
            note = "perform and run; "
        ok &= report("actions", lang, [f"unhandled {missing}"] if missing else [], note)
    return ok


def operations_table() -> dict[str, list[str]]:
    return operations_md.parse((SPEC / "operations.md").read_text())


def operations() -> bool:
    ok = True
    ops = operations_table()
    for lang, rel in ADAPTERS.items():
        text = (ROOT / rel).read_text()
        missing = [op for op in ops if op not in text and (lang == "go" or op not in SERVER_OPS)]
        ok &= report("operations", lang, [f"not dispatched {missing}"] if missing else [], f"{len(ops) - len(missing)} operations; ")
    return ok


def api_table() -> dict[str, dict[str, list[str]]]:
    """port -> {member row: spelled names}, from the section 7 table (column order = SHIMS order)."""
    doc = (SPEC / "handler.md").read_text()
    table = doc[doc.index("| Member |"):].split("\n\n")[0].splitlines()
    out = {lang: {} for lang in SHIMS}
    for row in table[2:]:
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", row)[1:-1]]
        for lang, cell in zip(SHIMS, cells[1:]):
            names = []
            for span in re.findall(r"`([^`]+)`", cell):
                span = re.sub(r"\([^()]*\)", "", span).replace(".await", "")
                names += re.findall(r"[A-Za-z_]\w*", span)
            out[lang][cells[0]] = names
    return out


def api() -> bool:
    ok = True
    for lang, rows in api_table().items():
        text = "".join((ROOT / rel).read_text() for rel in SHIMS[lang])
        missing = [f"{row}: {n}" for row, names in rows.items() for n in names if n not in text]
        ok &= report("api", lang, [f"not spelled {missing}"] if missing else [], f"{sum(map(len, rows.values()))} names; ")
    return ok


def generated() -> bool:
    ok = True
    for target in (errors, core, ffi):
        ok &= report("generated", target.__name__.split(".")[-1], [] if target.main(["--check"]) == 0 else ["drift: python3 conformance/tools/gen.py " + target.__name__.split(".")[-1]])
    return ok


DOCS = ["handler.md", "swift-ffi.md"]
BASES = ["", "conformance/tools", "conformance/spec", "dafny"]
EXT = re.compile(r"\.(dfy|py|go|rs|swift|kt|ts|j2|sh|yml|md|json|js|mjs|h|toml)$")
SKIP = {"swift/EHBPCore.xcframework", "js/dist", "conformance/.venv/bin/python"}


def tracked() -> set[str]:
    return set(subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split())


def missing_paths(doc: str, files: set[str]) -> list[str]:
    """The backticked path-like names of a spec document that are not tracked files or directories."""
    basenames = {p.rsplit("/", 1)[-1] for p in files}

    def pathlike(token: str) -> bool:
        if token in SKIP or any(c in token for c in " <>{}*") or "..." in token or token.startswith(("/", ".")):
            return False
        return "/" in token or bool(EXT.search(token))

    def exists(token: str) -> bool:
        for base in BASES:
            path = f"{base}/{token}" if base else token
            if path in files or any(p.startswith(path.rstrip("/") + "/") for p in files):
                return True
        return token.rsplit("/", 1)[-1] in basenames

    tokens = {t for t in re.findall(r"`([^`\n]+)`", (SPEC / doc).read_text()) if pathlike(t)}
    return sorted(t for t in tokens if not exists(t))


def docs() -> bool:
    files = tracked()
    return all([report("docs", doc, [f"names files that do not exist: {m}"] if (m := missing_paths(doc, files)) else []) for doc in DOCS])


def spec_rows() -> list[str]:
    doc = (SPEC / "handler.md").read_text()
    return doc[doc.index("| SPEC | Rule | Proof |"):].split("\n\n")[0].splitlines()[2:]


def rule_problems() -> list[str]:
    lemmas = set(re.findall(r"^\s*lemma\s+(?:\{:[^}]*\}\s*)*(Spec_\w+)", (ROOT / "dafny/spec_rules.dfy").read_text(), re.M))
    fixtures = {f["id"] for path in (ROOT / "test-vectors/conformance").glob("*.json") for f in json.loads(path.read_text())}
    tests = set(re.findall(r"method \{:test\}(?: \{:[^}]*\})* (\w+)", "".join(p.read_text() for p in (ROOT / "dafny").glob("*.dfy"))))
    problems, listed = [], set()
    for row in spec_rows():
        proof = row.split("|")[3].strip()
        if proof.startswith("deployment:"):
            continue
        names = re.findall(r"`([^`]+)`", proof)
        for name in names:
            if name.startswith("Spec_"):
                listed.add(name)
                if name not in lemmas:
                    problems.append(f"no lemma {name}")
            elif "/" in name:
                if not (ROOT / name).exists():
                    problems.append(f"no file {name}")
            elif proof.startswith("test:") and name not in fixtures:
                if name not in tests:
                    problems.append(f"no Dafny test {name}")
            elif name not in fixtures:
                problems.append(f"no fixture {name}")
        if "native:" in proof and not any(n in fixtures for n in names):
            problems.append(f"no fixture in {proof!r}")
    problems += [f"lemma {name} not in the table" for name in sorted(lemmas - listed)]
    return problems


def rules() -> bool:
    return report("rules", "handler.md", rule_problems(), f"{len(spec_rows())} rows; ")


CHECKS = {"layout": layout, "bindings": bindings, "budgets": budgets, "actions": actions, "operations": operations,
          "api": api, "generated": generated, "docs": docs, "rules": rules}


def main(argv: list[str]) -> int:
    names = argv or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        print(f"check.py: unknown section {', '.join(unknown)}; one of {', '.join(CHECKS)}", file=sys.stderr)
        return 2
    results = [CHECKS[n]() for n in names]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
