# AGENTS.md

Notes for AI agents and contributors working in this repository.

## Updating the version

This project publishes clients in several languages, and a few of them declare
their version in-tree. **Always bump the version with the helper script** so
every place stays in lockstep instead of editing files by hand:

```sh
./scripts/bump-version.sh <new-version>    # e.g. ./scripts/bump-version.sh 0.2.1
```

The script updates every in-tree version and keeps the lockfiles in sync:

| Client     | Files updated                                                          |
| ---------- | --------------------------------------------------------------------- |
| JavaScript | `js/package.json`, `js/package-lock.json`                             |
| Python     | `python/pyproject.toml`, `python/src/ehbp/__init__.py` (`__version__`) |
| Rust       | `rust/Cargo.toml`, `rust/Cargo.lock`                                   |
| Kotlin     | `kotlin/build.gradle.kts`, `kotlin/README.md` (install snippet)        |

The JavaScript lockfile is updated through `npm`; if `npm` is not installed the
script bumps `package.json` and tells you to run `npm install --package-lock-only`
to finish syncing the lockfile.

**Go** and **Swift** have no version to edit — they are released purely by the
git tag, so creating the `v<new-version>` tag is what ships them. **Kotlin** is
served by JitPack from the same tag (`jitpack.yml` builds `kotlin/`); the
`Reproducible build` workflow then checks JitPack's jar against a clean build.

### Release steps

1. `./scripts/bump-version.sh <new-version>`
2. Review `git diff` — only version lines should change.
3. Commit: `chore: bump version to v<new-version>`
4. Tag and push: `git tag v<new-version> && git push origin v<new-version>`

Keep all client versions aligned with the git tag.

## Generated code

The rule: what is derived from a machine-readable source is generated;
everything else is committed code with a check. The error files, the `core`
accessors and the Swift/Rust FFI coders are rendered by
`python3 conformance/tools/gen.py [--check] [target ...]` from the Dafny core;
never edit a region between `:begin` and `:end` markers or a file whose
header says "do not edit". Per-language spellings live in
`conformance/tools/gen/profiles/<lang>.py`, the code in
`conformance/tools/gen/templates/<lang>/` (Jinja; `pip install jinja2`).
The residues, shims and conformance adapters are written by hand;
`python3 conformance/tools/check.py` is the gate (layout, bindings, budgets,
actions, operations, api, generated drift, docs, spec rules) and
`conformance/.venv/bin/python -m pytest conformance/tools/tests -q` the test
suite; `conformance/spec/handler.md` sections 4, 5 and 8 to 12 describe the
layout and how to add a language.
