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

The JavaScript lockfile is updated through `npm`; if `npm` is not installed the
script bumps `package.json` and tells you to run `npm install --package-lock-only`
to finish syncing the lockfile.

**Go** and **Swift** have no version to edit — they are released purely by the
git tag, so creating the `v<new-version>` tag is what ships them.

### Release steps

1. `./scripts/bump-version.sh <new-version>`
2. Review `git diff` — only version lines should change.
3. Commit: `chore: bump version to v<new-version>`
4. Tag and push: `git tag v<new-version> && git push origin v<new-version>`

Keep all client versions aligned with the git tag.
