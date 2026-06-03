#!/usr/bin/env bash
#
# Bump the EHBP version across every client that declares it in-tree.
#
# Go and Swift are versioned solely by the git tag, so they have no version to
# edit here; creating the matching `v<version>` tag is what releases them.
#
# Usage:
#   scripts/bump-version.sh <new-version>
# Example:
#   scripts/bump-version.sh 0.2.1
#
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $(basename "$0") <new-version>  (e.g. 0.2.1)" >&2
  exit 1
fi

VERSION="$1"

# Reject anything that is not valid SemVer 2.0.0 (https://semver.org) so a
# malformed version is never written. Bash's =~ uses POSIX ERE, which lacks the
# non-capturing groups of the canonical regex, so the grammar is spelled out:
# numeric identifiers forbid leading zeros, and the optional pre-release and
# build-metadata sections may appear together (e.g. 1.2.3-rc.1+build.5).
num='(0|[1-9][0-9]*)'
pre='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
build='[0-9A-Za-z-]+'
semver="^${num}\.${num}\.${num}(-${pre}(\.${pre})*)?(\+${build}(\.${build})*)?\$"
# Match the whole value with =~; a line-oriented matcher like grep accepts a
# multiline value as long as any one line matches, smuggling garbage past
# validation. Reject embedded newlines outright too, since POSIX $ can also
# match just before a trailing newline.
if [[ "$VERSION" == *$'\n'* ]] || ! [[ "$VERSION" =~ $semver ]]; then
  echo "error: '$VERSION' is not a valid semantic version (expected e.g. 0.2.1)" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# In-place sed that works on both BSD/macOS and GNU/Linux (their `-i` flags differ).
replace_in_file() {
  # usage: replace_in_file <sed-expression> <file>
  local expr="$1" file="$2" tmp
  tmp="$(mktemp)"
  sed -E "$expr" "$file" >"$tmp"
  mv "$tmp" "$file"
}

echo "Bumping EHBP to v$VERSION"

# --- JavaScript: npm owns both package.json and package-lock.json ---
if command -v npm >/dev/null 2>&1; then
  (cd "$ROOT/js" && npm version "$VERSION" \
    --no-git-tag-version --allow-same-version --ignore-scripts >/dev/null)
else
  echo "  warning: npm not found; updating package.json only -- run" \
    "'npm install --package-lock-only' in js/ to sync the lockfile" >&2
  replace_in_file "s/(\"version\": \").*(\",)/\1$VERSION\2/" "$ROOT/js/package.json"
fi
echo "  updated js/package.json (+ package-lock.json)"

# --- Python: pyproject.toml [project].version and the package __version__ ---
replace_in_file "s/^version *=.*/version = \"$VERSION\"/" "$ROOT/python/pyproject.toml"
replace_in_file "s/^__version__ *=.*/__version__ = \"$VERSION\"/" "$ROOT/python/src/ehbp/__init__.py"
echo "  updated python/pyproject.toml + src/ehbp/__init__.py"

# --- Rust: Cargo.toml [package].version and the local crate entry in Cargo.lock ---
replace_in_file "s/^version *=.*/version = \"$VERSION\"/" "$ROOT/rust/Cargo.toml"
tmp="$(mktemp)"
awk -v ver="$VERSION" '
  /^name = "tinfoil-ehbp"$/ {
    print
    if ((getline line) > 0) {
      if (line ~ /^version = /) line = "version = \"" ver "\""
      print line
    }
    next
  }
  { print }
' "$ROOT/rust/Cargo.lock" >"$tmp"
mv "$tmp" "$ROOT/rust/Cargo.lock"
echo "  updated rust/Cargo.toml + Cargo.lock"

echo
echo "Versions now set:"
grep -E '^[[:space:]]*"version"|^version|^__version__' \
  "$ROOT/js/package.json" \
  "$ROOT/python/pyproject.toml" \
  "$ROOT/python/src/ehbp/__init__.py" \
  "$ROOT/rust/Cargo.toml" || true

echo
echo "Go and Swift release via the git tag (v$VERSION) -- no files to change."
echo "Next: review 'git diff', commit, then 'git tag v$VERSION'."
