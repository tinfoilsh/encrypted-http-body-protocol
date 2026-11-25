"""A parser for the operations table of conformance/spec/operations.md: the
markdown table whose first two columns are the operation and its inputs. An
input is a backticked name; `same as X` inherits X's inputs (X must come
first). The result keeps the table's order."""
from __future__ import annotations

import re


class ParseError(ValueError):
    pass


def cells(row: str) -> list[str]:
    """The cells of one `| a | b |` row; an escaped `\\|` stays in its cell."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", row)[1:-1]]


def parse(text: str) -> dict[str, list[str]]:
    """operation -> input names."""
    rows = [cells(line) for line in text.splitlines() if line.startswith("|")]
    if not rows or [c.lower() for c in rows[0][:2]] != ["operation", "inputs"]:
        raise ParseError("no table with `operation` and `inputs` as its first columns")
    out: dict[str, list[str]] = {}
    for row in rows[1:]:
        if len(row) < 2 or set(row[0]) <= set("-: "):
            continue  # the separator row
        m = re.match(r"`(\w+)`", row[0])
        if not m:
            raise ParseError(f"operation cell without a backticked name: {row[0]!r}")
        names = re.findall(r"`([\w.]+)`", row[1])
        inputs = [n for n in names if n not in out]
        for n in names:
            if n in out:
                inputs += out[n]  # `same as X`
        out[m.group(1)] = inputs
    return out
