"""Generated regions inside hand-written files: `<c> <name>:begin (<note>)`
.. `<c> <name>:end`, where `<c>` is the language's comment lead. The begin
marker's indentation stays outside the region; the end marker's indentation
is part of it (the region is replaced as a whole). Drift is reported as a
unified diff of the file's region against the rendering."""
from __future__ import annotations

import difflib


def begin(comment: str, name: str, note: str) -> str:
    return f"{comment} {name}:begin ({note})"


def wrap(comment: str, name: str, note: str, body: str, end_indent: str = "", end_gap: str = "") -> str:
    """The region text: the markers around `body`."""
    return f"{begin(comment, name, note)}\n{body}\n{end_gap}{end_indent}{comment} {name}:end"


def split(text: str, comment: str, name: str) -> tuple[str, str, str]:
    """(before, region, after) of the first `name` region of `text`."""
    lines = text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if line.lstrip().startswith(f"{comment} {name}:begin (")), None)
    if start is None:
        raise ValueError(f"no {name}:begin marker")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip() == f"{comment} {name}:end"), None)
    if end is None:
        raise ValueError(f"no {name}:end marker after {name}:begin")
    head = lines[start]
    indent = head[: len(head) - len(head.lstrip())]
    before = "".join(lines[:start]) + indent
    region = head[len(indent):] + "".join(lines[start + 1 : end]) + lines[end].rstrip("\n")
    after = "\n" + "".join(lines[end + 1 :]) if lines[end].endswith("\n") else ""
    return before, region, after


def replace(text: str, comment: str, name: str, rendered: str) -> str:
    before, _, after = split(text, comment, name)
    return before + rendered + after


def lines(before: str, region: str) -> tuple[int, int]:
    """(first, last) 1-based line numbers of a region returned by `split`."""
    first = before.count("\n") + 1
    return first, first + region.count("\n")


def diff(current: str, want: str, label: str) -> str:
    """A unified diff, empty when identical."""
    if current == want:
        return ""
    return "".join(difflib.unified_diff(current.splitlines(True), want.splitlines(True), label, "generated", n=1))
