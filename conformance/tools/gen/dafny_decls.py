"""A parser for the declarations of the Dafny core (dafny/ehbp.dfy,
dafny/ehbp_events.dfy): datatypes with their constructor and field order,
type aliases (a subset type keeps its base), newtypes, generic types, the
signatures of functions and predicates, typed consts (a const is a nullary
function) and the `CodeString` table. Only declaration lines are read;
bodies are skipped. A type is a str (a primitive, newtype, datatype or alias
name) or ("seq", t), ("tuple", [t..]), ("app", name, [t..])."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

Type = object  # str | tuple


@dataclass
class Datatype:
    module: str
    name: str
    params: list[str]
    ctors: list[tuple[str, list[tuple[str, Type]]]]


@dataclass
class Function:
    module: str
    name: str
    params: list[tuple[str, Type]]
    result: Type


@dataclass
class Decls:
    datatypes: dict[str, Datatype] = field(default_factory=dict)
    aliases: dict[str, Type] = field(default_factory=dict)
    newtypes: dict[str, Type] = field(default_factory=dict)
    functions: dict[str, Function] = field(default_factory=dict)
    consts: dict[str, str] = field(default_factory=dict)  # name -> the literal after `:=` on the same line


class ParseError(ValueError):
    pass


# --- types -----------------------------------------------------------------


def _type(s: str) -> tuple[Type, str]:
    s = s.lstrip()
    if s.startswith("()"):
        return ("tuple", []), s[2:]
    if s.startswith("("):
        items, s = _list(s[1:], ")")
        return (items[0] if len(items) == 1 else ("tuple", items)), s
    m = re.match(r"[\w.]+", s)
    if not m:
        raise ParseError(f"bad type at {s!r}")
    name, s, args = m.group().split(".")[-1], s[m.end():].lstrip(), []
    if s.startswith("<"):
        args, s = _list(s[1:], ">")
    if name == "seq":
        if len(args) != 1:
            raise ParseError(f"seq takes one type argument: {args}")
        return ("seq", args[0]), s
    return (("app", name, args) if args else name), s


def _list(s: str, close: str) -> tuple[list[Type], str]:
    """Comma-separated types up to `close`, which is consumed."""
    items = []
    while True:
        t, s = _type(s)
        items.append(t)
        s = s.lstrip()
        if s.startswith(","):
            s = s[1:]
        elif s.startswith(close):
            return items, s[1:]
        else:
            raise ParseError(f"expected ',' or {close!r} at {s!r}")


def parse_type(s: str) -> Type:
    t, rest = _type(s)
    if rest.strip():
        raise ParseError(f"trailing {rest.strip()!r} in type {s!r}")
    return t


def split_top(s: str, sep: str) -> list[str]:
    """Split at `sep` outside parentheses and angle brackets."""
    out, depth, cur = [], 0, ""
    for ch in s:
        depth += ch in "(<"
        depth -= ch in ")>"
        if ch == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    return out + [cur]


def _params(s: str) -> list[tuple[str, Type]]:
    """`name: T, name: T` (possibly empty) as typed fields."""
    out = []
    for item in split_top(s, ","):
        if item.strip():
            if ":" not in item:
                raise ParseError(f"field without a type: {item.strip()!r}")
            name, typ = item.split(":", 1)
            out.append((name.strip(), parse_type(typ)))
    return out


def _balanced(s: str) -> tuple[str, str]:
    """`s` starts with '('; (the text inside the matching parenthesis, the rest)."""
    depth = 0
    for i, ch in enumerate(s):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0:
            return s[1:i], s[i + 1:]
    raise ParseError(f"unbalanced parentheses in {s!r}")


# --- lines -----------------------------------------------------------------


def strip_comment(line: str) -> str:
    """The line without its `//` comment; a `//` inside a string literal stays."""
    quoted = False
    for i, ch in enumerate(line):
        if ch == '"' and (i == 0 or line[i - 1] != "\\"):
            quoted = not quoted
        elif not quoted and line.startswith("//", i):
            return line[:i]
    return line


_DECL = re.compile(r"\s*(?:ghost |opaque |static )*(module|datatype|type|newtype|const|function|predicate|lemma|method)\b(?:\s*\{:[^}]*\})*\s*(.*)$")


def parse(text: str, decls: Decls | None = None, modules: tuple[str, ...] | None = None) -> Decls:
    """The declarations of `text` added to `decls`; with `modules`, only those
    modules' (names are per module, and the ones the generators read must
    not collide)."""
    decls = decls or Decls()
    lines = [strip_comment(line) for line in text.splitlines()]
    module, i = "", 0
    while i < len(lines):
        line, i = lines[i], i + 1
        m = _DECL.match(line)
        if not m:
            continue
        kind, rest = m.groups()
        try:
            if kind == "module":
                module = re.match(r"(\w+)", rest).group(1)
            elif modules is not None and module not in modules:
                continue
            elif kind in ("type", "newtype"):
                _alias(decls, kind, rest)
            elif kind == "datatype":
                i = _datatype(decls, module, rest, lines, i)
            elif kind == "const":
                _const(decls, module, rest)
            elif kind in ("function", "predicate"):
                _function(decls, module, kind, rest)
        except ParseError as err:
            raise ParseError(f"line {i}: {line.strip()!r}: {err}") from None
    return decls


def _alias(decls: Decls, kind: str, rest: str) -> None:
    m = re.match(r"(\w+)\s*=\s*(?:\w+\s*:\s*)?(.+)$", rest)
    if not m:
        raise ParseError(f"bad {kind} declaration")
    name, base = m.groups()
    base = parse_type(split_top(base, "|")[0])  # a subset type's predicate follows `|`
    (decls.newtypes if kind == "newtype" else decls.aliases)[name] = base


def _datatype(decls: Decls, module: str, rest: str, lines: list[str], i: int) -> int:
    """Reads the constructor list, which continues while parentheses are open
    or the next non-blank line is another `|` constructor; returns the index
    of the line after it."""
    m = re.match(r"(\w+)(?:<([^>]*)>)?\s*=(.*)$", rest)
    if not m:
        raise ParseError("bad datatype declaration")
    name, params, body = m.groups()
    while True:
        j = i
        while j < len(lines) and not lines[j].strip():
            j += 1
        if j < len(lines) and (body.count("(") > body.count(")") or lines[j].strip().startswith("|")):
            body += " " + lines[j].strip()
            i = j + 1
        else:
            break
    if name in decls.datatypes:
        raise ParseError(f"datatype {name} declared twice")
    ctors = []
    for c in split_top(body, "|"):
        if not c.strip():
            continue
        m = re.fullmatch(r"\s*(\w+)\s*(?:\((.*)\))?\s*", c, re.S)
        if not m:
            raise ParseError(f"bad constructor {c.strip()!r}")
        ctors.append((m.group(1), _params(m.group(2) or "")))
    decls.datatypes[name] = Datatype(module, name, params.replace(" ", "").split(",") if params else [], ctors)
    return i


def _const(decls: Decls, module: str, rest: str) -> None:
    m = re.match(r"(\w+)\s*:\s*([^:]+?)\s*:=\s*(.*)$", rest)
    if m:  # an untyped const is not a declaration the generators read
        name, typ, value = m.groups()
        decls.functions[name] = Function(module, name, [], parse_type(typ))
        decls.consts[name] = value.strip()


def _function(decls: Decls, module: str, kind: str, rest: str) -> None:
    m = re.match(r"(\w+)\s*(\(.*)$", rest)
    if not m:
        raise ParseError(f"bad {kind} declaration")
    name = m.group(1)
    params, after = _balanced(m.group(2))
    result: Type = "bool"
    if kind == "function":
        after = re.split(r"\{|\b(?:requires|ensures|reads|decreases)\b", after, maxsplit=1)[0].strip()
        if not after.startswith(":"):
            raise ParseError(f"function {name} has no result type")
        result_text = after[1:].strip()
        named = re.fullmatch(r"\((\w+)\s*:\s*(.+)\)", result_text)  # `: (r: T)` names the result
        result = parse_type(named.group(2) if named else result_text)
    decls.functions[name] = Function(module, name, _params(params), result)


def parse_files(paths: list[Path], modules: tuple[str, ...] | None = None) -> Decls:
    decls = Decls()
    for path in paths:
        parse(path.read_text(), decls, modules)
    return decls


# --- what the generators read ----------------------------------------------


def code_strings(text: str) -> list[tuple[str, str]]:
    """(constructor, string) of every `case` of `CodeString` with a non-empty string."""
    start = text.find("function CodeString")
    if start < 0:
        raise ParseError("no CodeString function")
    body = text[start:]
    body = body[: body.index("}")]
    return [(name, value) for name, value in re.findall(r'case (\w+) => "([A-Z_]*)"', body) if value]


def const_values(decls: Decls) -> dict[str, str]:
    """String consts verbatim (quoted) and integer consts evaluated, as text."""
    out = {}
    for name, value in decls.consts.items():
        typ = decls.functions[name].result
        if typ == "string":
            out[name] = value
        elif re.fullmatch(r"[0-9x_a-fA-F* ]+", value):
            out[name] = str(eval(value.replace("_", "")))  # noqa: S307 - literal arithmetic from the core
    return out
