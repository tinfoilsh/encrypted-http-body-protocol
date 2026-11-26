"""Swift: the native spellings of every generated region, the files they live
in, and the forms the generators fill (`$name` holes; `$$` is a dollar).
Swift runs the core through the C ABI (handler.md section 10): no errors file
is generated; the `core` enum and the coders are."""

casing = "camel"  # a core name as a member: parseConfig
comment = "//"
end_gap = ""
files = dict(
    core="swift/Sources/EHBP/Core.swift",
    ffi="swift/Sources/EHBP/Core.swift",
)
region_indent = {"core": "    "}

# ffi: the Swift side of the C ABI (swift-ffi.md). `ffi_ty`/`ffi_enc`/`ffi_dec`
# spell one type, `ffi_decl` its Swift declaration, `ffi_coder` its Writer and
# Reader methods. The type model (resolve, target, part, ...) is gen.ffi's.
import textwrap as _textwrap  # noqa: E402
from types import SimpleNamespace as _NS  # noqa: E402

from gen import ffi as _model  # noqa: E402

_ffi_prim_ty = {"bool": "Bool", "int": "Int64", "nat": "Int64", "uint64": "UInt64", "string": "String"}
_ffi_prim_io = {"bool": "bool", "int": "int", "nat": "int", "uint64": "u64", "string": "str"}


def _ind(lines: list[str]) -> list[str]:
    return [("    " + line) if line else line for line in lines]


def ffi_case(name: str) -> str:
    return name[0].lower() + name[1:]


def ffi_name(t) -> str:
    """The coder method of a type: Option<(bytes, bytes)> -> optionBytesBytes."""
    ps = _model.part(t)
    return ps[0][0].lower() + ps[0][1:] + "".join(p[0].upper() + p[1:] for p in ps[1:])


def ffi_ty(t) -> str:
    t = _model.resolve(t)
    if isinstance(t, str) and t in _ffi_prim_ty:
        return _ffi_prim_ty[t]
    if t == _model.BYTES:
        return "Data"
    if isinstance(t, str):
        return t
    if t[0] == "seq":
        return f"[{ffi_ty(t[1])}]"
    if t[0] == "tuple":
        return "(" + ", ".join(ffi_ty(x) for x in t[1]) + ")"
    if t[1] == "Option":
        return f"{ffi_ty(t[2][0])}?"
    raise SystemExit(f"no Swift value for {t} (Result only decodes, as a throw)")


def ffi_enc(x: str, t, w: str = "self") -> list[str]:
    """Statements writing `x` of type `t` with the Writer `w`."""
    t = _model.resolve(t)
    if isinstance(t, str) and t in _ffi_prim_io:
        return [f"{w}.{_ffi_prim_io[t]}({x})"]
    if t == _model.BYTES:
        return [f"{w}.bytes({x})"]
    if isinstance(t, tuple) and t[0] == "seq":
        return [f"{w}.len({x}.count); for e in {x} {{ {'; '.join(ffi_enc('e', t[1], w))} }}"]
    if isinstance(t, tuple) and t[0] == "tuple":
        return sum((ffi_enc(f"{x}.{i}", a, w) for i, a in enumerate(t[1])), [])
    return [f"{w}.{ffi_name(t)}({x})"]


def ffi_dec(t, r: str = "") -> str:
    """An expression reading one `t` from the Reader `r` ("" inside Reader itself)."""
    t = _model.resolve(t)
    if isinstance(t, str) and t in _ffi_prim_io:
        return f"{r}{_ffi_prim_io[t]}()"
    if t == _model.BYTES:
        return f"{r}bytes()"
    if isinstance(t, tuple) and t[0] == "seq":
        return f"(0..<{r}len()).map {{ _ in {ffi_dec(t[1], r)} }}"
    if isinstance(t, tuple) and t[0] == "tuple":
        return "(" + ", ".join(ffi_dec(a, r) for a in t[1]) + ")"
    if isinstance(t, tuple) and t[1] == "Result":
        raise SystemExit(f"Result<T> inside a type: {t}")
    return f"{r}{ffi_name(t)}()"


def ffi_decl(t) -> list[str]:
    if _model.is_alias(t):
        return [f"typealias {t} = {ffi_ty(_model.aliases()[t])}"]
    if isinstance(t, tuple):
        return []  # Option<T> is T?, Result<T> is T or a throw
    ctors = _model.target(t)
    if len(ctors) == 1:
        (c, fields), = ctors
        if c != t:
            raise SystemExit(f"{t}'s one constructor is {c}; a struct needs the type's name")
        return [f"struct {t} {{ let " + ", ".join(f"{f}: {ffi_ty(ft)}" for f, ft in fields) + " }"]
    if all(not fields for _, fields in ctors):
        lines = _textwrap.wrap(", ".join(ffi_case(c) for c, _ in ctors), 100)
        return [f"enum {t}: UInt8 {{", f"    case {lines[0]}", *["         " + line for line in lines[1:]], "}"]
    cases = [f"    case {ffi_case(c)}" + (f"({', '.join(f'{f}: {ffi_ty(ft)}' for f, ft in fields)})" if fields else "") for c, fields in ctors]
    return [f"enum {t} {{", *cases, "}"]


def ffi_coder(t):
    """(decl, writer, reader) of one named type, each a block of lines; a Result has no writer."""
    name = ffi_name(t)
    decl = "\n".join(ffi_decl(t))
    if _model.is_alias(t):
        under = _model.aliases()[t]
        return _NS(decl=decl, writer=f"mutating func {name}(_ v: {t}) {{ {'; '.join(ffi_enc('v', under))} }}",
                   reader=f"mutating func {name}() -> {t} {{ {ffi_dec(under)} }}")
    ctors = _model.target(t)
    if isinstance(t, tuple) and t[1] == "Option":
        (none, nf), (some, sf) = ctors if not ctors[0][1] else ctors[::-1]
        none_i, some_i = [c for c, _ in ctors].index(none), [c for c, _ in ctors].index(some)
        if nf or len(sf) != 1:
            raise SystemExit("Option is a nullary constructor and a one-field one")
        ft = sf[0][1]
        return _NS(decl=decl,
                   writer=f"mutating func {name}(_ v: {ffi_ty(ft)}?) {{ if let v {{ u8({some_i}); {'; '.join(ffi_enc('v', ft))} }} else {{ u8({none_i}) }} }}",
                   reader="\n".join([f"mutating func {name}() -> {ffi_ty(ft)}? {{", "    switch u8() {", f"    case {none_i}: return nil",
                                     f"    case {some_i}: return {ffi_dec(ft)}", f'    default: preconditionFailure("core: bad {_model.part(t)[0]} tag")', "    }", "}"]))
    if isinstance(t, tuple) and t[1] == "Result":
        tags = {c: i for i, (c, _) in enumerate(ctors)}
        ok, err = dict(ctors)["Ok"], dict(ctors)["Err"]
        if [f for f, _ in ok] != ["value"] or [f for f, _ in err] != ["code", "message"]:
            raise SystemExit("Result is Ok(value) | Err(code, message)")
        return _NS(decl=decl, writer="",
                   reader="\n".join([f"mutating func {name}() throws -> {ffi_ty(ok[0][1])} {{", "    switch u8() {", f"    case {tags['Ok']}: return {ffi_dec(ok[0][1])}",
                                     f"    case {tags['Err']}: throw error({', '.join(ffi_dec(ft) for _, ft in err)}, nil)",
                                     '    default: preconditionFailure("core: bad Result tag")', "    }", "}"]))
    if len(ctors) == 1:
        (c, fields), = ctors
        return _NS(decl=decl,
                   writer=f"mutating func {name}(_ v: {t}) {{ " + "; ".join(sum((ffi_enc(f"v.{f}", ft) for f, ft in fields), [])) + " }",
                   reader=f"mutating func {name}() -> {t} {{ {t}(" + ", ".join(f"{f}: {ffi_dec(ft)}" for f, ft in fields) + ") }")
    if all(not fields for _, fields in ctors):
        return _NS(decl=decl, writer=f"mutating func {name}(_ v: {t}) {{ u8(v.rawValue) }}",
                   reader=f"mutating func {name}() -> {t} {{ {t}(rawValue: u8())! }}")
    enc, dec = [], []
    for i, (c, fields) in enumerate(ctors):
        pat = f".{ffi_case(c)}" + (f"({', '.join('let ' + f for f, _ in fields)})" if fields else "")
        enc.append(f"case {pat}: " + "; ".join([f"u8({i})"] + sum((ffi_enc(f, ft) for f, ft in fields), [])))
        dec.append(f"case {i}: return .{ffi_case(c)}" + (f"({', '.join(f'{f}: {ffi_dec(ft)}' for f, ft in fields)})" if fields else ""))
    return _NS(decl=decl,
               writer="\n".join([f"mutating func {name}(_ v: {t}) {{", "    switch v {", *_ind(enc), "    }", "}"]),
               reader="\n".join([f"mutating func {name}() -> {t} {{", "    switch u8() {", *_ind(dec), f'    default: preconditionFailure("core: bad {t} tag")', "    }", "}"]))

# core: the `Core` enum is every ABI op over the coders above (templates/swift/core.swift.j2).
core = {}

types = {"bytes": "Data", "nat": "Int"}
