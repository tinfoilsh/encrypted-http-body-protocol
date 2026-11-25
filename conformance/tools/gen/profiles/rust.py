"""Rust: the native spellings of every generated region, the files they live
in, and the forms the generators fill (`$name` holes; `$$` is a dollar)."""

casing = "snake"  # a core name as a member: parse_config
comment = "//"
end_gap = ""
files = dict(
    core="rust/src/identity.rs",
    errors="rust/src/error.rs",
    protocol="rust/src/protocol.rs",
    ffi="rust/ffi/src/lib.rs",
)
region_indent = {}

# errors: the spelling the SDK already exposes for a Dafny code name.
error_native = {}

# ffi: the Rust side of the C ABI (swift-ffi.md). `ffi_ty`/`ffi_enc`/`ffi_dec`/
# `ffi_sample` spell one type, `ffi_coder` one type's Writer and Reader methods
# and sample values, `ffi_op` one arm of the `call` op table. The type model
# (resolve, target, part, ...) is gen.ffi's.
from types import SimpleNamespace as _NS  # noqa: E402

from gen import ffi as _model  # noqa: E402

ffi_module = {"EHBP": "core", "EHBPEvents": "ev"}  # Dafny module -> the alias lib.rs imports it under
_ffi_prim_ty = {"bool": "bool", "int": "DafnyInt", "nat": "DafnyInt", "uint64": "u64", "string": "Sequence<DafnyChar>"}
_ffi_prim_io = {"bool": "bool", "uint64": "u64", "string": "str", "int": "int", "nat": "int"}
_ffi_prim_sample = {"bool": "true", "int": "DafnyInt::from(7i64)", "nat": "DafnyInt::from(7i64)", "uint64": "7u64", "string": 'string_of("héllo")'}


def _ind(lines: list[str], n: int = 1) -> list[str]:
    return [("    " * n + line) if line else line for line in lines]


def ffi_name(t) -> str:
    """The coder method of a type: Option<(bytes, bytes)> -> option_bytes_bytes."""
    from gen import snake
    return "_".join(snake(p) for p in _model.part(t))


def ffi_path(t) -> str:
    name = t[1] if isinstance(t, tuple) else t
    return f"{ffi_module[_model.module_of(t)]}::{name}"


def ffi_ty(t, arc: bool = True) -> str:
    t = _model.resolve(t)
    if isinstance(t, str) and t in _ffi_prim_ty:
        return _ffi_prim_ty[t]
    if t == _model.BYTES:
        return "Sequence<u8>"
    if _model.is_alias(t):
        return t
    if isinstance(t, tuple) and t[0] == "seq":
        return f"Sequence<{ffi_ty(t[1])}>"
    if isinstance(t, tuple) and t[0] == "tuple":
        return "(" + ", ".join(ffi_ty(x) for x in t[1]) + ")"
    inner = ffi_path(t) + (f"<{', '.join(ffi_ty(x) for x in t[2])}>" if isinstance(t, tuple) else "")
    return f"Arc<{inner}>" if arc else inner


def ffi_enc(x: str, t) -> list[str]:
    """Statements writing `x`, an expression of type `&T` (or a reference binding), with `w`."""
    t = _model.resolve(t)
    bare = x[1:] if x.startswith("&") else x
    if t in ("bool", "uint64"):
        return [f"w.{_ffi_prim_io[t]}({bare if x.startswith('&') else '*' + x});"]
    if t in ("int", "nat", "string"):
        return [f"w.{_ffi_prim_io[t]}({x});"]
    if t == _model.BYTES:
        return [f"w.seq({x});"]
    if isinstance(t, tuple) and t[0] == "seq":
        return [f"w.len({bare}.cardinality_usize());", f"for e in {bare}.iter() {{", *_ind(ffi_enc("&e", t[1])), "}"]
    if isinstance(t, tuple) and t[0] == "tuple":
        return sum((ffi_enc(f"&{bare}.{i}", a) for i, a in enumerate(t[1])), [])
    return [f"w.{ffi_name(t)}({x});"]


def ffi_dec(t) -> str:
    """An expression reading one `T` from `r`, Arc-wrapped where a Dafny field holds one."""
    t = _model.resolve(t)
    if isinstance(t, str) and t in _ffi_prim_io:
        return f"r.{_ffi_prim_io[t]}()?"
    if t == _model.BYTES:
        return "r.seq()?"
    if isinstance(t, tuple) and t[0] == "seq":
        return f"{{ let n = r.len()?; let mut v = Vec::with_capacity(n.min(1024)); for _ in 0..n {{ v.push({ffi_dec(t[1])}); }} Sequence::from_array_owned(v) }}"
    if isinstance(t, tuple) and t[0] == "tuple":
        return "(" + ", ".join(ffi_dec(a) for a in t[1]) + ")"
    if _model.is_alias(t):
        return f"r.{ffi_name(t)}()?"
    return f"Arc::new(r.{ffi_name(t)}()?)"


def ffi_sample(t) -> str:
    t = _model.resolve(t)
    if isinstance(t, str) and t in _ffi_prim_sample:
        return _ffi_prim_sample[t]
    if t == _model.BYTES:
        return "Sequence::from_array_owned(vec![1u8, 2, 3])"
    if isinstance(t, tuple) and t[0] == "seq":
        return f"Sequence::from_array_owned(vec![{ffi_sample(t[1])}])"
    if isinstance(t, tuple) and t[0] == "tuple":
        return "(" + ", ".join(ffi_sample(a) for a in t[1]) + ")"
    if _model.is_alias(t):
        return ffi_sample(_model.aliases()[t])
    return f"Arc::new(sample_{ffi_name(t)}().pop().unwrap())"


def ffi_coder(t):
    """(writer, reader, sample) of one named type, each a block of lines."""
    name, ty = ffi_name(t), ffi_ty(t, arc=False)
    if _model.is_alias(t):
        under = _model.aliases()[t]
        return _NS(writer="\n".join([f"fn {name}(&mut self, v: &{ty}) {{", "    let w = self;", *_ind(ffi_enc("v", under)), "}"]),
                   reader="\n".join([f"fn {name}(&mut self) -> Result<{ty}, Bad> {{", "    let r = self;", f"    Ok({ffi_dec(under)})", "}"]),
                   sample="")
    ctors, path, single = _model.target(t), ffi_path(t), _model.is_single(t)
    enc, dec, samples = [], [], []
    for i, (c, fields) in enumerate(ctors):
        names = ", ".join(f for f, _ in fields)
        pat = f"{path}::{c} {{ {names} }}" if fields else f"{path}::{c} {{}}"
        body = ([] if single else [f"w.u8({i});"]) + sum((ffi_enc(f, ft) for f, ft in fields), [])
        enc += [f"{pat} => {{", *_ind(body), "}"] if len(body) != 1 else [f"{pat} => {body[0][:-1]},"]
        init = f"{path}::{c} {{ " + ", ".join(f"{f}: {ffi_dec(ft)}" for f, ft in fields) + " }" if fields else f"{path}::{c} {{}}"
        dec.append(init if single else f"{i} => {init},")
        samples.append(f"{path}::{c} {{ " + ", ".join(f"{f}: {ffi_sample(ft)}" for f, ft in fields) + " }" if fields else f"{path}::{c} {{}}")
    writer = [f"fn {name}(&mut self, v: &{ty}) {{", "    let w = self;", "    match v {", *_ind(enc, 2), "    }", "}"]
    body = [f"Ok({dec[0]})"] if single else ["Ok(match r.u8()? {", *_ind(dec), "    _ => return Err(Bad),", "})"]
    reader = [f"fn {name}(&mut self) -> Result<{ty}, Bad> {{", "    let r = self;", *_ind(body), "}"]
    sample = [f"fn sample_{name}() -> Vec<{ty}> {{", "    vec![", *_ind([s + "," for s in samples], 2), "    ]", "}"]
    return _NS(writer="\n".join(writer), reader="\n".join(reader), sample="\n".join(sample))


def ffi_op(op) -> str:
    """The body of one `call` arm: decode the arguments, call, encode the result."""
    fn, module, args, res = op
    args = [_model.parse_type(t) for _, t in args]
    lines = [f"let a{k} = {ffi_dec(a)};" for k, a in enumerate(args)]
    call = ", ".join(f"a{k}" if _model.resolve(a) in ("bool", "uint64") else f"&a{k}" for k, a in enumerate(args))
    lines.append(f"let out = {ffi_module[module]}::_default::{fn}({call});")
    return "\n".join(lines + ffi_enc("&out", _model.parse_type(res)))

# core: the test accessor (handler.md section 7); see the Go profile for the keys.
core = dict(
    returns={"Result<bytes>": "Result<Vec<u8>>", "string": "String", "Option<bytes>": "Option<Vec<u8>>", "Result<Token>": "Result<SessionRecoveryToken>"},
    ret={
        "Result<bytes>": "Ok(bytes(&result(&$expr)?))",
        "string": "string(&$expr)",
        "Option<bytes>": "match $expr.as_ref() { core::Option::Some { value } => Some(bytes(value)), core::Option::None {} => None }",
        "Result<Token>": "Ok(SessionRecoveryToken::from_core(&*result(&$expr)?))",
    },
    wrap={"bytes": "&seq($x)", "string": "&str($x)", "uint64": "$x"},
    call={"EHBP": "core::_default::$fn($args)", "EHBPEvents": "ev::_default::$fn($args)"},
    param="$name: $type",
    overrides={"ParseToken": ("let (secret, enc) = ev::_default::ParseToken($json);", "core::_default::ValidateTokenFields(&secret, &enc)")},
)

types = {"bytes": '&[u8]', "nat": "usize", "string": '&str', "uint64": "u64"}
