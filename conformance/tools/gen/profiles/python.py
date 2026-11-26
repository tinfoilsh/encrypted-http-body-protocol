"""Python: the native spellings of every generated region, the files they
live in, and the forms the generators fill (`$name` holes; `$$` is a dollar)."""

casing = "snake"  # a core name as a member: parse_config
comment = "#"
end_gap = ""
files = dict(
    core="python/src/ehbp/identity.py",
    errors="python/src/ehbp/errors.py",
    protocol="python/src/ehbp/protocol.py",
)
region_indent = {}

# errors: the spelling the SDK already exposes for a Dafny code name.
error_native = {"HpkeSetupFailed": "HPKESetupFailed", "AeadDecryptFailed": "AEADDecryptFailed"}

# core: the test accessor (handler.md section 7); see the Go profile for the keys.
core = dict(
    returns={"Result<bytes>": "bytes", "string": "str", "Option<bytes>": "Optional[bytes]", "Result<Token>": "SessionRecoveryToken"},
    ret={
        "Result<bytes>": "return r.bytes_(r.unwrap($expr))",
        "string": "return r.string($expr)",
        "Option<bytes>": "o = $expr\nreturn r.bytes_(o.value) if o.is_Some else None",
        "Result<Token>": "t = r.unwrap($expr)\nreturn SessionRecoveryToken(r.bytes_(t.exportedSecret), r.bytes_(t.requestEnc))",
    },
    wrap={"bytes": "r.seq(bytes($x))", "string": "r.str_($x)", "uint64": "_uint64($x)"},
    call={"EHBP": "EHBP.default__.$fn($args)", "EHBPEvents": "ev.default__.$fn($args)"},
    param="$name: $type",
    overrides={"ParseToken": ("fields = ev.default__.ParseToken($json)", "EHBP.default__.ValidateTokenFields(*fields)")},
)


def _wrap_line(line: str) -> str:
    """A line over 100 columns breaks after the first paren when the line is
    one call: the way ruff's E501 and the hand-written code want it."""
    i = line.find("(")
    if len(line) <= 100 or i < 0 or not line.endswith(")"):
        return line
    depth = 0
    for j, ch in enumerate(line[i:], i):
        depth += (ch == "(") - (ch == ")")
        if depth == 0 and j < len(line) - 1:
            return line  # the first call ends before the line does
    indent = line[:len(line) - len(line.lstrip())]
    return f"{line[:i + 1]}\n{indent}    {line[i + 1:-1]}\n{indent})"


types = {"bytes": "bytes", "nat": "int", "string": "str", "uint64": "int"}
