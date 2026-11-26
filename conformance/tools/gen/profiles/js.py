"""JavaScript: the native spellings of every generated region, the files they
live in, and the forms the generators fill (`$name` holes; `$$` is a dollar)."""

casing = "camel"  # a core name as a member: parseConfig
comment = "//"
end_gap = ""
files = dict(
    core="js/src/identity.ts",
    errors="js/src/errors.ts",
    protocol="js/src/protocol.ts",
)
region_indent = {"core": "  "}

# errors: the spelling the SDK already exposes for a Dafny code name.
error_native = {}

# core: the test accessor (handler.md section 7); see the Go profile for the keys.
core = dict(
    returns={"Result<bytes>": "Uint8Array", "string": "string", "Option<bytes>": "Uint8Array | undefined", "Result<Token>": "SessionRecoveryToken"},
    ret={
        "Result<bytes>": "return bytes(unwrap($expr));",
        "string": "return string($expr);",
        "Option<bytes>": "let o = $expr;\nreturn o.is_Some ? bytes(o.dtor_value) : undefined;",
        "Result<Token>": "let t = unwrap($expr);\nreturn { exportedSecret: bytes(t.dtor_exportedSecret), requestEnc: bytes(t.dtor_requestEnc) };",
    },
    wrap={"bytes": "seq($x)", "string": "str($x)", "uint64": "uint64($x)"},
    call={"EHBP": "pure.$fn($args)", "EHBPEvents": "ev.$fn($args)"},
    param="$name: $type",
    overrides={"ParseToken": ("", "pure.ValidateTokenFields(...ev.ParseToken($json))")},
)

types = {"bytes": "Uint8Array", "nat": "number", "string": "string", "uint64": 'bigint | number'}
