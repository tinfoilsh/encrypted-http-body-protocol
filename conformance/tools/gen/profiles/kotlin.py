"""Kotlin: the native spellings of every generated region, the files they
live in, and the forms the generators fill (`$name` holes; `$$` is a dollar)."""

casing = "camel"  # a core name as a member: parseConfig
comment = "//"
end_gap = ""
files = dict(
    core="kotlin/src/main/kotlin/sh/tinfoil/ehbp/Core.kt",
    errors="kotlin/src/main/kotlin/sh/tinfoil/ehbp/protocol/Errors.kt",
    protocol="kotlin/src/main/kotlin/sh/tinfoil/ehbp/protocol/Protocol.kt",
)
region_indent = {"core": "    "}

# errors: the spelling the SDK already exposes for a Dafny code name.
error_native = {"HpkeSetupFailed": "HPKESetupFailed", "AeadDecryptFailed": "AEADDecryptFailed"}

# core: the test accessor (handler.md section 7); see the Go profile for the keys.
core = dict(
    returns={"Result<bytes>": "ByteArray", "string": "String", "Option<bytes>": "ByteArray?", "Result<Token>": "SessionRecoveryToken"},
    ret={
        "Result<bytes>": "return bytes(unwrap($expr))",
        "string": "return string($expr)",
        "Option<bytes>": "return $expr.takeIf { it.is_Some }?.let { bytes(it.dtor_value()) }",
        "Result<Token>": "val t = unwrap($expr)\nreturn SessionRecoveryToken(bytes(t.dtor_exportedSecret()), bytes(t.dtor_requestEnc()))",
    },
    wrap={"bytes": "seq($x)", "string": "str($x)", "uint64": "$x.toLong()"},
    call={"EHBP": "EHBP.__default.$fn($args)", "EHBPEvents": "EHBPEvents.__default.$fn($args)"},
    param="$name: $type",
    overrides={
        "ParseToken": ("""\
// shortcut: the core's ParseString is quadratic in Java (acc + [c] per char), so a huge document exhausts the heap; drop when the core accumulates linearly
if (json.length > 4096) throw ProtocolError(Code.InvalidToken, "token document is too long") // two 64-hex members plus any formatting
val fields = EHBPEvents.__default.ParseToken($json)""",
                       "EHBP.__default.ValidateTokenFields(fields.dtor__0(), fields.dtor__1())"),
    },
)

types = {"bytes": "ByteArray", "nat": "Int", "string": "String", "uint64": "ULong"}
