"""Go: the native spellings of every generated region, the files they live
in, and the forms the generators fill (`$name` holes; `$$` is a dollar)."""

casing = "pascal"  # a core name as a member: ParseConfig
comment = "//"
end_gap = "\n"  # a blank line before every region's end marker
files = dict(
    core="client/core.go",
    errors="protocol/errors.go",
    protocol="protocol/protocol.go",
)
region_indent = {}  # region -> the indentation of its end marker (and head line) inside the file

# errors: the spelling the SDK already exposes for a Dafny code name.
error_native = {"HpkeSetupFailed": "HPKESetupFailed", "AeadDecryptFailed": "AEADDecryptFailed"}

# core: the test accessor (handler.md section 7). `returns` is the return type
# and `ret` the result statements per result type (`$expr` is the core call),
# `wrap` the argument wrapper per type, `call` the call form per Dafny module,
# `overrides` a (pre, expr) where one core call is not the member.
core = dict(
    returns={"Result<bytes>": "([]byte, error)", "string": "string", "Option<bytes>": "[]byte", "Result<Token>": "(*SessionRecoveryToken, error)"},
    ret={
        "Result<bytes>": "return bytesResult($expr)",
        "string": "return eventresidue.String($expr)",
        "Option<bytes>": """\
o := $expr
if !o.Is_Some() {
	return nil
}
return eventresidue.Bytes(o.Dtor_value().(_dafny.Sequence))""",
        "Result<Token>": """\
r := $expr
if r.Is_Err() {
	return nil, eventresidue.Error(r.Dtor_code(), eventresidue.String(r.Dtor_message()), nil)
}
tok := r.Dtor_value().(core.Token)
return &SessionRecoveryToken{eventresidue.Bytes(tok.Dtor_exportedSecret()), eventresidue.Bytes(tok.Dtor_requestEnc())}, nil""",
    },
    wrap={"bytes": "eventresidue.Seq($x)", "string": "eventresidue.Str($x)", "uint64": "$x"},
    call={"EHBP": "core.Companion_Default___.$fn($args)", "EHBPEvents": "ev.Companion_Default___.$fn($args)"},
    param="$name $type",
    overrides={
        "ParseToken": ("fields := ev.Companion_Default___.ParseToken($json)",
                       "core.Companion_Default___.ValidateTokenFields((*fields.IndexInt(0)).(core.Option), (*fields.IndexInt(1)).(core.Option))"),
    },
)

types = {"bytes": '[]byte', "nat": "int", "string": "string", "uint64": "uint64"}
