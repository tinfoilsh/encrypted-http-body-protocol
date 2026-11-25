import pytest

from gen import ROOT, ffi
from gen import dafny_decls as dd

SNIPPET = '''
module M {
  newtype uint8 = x: int | 0 <= x < 0x100
  type bytes = seq<uint8>
  type PublicKey = b: bytes | |b| == 32 witness seq(32, i => 0)
  type Headers = seq<(string, string)>
  const Url: string := "http://x" // a string with a comment marker inside
  const Limit: nat := 64 * 1024

  datatype Result<T> = Ok(value: T) | Err(code: Code, message: string)
  datatype Code =
    | Alpha
    // a comment between constructors
    | Beta

  datatype Event =
    | Start(verb: string, headers: Headers, port: int)
    | Pair(p: (bytes, bool))
    | Unit

  function Check(b: bytes, n: nat): Result<()> requires n > 0 { Ok(()) }
  function Named(e: Event): (o: (Option<string>, Option<string>))
  predicate Small(h: Headers)
  lemma Nothing()
}
'''


@pytest.fixture(scope="module")
def decls():
    return dd.parse(SNIPPET)


def test_types(decls):
    assert decls.newtypes == {"uint8": "int"}
    assert decls.aliases == {"bytes": ("seq", "uint8"), "PublicKey": "bytes", "Headers": ("seq", ("tuple", ["string", "string"]))}


def test_consts_are_nullary_functions(decls):
    assert decls.consts == {"Url": '"http://x"', "Limit": "64 * 1024"}
    assert decls.functions["Url"].params == [] and decls.functions["Url"].result == "string"
    assert dd.const_values(decls) == {"Url": '"http://x"', "Limit": "65536"}


def test_datatypes_keep_constructor_and_field_order(decls):
    assert decls.datatypes["Result"].params == ["T"]
    assert decls.datatypes["Result"].ctors == [("Ok", [("value", "T")]), ("Err", [("code", "Code"), ("message", "string")])]
    assert [c for c, _ in decls.datatypes["Code"].ctors] == ["Alpha", "Beta"]
    assert decls.datatypes["Event"].ctors[0] == ("Start", [("verb", "string"), ("headers", "Headers"), ("port", "int")])
    assert decls.datatypes["Event"].ctors[1] == ("Pair", [("p", ("tuple", ["bytes", "bool"]))])  # aliases stay names
    assert decls.datatypes["Event"].ctors[2] == ("Unit", [])
    assert decls.datatypes["Event"].module == "M"


def test_function_signatures(decls):
    check = decls.functions["Check"]
    assert [n for n, _ in check.params] == ["b", "n"] and check.result == ("app", "Result", [("tuple", [])])
    assert decls.functions["Named"].result == ("tuple", [("app", "Option", ["string"]), ("app", "Option", ["string"])])
    assert decls.functions["Small"].result == "bool"
    assert "Nothing" not in decls.functions


def test_module_filter_and_duplicates():
    text = "module A {\n  datatype X = X(a: int)\n}\nmodule B {\n  datatype X = Y | Z\n}\n"
    with pytest.raises(dd.ParseError, match="declared twice"):
        dd.parse(text)
    assert [c for c, _ in dd.parse(text, modules=("B",)).datatypes["X"].ctors] == ["Y", "Z"]


def test_errors_name_the_line():
    with pytest.raises(dd.ParseError, match="line 1.*bad type"):
        dd.parse("function F(a: seq<>): int")
    with pytest.raises(dd.ParseError, match="no result type"):
        dd.parse("function F(a: int)")


def test_strip_comment_keeps_strings():
    assert dd.strip_comment('x := "a//b" // c') == 'x := "a//b" '


def test_code_strings():
    text = 'function CodeString(c: Code): string\n{\n  match c\n  case A => "A_CODE"\n  case T => ""\n}\n'
    assert dd.code_strings(text) == [("A", "A_CODE")]


# --- the real core ----------------------------------------------------------


def test_real_core_parses():
    d = ffi.decls()
    event = [c for c, _ in d.datatypes["Event"].ctors]
    assert event[0] == "Start" and event[-1] == "CallerClose"
    assert [c for c, _ in d.datatypes["Action"].ctors][:3] == ["BeginSession", "PublishToken", "ClearToken"]
    assert d.aliases["Headers"] == ("seq", ("tuple", ["string", "string"]))
    assert d.datatypes["Option"].params == ["T"]


def test_every_op_exists_with_its_arity():
    d = ffi.decls()
    for name, module, args, _ in ffi.OPS:
        f = d.functions[name]
        assert (f.module, len(f.params)) == (module, len(args)), name


def test_an_op_with_the_wrong_arity_fails(monkeypatch):
    monkeypatch.setattr(ffi, "OPS", ffi.OPS + [("ParseConfig", "EHBP", [], "Result<bytes>")])
    ffi.decls.cache_clear()
    try:
        with pytest.raises(SystemExit, match="ParseConfig is EHBP.ParseConfig/1"):
            ffi.decls()
    finally:
        ffi.decls.cache_clear()


def test_error_codes_and_consts_from_the_core():
    codes = dd.code_strings((ROOT / "dafny/ehbp.dfy").read_text())
    assert codes[0] == ("InvalidKeyConfig", "INVALID_KEY_CONFIG") and len(codes) == 15
    k = dd.const_values(dd.parse_files([ROOT / "dafny/ehbp.dfy"]))
    assert k["KeysPath"] == '"/.well-known/hpke-keys"' and k["RequestFrameBytes"] == "65536"
