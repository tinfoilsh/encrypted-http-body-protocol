import pytest

import check
from gen import operations_md as om

TABLE = """
Some prose with | a pipe.

| operation | inputs | success `body_hex` | error codes |
| --- | --- | --- | --- |
| `one` | `a`, `b` (32) | `x` `\\|\\|` `y` | `E` |
| `two` | same as `one`, plus top-level `chunking` | out | same as `one` |
| `three` | none | out | - |
"""


def test_inputs_and_inheritance():
    assert om.parse(TABLE) == {"one": ["a", "b"], "two": ["chunking", "a", "b"], "three": []}


def test_cells_keep_escaped_pipes():
    assert om.cells("| `a` | x `\\|\\|` y |") == ["`a`", "x `\\|\\|` y"]


def test_header_is_required():
    with pytest.raises(om.ParseError, match="operation"):
        om.parse("| op | in |\n| --- | --- |\n| `a` | `b` |\n")
    with pytest.raises(om.ParseError, match="backticked"):
        om.parse("| operation | inputs |\n| --- | --- |\n| a | `b` |\n")


def test_real_table_parses():
    spec = check.operations_table()
    assert len(spec) == 20 and check.SERVER_OPS <= set(spec)
    assert spec["decrypt_response_streaming"] == ["chunking", "exportedSecret", "requestEnc", "responseNonce", "encryptedResponse"]
    assert spec["reject_cross_origin"] == []
