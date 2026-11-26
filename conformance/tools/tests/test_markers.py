import pytest

from gen import markers

TEXT = "head\n    // x:begin (note)\n    body\n    // x:end\ntail\n"


def test_split_keeps_the_begin_indent_outside():
    before, region, after = markers.split(TEXT, "//", "x")
    assert before == "head\n    "
    assert region == "// x:begin (note)\n    body\n    // x:end"
    assert after == "\ntail\n"
    assert before + region + after == TEXT


def test_wrap_and_replace():
    region = markers.wrap("//", "x", "note", "new", end_indent="    ")
    assert region == "// x:begin (note)\nnew\n    // x:end"
    out = markers.replace(TEXT, "//", "x", region)
    assert out == "head\n    // x:begin (note)\nnew\n    // x:end\ntail\n"
    assert markers.replace(out, "//", "x", region) == out  # idempotent


def test_lines_and_diff():
    before, region, _ = markers.split(TEXT, "//", "x")
    assert markers.lines(before, region) == (2, 4)
    assert markers.diff("a\n", "a\n", "f") == ""
    assert "-a\n+b\n" in markers.diff("a\n", "b\n", "f")


def test_missing_markers():
    with pytest.raises(ValueError, match="no y:begin"):
        markers.split(TEXT, "//", "y")
    with pytest.raises(ValueError, match="no x:end"):
        markers.split("// x:begin (n)\nbody\n", "//", "x")
