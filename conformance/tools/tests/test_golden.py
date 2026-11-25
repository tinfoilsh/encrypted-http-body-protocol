"""Rendering every generated target for every language into a temporary tree
gives the committed tree: the drift check as a test. Rendering is idempotent."""
import importlib

import pytest

from gen import ROOT, markers, profile
from gen import errors as errors_target

REGIONS = ["core", "ffi"]


def rendered(target: str, lang: str) -> tuple[str, str]:
    """(relative path, the file as the target would write it)."""
    mod = importlib.import_module(f"gen.{target}")
    P = profile(lang)
    rel = P.files[target]
    comment = "//" if target == "ffi" else P.comment
    return rel, markers.replace((ROOT / rel).read_text(), comment, target, mod.render(lang))


CASES = [(t, lang) for t in REGIONS for lang in importlib.import_module(f"gen.{t}").LANGS]


@pytest.mark.parametrize("target,lang", CASES)
def test_golden(target, lang, tmp_path):
    rel, text = rendered(target, lang)
    out = tmp_path / rel
    out.parent.mkdir(parents=True)
    out.write_text(text)
    assert out.read_text() == (ROOT / rel).read_text(), f"{rel} drifts from gen.py {target}"


def test_golden_errors(tmp_path):
    for rel, text in errors_target.render().items():
        out = tmp_path / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text)
        assert out.read_text() == (ROOT / rel).read_text(), f"{rel} drifts from gen.py errors"


@pytest.mark.parametrize("target,lang", CASES)
def test_idempotent(target, lang):
    assert rendered(target, lang) == rendered(target, lang)
    rel, text = rendered(target, lang)
    mod = importlib.import_module(f"gen.{target}")
    comment = "//" if target == "ffi" else profile(lang).comment
    assert markers.replace(text, comment, target, mod.render(lang)) == text  # replacing a rendered region with itself changes nothing
