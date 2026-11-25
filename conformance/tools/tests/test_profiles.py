"""Every profile has the keys every generator needs, and a template per target."""
import importlib

import pytest

from gen import profile, template

TARGETS = ["errors", "core", "ffi"]
PAIRS = [(t, lang) for t in TARGETS for lang in importlib.import_module(f"gen.{t}").LANGS]


@pytest.mark.parametrize("target,lang", PAIRS)
def test_profile_has_the_keys(target, lang):
    mod = importlib.import_module(f"gen.{target}")
    missing = [k for k in mod.PROFILE_KEYS if not hasattr(profile(lang), k)]
    assert not missing, f"gen/profiles/{lang}.py lacks {missing} (needed by gen.{target})"


@pytest.mark.parametrize("target,lang", PAIRS)
def test_template_exists(target, lang):
    if target == "errors":
        template(lang, "errors") and template(lang, "protocol")
    else:
        template(lang, target)


def test_unknown_language():
    with pytest.raises(SystemExit, match="unknown language"):
        profile("cobol")
