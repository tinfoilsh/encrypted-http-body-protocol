"""The code generators behind `conformance/tools/gen.py`: one module per target
(errors, core, ffi: what is derived from a machine-readable source), one
profile per language (`profiles/<lang>.py`: the native spellings every target
needs) and one Jinja template per language and target
(`templates/<lang>/<target>.<ext>.j2`). The rest of a port is committed code,
checked by `conformance/tools/check.py`.

A profile is data: short spellings with `$name` holes (`string.Template`,
`$$` is a literal dollar) and a few render helpers. A template is the code of
one language with `{{ }}` / `{% %}` holes, rendered with `trim_blocks`,
`lstrip_blocks` and `keep_trailing_newline` so the bytes it emits are the
bytes it shows. Adding a language is one profile plus its templates
(handler.md section 8)."""
from __future__ import annotations

import importlib
import re
import sys
from functools import cache
from pathlib import Path
from string import Template
from types import ModuleType

ROOT = Path(__file__).resolve().parents[3]
TEMPLATES = Path(__file__).parent / "templates"
LANGS = ["go", "python", "kotlin", "rust", "js", "swift"]

try:
    import jinja2
except ImportError:  # the conformance venv has it; a system python3 may not
    for site in (ROOT / "conformance/.venv/lib").glob("python*/site-packages"):
        sys.path.append(str(site))
    try:
        import jinja2
    except ImportError:
        raise SystemExit("gen: jinja2 is required (pip install jinja2)") from None


@cache
def profile(lang: str) -> ModuleType:
    """The language's profile module, `gen.profiles.<lang>`."""
    if lang not in LANGS:
        raise SystemExit(f"gen: unknown language {lang!r}; one of {', '.join(LANGS)}")
    return importlib.import_module(f"gen.profiles.{lang}")


@cache
def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES)),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True,
    )
    env.filters["fill"] = fill
    return env


def template(lang: str, target: str) -> jinja2.Template:
    """`templates/<lang>/<target>.<ext>.j2`; the extension is the language's."""
    matches = sorted((TEMPLATES / lang).glob(f"{target}.*.j2"))
    if len(matches) != 1:
        raise SystemExit(f"gen: {TEMPLATES.relative_to(ROOT)}/{lang}/{target}.<ext>.j2: {'missing' if not matches else 'ambiguous'}")
    return environment().get_template(f"{lang}/{matches[0].name}")


def macro(lang: str, target: str, name: str, context: dict | None = None, **kw) -> str:
    """One `{% macro name() %}` of the template, rendered with `kw` as its
    arguments and `context` as the variables its body may read; a missing
    macro names itself."""
    module = template(lang, target).make_module(context or {})
    if not hasattr(module, name):
        raise SystemExit(f"gen: templates/{lang}/{target}: no macro {name!r}")
    return str(getattr(module, name)(**kw))


def fill(spelling: str, **kw) -> str:
    """A profile spelling with its `$name` holes filled; a hole without a value fails."""
    return Template(spelling).substitute(kw)


def snake(name: str) -> str:
    """ParseConfig -> parse_config, X25519Result -> x25519_result."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def lower(name: str) -> str:
    """ParseConfig -> parseConfig."""
    return name[0].lower() + name[1:]


CASINGS = {"pascal": lambda n: n, "snake": snake, "camel": lower}


def spell(lang: str, name: str) -> str:
    """A core name in the language's casing (the profile's `casing`)."""
    return CASINGS[profile(lang).casing](name)
