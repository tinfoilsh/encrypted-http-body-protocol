"""The SPEC rule table of handler.md section 3 (check.py `rules`): every name
it lists exists, every Spec_* lemma is listed, and every lemma quotes its rule."""
import re

import check
from gen import ROOT

RULES = (ROOT / "dafny/spec_rules.dfy").read_text()
LEMMAS = set(re.findall(r"^\s*lemma\s+(?:\{:[^}]*\}\s*)*(Spec_\w+)", RULES, re.M))
ROWS = check.spec_rows()


def test_table_has_rows():
    assert len(ROWS) > 50 and all(len(row.split("|")) == 5 for row in ROWS)


def test_every_name_exists_and_every_lemma_is_listed():
    assert check.rule_problems() == []


def test_every_lemma_has_a_rule_comment():
    for name in LEMMAS:
        before = RULES[: re.search(rf"^\s*lemma\s+(?:\{{:[^}}]*\}}\s*)*{name}\(", RULES, re.M).start()].rstrip().splitlines()[-1]
        assert before.strip().startswith("//"), f"{name} has no doc comment quoting the rule"
