"""Every backticked name in the specs that looks like a path names a tracked
file or directory (check.py `docs`), so a renamed file cannot leave a stale
reference behind."""
import pytest

import check


@pytest.mark.parametrize("doc", check.DOCS)
def test_paths_exist(doc):
    missing = check.missing_paths(doc, check.tracked())
    assert not missing, f"{doc} names files that do not exist: {missing}"

