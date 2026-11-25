import subprocess
import sys

from gen import ROOT

TOOLS = ROOT / "conformance/tools"


def run(*args):
    return subprocess.run([sys.executable, *args], cwd=ROOT, capture_output=True, text=True)


def test_check_all_is_in_sync():
    done = run(TOOLS / "gen.py", "--check", "all")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "core in sync" in done.stdout and "ffi in sync" in done.stdout


def test_unknown_target():
    done = run(TOOLS / "gen.py", "nope")
    assert done.returncode == 2 and "unknown target" in done.stderr


def test_forwarder_and_language_argument():
    done = run(TOOLS / "gen_core.py", "--check", "go")
    assert done.returncode == 0 and done.stdout.strip() == "go      core in sync"


def test_check():
    done = run(TOOLS / "check.py")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "FAIL" not in done.stdout


def test_check_unknown_section():
    done = run(TOOLS / "check.py", "nope")
    assert done.returncode == 2 and "unknown section" in done.stderr
