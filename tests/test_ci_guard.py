"""SC-CI-01/02: the test-count guard counts all tests and can actually fail."""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD = REPO_ROOT / "tools" / "test_count_guard.sh"


def _run_guard(*args):
    return subprocess.run(
        ["bash", str(GUARD), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_sc_ci_01_guard_passes_head_vs_head_and_counts_all_tests():
    result = _run_guard("HEAD", "HEAD")
    assert result.returncode == 0, result.stderr + result.stdout
    # output must be a single integer per ref (the old `|| echo 0` bug
    # produced "0\n0" and could never fail the -lt comparison)
    line = [ln for ln in result.stdout.splitlines() if ln.startswith("test count:")]
    assert len(line) == 1
    parts = dict(kv.split("=") for kv in line[0].split(":", 1)[1].split())
    assert parts["before"].isdigit() and parts["after"].isdigit()
    assert int(parts["before"]) > 0  # unit tests + scenarios both counted


def test_sc_ci_02_guard_self_test_catches_deliberate_deletion():
    # --self-test builds a doctored tree (per fixtures/deliberate_violation)
    # with tests removed and proves the guard exits non-zero on it.
    result = _run_guard("--self-test")
    assert result.returncode == 0, result.stderr + result.stdout
    assert "SELF-TEST OK" in result.stdout
