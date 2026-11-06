#!/usr/bin/env python3
"""Per-file test inventory (BACKLOG M2 #7).

Pure stdlib. Prints a `def test_` count for every tests/test_*.py file, plus
the scenario file count and the grand total, in a format consistent with
tools/test_count_guard.sh (same counting rule: lines containing 'def test_').
Read-only: never modifies the tree; run it from anywhere.

Usage:
  python3 tools/test_inventory.py
"""

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"
SCENARIOS_DIR = TESTS_DIR / "scenarios"


def count_file(path):
    """Lines containing 'def test_' — identical to the guard's git-grep rule."""
    count = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if "def test_" in line:
                count += 1
    return count


def main():
    unit_total = 0
    print("per-file test inventory (lines containing 'def test_' in tests/test_*.py):")
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        count = count_file(path)
        unit_total += count
        print(f"  {path.relative_to(REPO_ROOT)}: {count}")
    scenario_total = sum(
        1 for path in SCENARIOS_DIR.rglob("*") if path.suffix in (".yaml", ".yml")
    )
    print(f"unit tests (tests/test_*.py): {unit_total}")
    print(f"scenario files (tests/scenarios): {scenario_total}")
    print(f"total: {unit_total + scenario_total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
