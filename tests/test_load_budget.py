"""SC-LOAD-01: max_chars is the CLASS budget, aggregated across records."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import build_bundle, load

from syn import syn_record


def test_sc_load_01_class_budget_not_laundered_by_big_per_record_max():
    # class budget is the MINIMUM max_chars declared in the class (SPEC):
    # a record declaring max_chars=50000 must not launder a 5000-char body
    # past the class budget of 10 declared by its sibling.
    big = syn_record(
        "big", "x" * 5000, priority="standard",
        max_chars=50000, on_budget_exceed="skip",
    )
    small = syn_record("small", "aa", priority="standard", max_chars=10)
    bundle = build_bundle("bundle-budget", records=[big, small])
    ids = [r["id"] for r in load([bundle])]
    assert "big" not in ids
    assert ids == ["small"]


def test_class_budget_aggregates_across_records():
    r1 = syn_record("r1", "0123456789", priority="standard", max_chars=13)
    r2 = syn_record(
        "r2", "abcdefgh", priority="standard",
        max_chars=13, on_budget_exceed="skip",
    )
    bundle = build_bundle("bundle-agg", records=[r1, r2])
    assert [r["id"] for r in load([bundle])] == ["r1"]


def test_class_budgets_are_independent_per_priority():
    crit = syn_record("c1", "0123456789", priority="critical", max_chars=10)
    std = syn_record("s1", "abcdefghij", priority="standard", max_chars=10)
    bundle = build_bundle("bundle-indep", records=[std, crit])
    ids = [r["id"] for r in load([bundle])]
    assert ids == ["c1", "s1"]
