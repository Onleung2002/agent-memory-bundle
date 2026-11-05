"""SC-MERGE-01: mixed merge modes resolve deterministically (SPEC 1.1):
error_on_conflict anywhere -> MergeConflict; else if ALL copies declare
append_last_wins -> last wins; otherwise -> first wins."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import MergeConflict, build_bundle, canonical_bytes, load

from syn import assert_raises, syn_record


def test_sc_merge_01_mixed_first_and_last_resolves_first_wins():
    a = build_bundle(
        "bundle-a",
        records=[syn_record("dup", "from a", merge="append_first_wins")],
    )
    b = build_bundle(
        "bundle-b",
        records=[syn_record("dup", "from b", merge="append_last_wins")],
    )
    records = load([b, a])  # input order must not matter
    assert len(records) == 1
    assert records[0]["body"] == "from a"


def test_sc_merge_01_mixed_modes_deterministic_regardless_of_input_order():
    a = build_bundle(
        "bundle-a",
        records=[syn_record("dup", "from a", merge="append_last_wins")],
    )
    b = build_bundle(
        "bundle-b",
        records=[syn_record("dup", "from b", merge="append_first_wins")],
    )
    first = load([a, b])
    second = load([b, a])
    assert canonical_bytes(first) == canonical_bytes(second)


def test_sc_merge_01_error_on_conflict_dominates_mixed_group():
    a = build_bundle(
        "bundle-a",
        records=[syn_record("dup", "from a", merge="error_on_conflict")],
    )
    b = build_bundle(
        "bundle-b",
        records=[syn_record("dup", "from b", merge="append_last_wins")],
    )
    assert_raises(MergeConflict, load, [a, b])
