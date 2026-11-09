"""SC-MERGE-01: mixed merge modes resolve deterministically (SPEC 1.1 +
SPEC 1.2 duplicate tiebreak, v0.1 audit §9, M4 round C1):
error_on_conflict anywhere -> MergeConflict; else if ALL copies declare
append_last_wins -> last wins; EVERY other group (uniform first-wins or
mixed) -> the copy with the GREATEST canonical SHA-256 of the record
wins — order-independent, so an attacker can no longer pick bundle names
to make a stale copy win."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import (
    MergeConflict,
    build_bundle,
    canonical_bytes,
    canonical_sha256,
    load,
)

from syn import assert_raises, syn_record


def test_sc_merge_01_mixed_first_and_last_resolves_by_record_digest():
    # UPDATED-PIN (M4 round C1, SPEC 1.2 duplicate tiebreak, audit §9):
    # the old semantics pinned "mixed modes -> first wins" (bundle-id
    # order). The tightened semantics resolve ANY group without a
    # unanimous declared mode by the GREATEST canonical SHA-256 of the
    # record — here "from b" wins because its record digest is larger,
    # regardless of input order.
    a = build_bundle(
        "bundle-a",
        records=[syn_record("dup", "from a", merge="append_first_wins")],
    )
    b = build_bundle(
        "bundle-b",
        records=[syn_record("dup", "from b", merge="append_last_wins")],
    )
    winner = (
        "from a"
        if canonical_sha256(a["records"][0]) > canonical_sha256(b["records"][0])
        else "from b"
    )
    assert winner == "from b"
    for bundles in ([b, a], [a, b]):
        records = load(bundles)
        assert len(records) == 1
        assert records[0]["body"] == "from b"


def test_sc_merge_01_attack_stale_aaa_bundle_cannot_win_by_name():
    # audit §9 attack, pinned: the stale copy lives in "aaa-stale", the
    # fresh copy in "zzz-fresh"; both declare the (default) first-wins
    # mode. Bundle-id first-wins would let the ATTACKER-CHOSEN name pick
    # the stale copy; the content-digest tiebreak picks by the records
    # alone, and both input orders are byte-identical.
    # body choice matters: the tiebreak is content-based, so this fixture
    # pins the attack flip concretely — the fresh copy's record digest is
    # LARGER (verified), hence the old bundle-id first-wins would have
    # served the attacker the stale copy from "aaa-stale".
    stale = build_bundle(
        "aaa-stale",
        records=[syn_record("dup", "STALE copy")],
    )
    fresh = build_bundle(
        "zzz-fresh",
        records=[syn_record("dup", "fresh legitimate copy")],
    )
    assert canonical_sha256(fresh["records"][0]) > canonical_sha256(
        stale["records"][0]
    )
    first = load([stale, fresh])
    second = load([fresh, stale])
    assert canonical_bytes(first) == canonical_bytes(second)
    assert len(first) == 1
    assert first[0]["body"] == "fresh legitimate copy"


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
