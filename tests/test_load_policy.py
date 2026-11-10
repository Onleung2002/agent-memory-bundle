"""load_policy adjudication: determinism, budget behaviors, merge modes."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import BudgetExceeded, MergeConflict, build_bundle, load, load_bytes

from syn import assert_raises, syn_bundle_a, syn_bundle_b, syn_record


def test_load_byte_identical_across_invocations():
    bundles = [syn_bundle_a(), syn_bundle_b()]
    first = load_bytes(bundles)
    second = load_bytes([syn_bundle_a(), syn_bundle_b()])
    assert first == second


def test_priority_ordering_critical_standard_opportunistic():
    records = load([syn_bundle_a(), syn_bundle_b()])
    priorities = [r["mbcp"]["load_policy"]["priority"] for r in records]
    assert priorities == ["critical", "critical", "standard", "standard", "opportunistic"]


def test_on_budget_exceed_truncate_last():
    bundle = build_bundle(
        "bundle-trunc",
        records=[
            syn_record("r1", "0123456789", priority="standard", max_chars=13),
            syn_record(
                "r2",
                "abcdefgh",
                priority="standard",
                max_chars=13,
                on_budget_exceed="truncate_last",
            ),
        ],
    )
    records = load([bundle])
    assert [r["id"] for r in records] == ["r1", "r2"]
    assert records[1]["body"] == "abc"  # 13 - 10 = 3 chars remaining


def test_on_budget_exceed_skip():
    bundle = build_bundle(
        "bundle-skip",
        records=[
            syn_record("r1", "0123456789", priority="standard", max_chars=10),
            syn_record(
                "r2", "abcdef", priority="standard", max_chars=10,
                on_budget_exceed="skip",
            ),
        ],
    )
    records = load([bundle])
    assert [r["id"] for r in records] == ["r1"]


def test_on_budget_exceed_error():
    bundle = build_bundle(
        "bundle-err",
        records=[
            syn_record("r1", "0123456789", priority="critical", max_chars=10),
            syn_record(
                "r2", "abcdef", priority="critical", max_chars=10,
                on_budget_exceed="error",
            ),
        ],
    )
    assert_raises(BudgetExceeded, load, [bundle])


def test_merge_append_first_wins():
    # NOTE (M4 round C1): "append_first_wins" no longer resolves by
    # bundle-id order — uniform first-wins groups resolve by the SPEC 1.2
    # duplicate tiebreak (greatest canonical SHA-256 of the record, audit
    # §9). This fixture pins the tiebreak outcome: "body from bundle-a"
    # wins because its record digest is the larger one, not because its
    # bundle id sorts first.
    first = build_bundle(
        "bundle-a",
        records=[syn_record("dup", "body from bundle-a", merge="append_first_wins")],
    )
    second = build_bundle(
        "bundle-b",
        records=[syn_record("dup", "body from bundle-b", merge="append_first_wins")],
    )
    from mbcp import canonical_sha256

    assert canonical_sha256(first["records"][0]) > canonical_sha256(
        second["records"][0]
    )
    records = load([second, first])  # input order must not matter
    assert len(records) == 1
    assert records[0]["body"] == "body from bundle-a"


def test_merge_append_last_wins():
    first = build_bundle(
        "bundle-a",
        records=[syn_record("dup", "body from bundle-a", merge="append_last_wins")],
    )
    second = build_bundle(
        "bundle-b",
        records=[syn_record("dup", "body from bundle-b", merge="append_last_wins")],
    )
    records = load([first, second])
    assert len(records) == 1
    assert records[0]["body"] == "body from bundle-b"


def test_merge_error_on_conflict():
    first = build_bundle(
        "bundle-a",
        records=[syn_record("dup", "body from bundle-a", merge="error_on_conflict")],
    )
    second = build_bundle(
        "bundle-b",
        records=[syn_record("dup", "body from bundle-b", merge="append_first_wins")],
    )
    assert_raises(MergeConflict, load, [first, second])
