"""Tombstone-first import: deletions always win over additions."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import apply_tombstones, build_bundle, canonical_sha256, import_bundle, make_tombstone

from syn import FIXED_TS, syn_record


def test_apply_tombstones_removes_targeted_records():
    records = [syn_record("keep", "k"), syn_record("drop", "d")]
    tombs = [make_tombstone("drop", "synthetic", deleted_at=FIXED_TS)]
    remaining = apply_tombstones(records, tombs)
    assert [r["id"] for r in remaining] == ["keep"]


def test_tombstone_first_ordering_inside_single_bundle():
    # records listed "before" the tombstone in the manifest must still be
    # deleted: ordering inside the file must not change the outcome.
    bundle = build_bundle(
        "bundle-order",
        records=[syn_record("ghost", "should not survive")],
        tombstones=[make_tombstone("ghost", "deleted", deleted_at=FIXED_TS)],
    )
    store = import_bundle({"records": [], "tombstones": []}, bundle)
    assert store["records"] == []
    assert [t["target_id"] for t in store["tombstones"]] == ["ghost"]


def test_stale_bundle_cannot_resurrect_deleted_record():
    # store already knows rec-x was deleted...
    store = {
        "records": [syn_record("rec-y", "survivor")],
        "tombstones": [make_tombstone("rec-x", "erased", deleted_at=FIXED_TS)],
    }
    # ...a stale bundle still carries the deleted row (and no tombstone)
    stale = build_bundle("bundle-stale", records=[syn_record("rec-x", "stale copy")])
    merged = import_bundle(store, stale)
    ids = [r["id"] for r in merged["records"]]
    assert "rec-x" not in ids
    assert ids == ["rec-y"]
    assert "rec-x" in [t["target_id"] for t in merged["tombstones"]]


def test_incoming_tombstone_deletes_existing_store_record():
    store = {
        "records": [syn_record("rec-z", "about to be erased")],
        "tombstones": [],
    }
    bundle = build_bundle(
        "bundle-del",
        records=[],
        tombstones=[make_tombstone("rec-z", "erasure", deleted_at=FIXED_TS)],
    )
    merged = import_bundle(store, bundle)
    assert merged["records"] == []
    assert [t["target_id"] for t in merged["tombstones"]] == ["rec-z"]


def test_tombstone_dedup_keeps_latest_deleted_at():
    older = make_tombstone("rec-t", "first", deleted_at="2026-01-01T00:00:00Z")
    newer = make_tombstone("rec-t", "second", deleted_at="2026-06-01T00:00:00Z")
    store = {"records": [], "tombstones": [newer]}
    bundle = build_bundle("bundle-t", records=[], tombstones=[older])
    merged = import_bundle(store, bundle)
    assert len(merged["tombstones"]) == 1
    assert merged["tombstones"][0]["reason"] == "second"


def test_sc_del_04_tombstone_merge_unions_derived_artifacts():
    # L3 evidence must not shrink: merged tombstone carries the UNION of
    # derived_artifacts from every copy, not just the latest copy's list.
    older = make_tombstone(
        "rec-t", "first",
        deleted_at="2026-01-01T00:00:00Z",
        derived_artifacts=["chunk:rec-t:0"],
    )
    newer = make_tombstone(
        "rec-t", "second",
        deleted_at="2026-06-01T00:00:00Z",
        derived_artifacts=["emb:rec-t"],
    )
    store = {"records": [], "tombstones": [newer]}
    bundle = build_bundle("bundle-t2", records=[], tombstones=[older])
    merged = import_bundle(store, bundle)
    assert len(merged["tombstones"]) == 1
    winner = merged["tombstones"][0]
    assert winner["reason"] == "second"  # latest deleted_at wins
    assert sorted(winner["derived_artifacts"]) == ["chunk:rec-t:0", "emb:rec-t"]


def test_tombstone_dedupe_equal_deleted_at_tiebreaks_on_canonical_sha256():
    # A-16 (SPEC 1.2): copies with EQUAL deleted_at resolve by GREATEST
    # canonical SHA-256 of the tombstone — fully order-independent.
    copy_alpha = make_tombstone(
        "rec-tie", "copy-alpha",
        deleted_at="2026-06-01T00:00:00Z",
        derived_artifacts=["chunk:rec-tie:0"],
    )
    copy_beta = make_tombstone(
        "rec-tie", "copy-beta",
        deleted_at="2026-06-01T00:00:00Z",
        derived_artifacts=["emb:rec-tie"],
    )
    digests = {
        "copy-alpha": canonical_sha256(copy_alpha),
        "copy-beta": canonical_sha256(copy_beta),
    }
    expected_reason = max(digests, key=digests.get)

    merged_outputs = []
    for copies in ([copy_alpha, copy_beta], [copy_beta, copy_alpha]):
        merged = import_bundle(
            {"records": [], "tombstones": list(copies)},
            {"records": [], "tombstones": []},
        )
        assert len(merged["tombstones"]) == 1
        winner = merged["tombstones"][0]
        assert winner["reason"] == expected_reason  # digest-greater wins
        assert sorted(winner["derived_artifacts"]) == [
            "chunk:rec-tie:0",
            "emb:rec-tie",
        ]  # union, never shrunk
        merged_outputs.append(merged)

    # identical merged output under BOTH input orders
    assert merged_outputs[0] == merged_outputs[1]
