"""Tombstone-first import: deletions always win over additions."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import (
    TombstonedIdRejectedError,
    apply_tombstones,
    build_bundle,
    canonical_sha256,
    import_bundle,
    make_tombstone,
)

from syn import FIXED_TS, assert_raises, syn_record


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


def test_stale_bundle_copy_of_store_tombstoned_id_is_rejected():
    # UPDATED-PIN (M4 round C1, SPEC 1.2 write boundary, audit §6): the
    # old semantics silently FILTERED an incoming copy of a store-
    # tombstoned id; the tightened semantics REJECT the ingest with a
    # typed error naming the id — resurrection is closed at the write
    # boundary, not just at load time.
    store = {
        "records": [syn_record("rec-y", "survivor")],
        "tombstones": [make_tombstone("rec-x", "erased", deleted_at=FIXED_TS)],
    }
    stale = build_bundle("bundle-stale", records=[syn_record("rec-x", "stale copy")])
    assert_raises(TombstonedIdRejectedError, import_bundle, store, stale)
    try:
        import_bundle(store, stale)
    except TombstonedIdRejectedError as err:
        assert "rec-x" in str(err)
    else:
        raise AssertionError("expected TombstonedIdRejectedError")


def test_import_still_accepts_untombstoned_incoming_ids():
    # audit §6 probe, control: a DIFFERENT incoming id is accepted.
    store = {
        "records": [],
        "tombstones": [make_tombstone("rec-x", "erased", deleted_at=FIXED_TS)],
    }
    fresh = build_bundle(
        "bundle-fresh",
        records=[syn_record("rec-y", "unrelated")],
    )
    merged = import_bundle(store, fresh)
    assert [r["id"] for r in merged["records"]] == ["rec-y"]


def test_incoming_bundles_own_tombstone_still_filters_silently():
    # Importer contract (SPEC 1.2/§4): a bundle that carries the tombstone
    # for a row it still lists is NOT a resurrection attempt — the write
    # boundary only gates on the STORE journal; the bundle's own tombstone
    # silently wins over its stale row (tombstone-first, unchanged).
    store = {"records": [], "tombstones": []}
    bundle = build_bundle(
        "bundle-order",
        records=[syn_record("ghost", "should not survive")],
        tombstones=[make_tombstone("ghost", "deleted", deleted_at=FIXED_TS)],
    )
    merged = import_bundle(store, bundle)
    assert merged["records"] == []


def test_apply_tombstones_nfc_normalizes_both_sides():
    # SPEC 1.5 / audit §12: tombstone target vs record id comparison is
    # NFC-normalized on both sides — an NFD variant of the target cannot
    # survive the filter, and ids pass through verbatim. (Pinned here
    # because apply_tombstones takes raw dicts: the load/build grammar
    # gates reject non-ASCII record ids before this point, so this is the
    # one place the NFD attack shape is reachable.)
    nfc_id = "caf\u00e9"  # composed (single code point)
    nfd_id = "cafe\u0301"  # decomposed (e + combining acute) \u2014 distinct bytes
    assert nfc_id != nfd_id
    # the grammar gates reject non-ASCII record ids at build/load time, so
    # construct these raw copies by id-swap (integrity binds the body only,
    # and apply_tombstones/import_bundle are the raw comparison layer).
    nfc_copy = syn_record("placeholder", "composed body")
    nfc_copy["id"] = nfc_id
    nfd_copy = syn_record("placeholder", "decomposed body")
    nfd_copy["id"] = nfd_id
    tomb = make_tombstone(nfc_id, "erased", deleted_at=FIXED_TS)
    remaining = apply_tombstones([nfc_copy, nfd_copy], [tomb])
    assert remaining == []
    # controls: NFC tombstone still filters an NFC id; verbatim ids keep
    # their original byte form in survivors
    other = apply_tombstones([nfd_copy], [make_tombstone("other", "x", deleted_at=FIXED_TS)])
    assert [r["id"] for r in other] == [nfd_id]
    nfc_only = apply_tombstones([nfc_copy], [tomb])
    assert nfc_only == []


def test_import_bundle_nfc_normalized_rejection():
    # SPEC 1.5 / audit §12, ingest side: the store tombstone comparison is
    # NFC-normalized — an NFD record id under an NFC store tombstone is
    # rejected, and vice versa.
    nfc_id = "caf\u00e9"  # composed (single code point)
    nfd_id = "cafe\u0301"  # decomposed (e + combining acute) — distinct bytes
    store = {
        "records": [],
        "tombstones": [make_tombstone(nfc_id, "erased", deleted_at=FIXED_TS)],
    }
    nfd_record = syn_record("placeholder", "decomposed stale copy")
    nfd_record["id"] = nfd_id
    bundle = {"records": [nfd_record], "tombstones": []}
    assert_raises(TombstonedIdRejectedError, import_bundle, store, bundle)
    # reverse direction: NFD tombstone target, NFC record id
    store2 = {
        "records": [],
        "tombstones": [make_tombstone(nfd_id, "erased", deleted_at=FIXED_TS)],
    }
    nfc_record = syn_record("placeholder", "composed stale copy")
    nfc_record["id"] = nfc_id
    assert_raises(
        TombstonedIdRejectedError,
        import_bundle,
        store2,
        {"records": [nfc_record], "tombstones": []},
    )


def test_case_variants_of_ids_stay_distinct():
    # SPEC 1.5 known residual: NFC does NOT casefold — 'Rec-1' and 'rec-1'
    # are different ids; a tombstone for one must not filter the other.
    tomb = make_tombstone("Rec-1", "erased", deleted_at=FIXED_TS)
    lower = syn_record("rec-1", "lower copy")
    upper = syn_record("Rec-1", "upper copy")
    remaining = apply_tombstones([lower, upper], [tomb])
    assert [r["id"] for r in remaining] == ["rec-1"]


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
