"""SC-DEL-01/02/03: tombstones + lifecycle enforced on the LOAD path."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import build_bundle, load, make_tombstone

from syn import FIXED_TS, syn_record


def test_sc_del_01_load_applies_tombstone_within_same_bundle():
    bundle = build_bundle(
        "bundle-del",
        records=[syn_record("ghost", "should not load")],
        tombstones=[make_tombstone("ghost", "erased", deleted_at=FIXED_TS)],
    )
    assert load([bundle]) == []


def test_sc_del_02_cross_bundle_tombstone_blocks_resurrection():
    stale = build_bundle(
        "bundle-a-stale",
        records=[
            syn_record("rec-x", "stale copy"),
            syn_record("rec-y", "survivor"),
        ],
    )
    deleter = build_bundle(
        "bundle-b-del",
        tombstones=[make_tombstone("rec-x", "erased", deleted_at=FIXED_TS)],
    )
    # input order must not matter
    for bundles in ([stale, deleter], [deleter, stale]):
        ids = [r["id"] for r in load(bundles)]
        assert ids == ["rec-y"], f"input order {bundles[0]['bundle']['id']} first"


def test_sc_del_03_load_filters_lifecycle_deleted():
    bundle = build_bundle(
        "bundle-lc",
        records=[
            syn_record("live", "ok"),
            syn_record("dead", "gone", lifecycle="deleted"),
        ],
    )
    assert [r["id"] for r in load([bundle])] == ["live"]


def test_load_keeps_lifecycle_archived():
    bundle = build_bundle(
        "bundle-arch",
        records=[
            syn_record("active-rec", "ok"),
            syn_record("archived-rec", "old", lifecycle="archived"),
        ],
    )
    assert [r["id"] for r in load([bundle])] == ["active-rec", "archived-rec"]


def test_sc_del_04_cross_bundle_lifecycle_deleted_is_id_wide():
    # SPEC 1.2 (v0.1 precision pass): lifecycle="deleted" is an id-wide
    # deletion signal. An active copy of the id in another bundle used to
    # load; now every copy of the id is excluded.
    stale = build_bundle(
        "bundle-a-stale",
        records=[
            syn_record("rec-x", "stale active copy"),
            syn_record("rec-y", "survivor"),
        ],
    )
    deleter = build_bundle(
        "bundle-b-del",
        records=[syn_record("rec-x", "deleted copy", lifecycle="deleted")],
    )
    # input order must not matter
    for bundles in ([stale, deleter], [deleter, stale]):
        ids = [r["id"] for r in load(bundles)]
        assert ids == ["rec-y"], f"input order {bundles[0]['bundle']['id']} first"


def test_lifecycle_deleted_id_wide_across_three_bundles():
    a = build_bundle(
        "bundle-a",
        records=[syn_record("rec-x", "copy a"), syn_record("keep-a", "a")],
    )
    b = build_bundle(
        "bundle-b",
        records=[syn_record("rec-x", "deleted copy", lifecycle="deleted")],
    )
    c = build_bundle(
        "bundle-c",
        records=[syn_record("rec-x", "copy c"), syn_record("keep-c", "c")],
    )
    ids = sorted(r["id"] for r in load([c, a, b]))
    assert ids == ["keep-a", "keep-c"]


def test_lifecycle_deleted_archived_copies_unaffected():
    # archived records whose ids are NOT deleted anywhere still load —
    # only "deleted" lifecycle is a deletion signal.
    bundle = build_bundle(
        "bundle-arch-mix",
        records=[
            syn_record("arch", "old", lifecycle="archived"),
            syn_record("dead", "gone", lifecycle="deleted"),
        ],
    )
    assert [r["id"] for r in load([bundle])] == ["arch"]


def test_lifecycle_deleted_id_excludes_archived_copy_of_same_id():
    # Same treatment as tombstones: the exclusion is id-wide, so even an
    # archived copy of a deleted id cannot load.
    archived = build_bundle(
        "bundle-a-arch",
        records=[syn_record("rec-x", "archived copy", lifecycle="archived")],
    )
    deleter = build_bundle(
        "bundle-b-del",
        records=[syn_record("rec-x", "deleted copy", lifecycle="deleted")],
    )
    assert load([archived, deleter]) == []
