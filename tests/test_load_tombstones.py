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
