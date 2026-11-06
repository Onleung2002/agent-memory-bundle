"""SC-LOAD-02: duplicate bundle-id tiebreak is content-digest based."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import build_bundle, canonical_bytes, canonical_sha256, load, make_tombstone

from syn import FIXED_TS, syn_record


def _dup_manifests():
    m1 = build_bundle(
        "bundle-dup",
        records=[syn_record("rec-dup", "from manifest one", merge="append_last_wins")],
    )
    m2 = build_bundle(
        "bundle-dup",
        records=[syn_record("rec-dup", "from manifest two", merge="append_last_wins")],
        tombstones=[make_tombstone("unrelated", "x", deleted_at=FIXED_TS)],
    )
    assert canonical_sha256(m1) != canonical_sha256(m2)
    return m1, m2


def test_sc_load_02_duplicate_bundle_id_result_independent_of_input_order():
    m1, m2 = _dup_manifests()
    first = load([m1, m2])
    second = load([m2, m1])
    assert canonical_bytes(first) == canonical_bytes(second)


def test_sc_load_02_tiebreak_winner_is_greatest_content_digest():
    m1, m2 = _dup_manifests()
    # SPEC: ordering key is (bundle.id, canonical SHA-256 of the manifest);
    # append_last_wins therefore picks the copy from the manifest with the
    # lexicographically greatest digest.
    expected = m1 if canonical_sha256(m1) > canonical_sha256(m2) else m2
    records = load([m1, m2])
    assert len(records) == 1
    assert records[0]["body"] == expected["records"][0]["body"]
