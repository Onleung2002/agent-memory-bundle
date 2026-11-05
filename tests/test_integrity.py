"""SC-INT-01: integrity digest verified on load; truncation re-digests."""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import build_bundle, canonical_bytes, load

from syn import syn_record


def test_sc_int_01_record_with_mismatched_digest_is_dropped():
    good = syn_record("rec-good", "valid body")
    bad = syn_record("rec-bad", "original body")
    bad["body"] = "tampered body"  # digest no longer matches body
    bundle = build_bundle("bundle-int", records=[good, bad])
    assert [r["id"] for r in load([bundle])] == ["rec-good"]


def test_sc_int_01_truncated_record_is_redigested_and_marked():
    bundle = build_bundle(
        "bundle-trunc",
        records=[
            syn_record("r1", "0123456789", priority="standard", max_chars=13),
            syn_record(
                "r2", "abcdefgh", priority="standard",
                max_chars=13, on_budget_exceed="truncate_last",
            ),
        ],
    )
    records = load([bundle])
    assert [r["id"] for r in records] == ["r1", "r2"]
    truncated = records[1]
    assert truncated["body"] == "abc"
    assert truncated["integrity"]["digest"] == hashlib.sha256(
        canonical_bytes("abc")
    ).hexdigest()
    assert truncated["integrity"]["truncated"] is True
    assert not records[0]["integrity"].get("truncated", False)


def test_untouched_records_keep_original_digest():
    record = syn_record("rec-orig", "untouched body")
    original_digest = record["integrity"]["digest"]
    records = load([build_bundle("bundle-orig", records=[record])])
    assert records[0]["integrity"]["digest"] == original_digest
