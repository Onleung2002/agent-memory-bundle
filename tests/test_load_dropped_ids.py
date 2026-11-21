"""A-21 dropped-ids channel (v0.2 API amendment 1, SPEC §3a).

load() returns a LoadResult(records, dropped_ids). dropped_ids reports
records dropped for integrity/validity failure (digest mismatch,
non-string body); policy filtering (tombstones, authentic deleted
signals, budget skip, truncate with nothing left) is NOT reported.
Every pin here is exercised with a poison fixture that would fail if
the reported behavior were absent (e.g. an empty dropped_ids where a
drop is expected).
"""

import sys
from pathlib import Path

import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import mbcp.bundle as bundle_module
from mbcp import (
    LoadResult,
    build_bundle,
    canonical_bytes,
    load,
    load_bytes,
    make_tombstone,
)

from syn import FIXED_TS, syn_record


def _bad_digest_copy(record):
    """A copy of `record` whose integrity digest no longer matches its
    body (first hex char flipped — always differs from the real digest)."""
    bad = dict(record)
    digest = record["integrity"]["digest"]
    bad["integrity"] = {
        "algo": "sha256",
        "digest": ("0" if digest[0] != "0" else "1") + digest[1:],
    }
    return bad


def test_load_returns_load_result_with_named_fields():
    bundle = build_bundle("b-shape", records=[syn_record("rec-a", "body a")])
    result = load([bundle])
    assert isinstance(result, LoadResult)
    assert isinstance(result.records, list)
    assert isinstance(result.dropped_ids, list)
    assert [r["id"] for r in result.records] == ["rec-a"]
    assert result.dropped_ids == []


def test_digest_failed_record_is_reported_not_silently_discarded():
    good = syn_record("rec-good", "untouched body")
    bad = _bad_digest_copy(syn_record("rec-bad", "forged body"))
    bundle = build_bundle("b-digest", records=[good, bad])
    result = load([bundle])
    assert [r["id"] for r in result.records] == ["rec-good"]
    # poison: a removed channel would leave this empty and fail here
    assert result.dropped_ids == ["rec-bad"]


def test_dropped_ids_are_sorted_deduped_and_normalized():
    # normalize_id() ASCII-case-folds: "DRP-B" and "drp-b" are one id;
    # two bad copies of "drp-a" collapse to a single entry; output is
    # sorted by codepoint order of the normalized id.
    b_upper = _bad_digest_copy(syn_record("DRP-B", "copy one"))
    a_lower = _bad_digest_copy(syn_record("drp-a", "copy two"))
    a_upper = _bad_digest_copy(syn_record("DRP-A", "copy three"))
    b1 = build_bundle("b-sdn-1", records=[b_upper, a_lower])
    b2 = build_bundle("b-sdn-2", records=[a_upper])
    result = load([b1, b2])
    assert result.records == []
    assert result.dropped_ids == ["drp-a", "drp-b"]


def test_non_string_body_drop_is_reported():
    # A-07: digest VALID but body not a string -> dropped and reported.
    # The build path rejects non-string bodies (SPEC 1.5), so swap the
    # body after build and re-digest — the digest itself stays valid.
    good = syn_record("rec-good", "ordinary body")
    numeric = syn_record("rec-obj", "placeholder")
    numeric["body"] = {"not": "a string"}
    numeric["integrity"]["digest"] = hashlib.sha256(
        canonical_bytes({"not": "a string"})
    ).hexdigest()
    manifest = build_bundle("b-nonstr", records=[good])
    manifest["records"].append(numeric)
    result = load([manifest])
    assert [r["id"] for r in result.records] == ["rec-good"]
    assert result.dropped_ids == ["rec-obj"]


def test_same_id_merge_winner_and_dropped_copy_appear_on_both_sides():
    winner = syn_record("rec-dup", "authentic copy")
    forged = _bad_digest_copy(syn_record("rec-dup", "forged copy"))
    b1 = build_bundle("b-both-1", records=[winner])
    b2 = build_bundle("b-both-2", records=[forged])
    result = load([b1, b2])
    assert [r["id"] for r in result.records] == ["rec-dup"]
    assert result.records[0]["body"] == "authentic copy"
    assert result.dropped_ids == ["rec-dup"]


def test_digest_failed_deleted_copy_reports_and_produces_no_signal():
    # A tampered lifecycle="deleted" copy yields NO id-wide deletion
    # signal (audit §10) AND is reported in dropped_ids; the live copy
    # of the same id elsewhere still loads.
    tampered = syn_record("rec-x", "deleted but forged", lifecycle="deleted")
    tampered = _bad_digest_copy(tampered)
    live = syn_record("rec-x", "live body")
    b_deleted = build_bundle("b-del", records=[tampered])
    b_live = build_bundle("b-live", records=[live])
    result = load([b_deleted, b_live])
    assert [r["id"] for r in result.records] == ["rec-x"]
    assert result.records[0]["body"] == "live body"
    assert result.dropped_ids == ["rec-x"]


def test_tombstoned_id_is_not_in_dropped_ids():
    gone = syn_record("rec-gone", "still digest-valid, but tombstoned")
    ok = syn_record("rec-ok", "survivor")
    bundle = build_bundle(
        "b-tomb",
        records=[gone, ok],
        tombstones=[make_tombstone("rec-gone", "erasure", deleted_at=FIXED_TS)],
    )
    result = load([bundle])
    assert [r["id"] for r in result.records] == ["rec-ok"]
    # policy filtering, not an integrity failure: nothing to report
    assert result.dropped_ids == []


def test_authentic_deleted_signal_is_not_in_dropped_ids():
    authentic = syn_record("rec-y", "real deletion signal", lifecycle="deleted")
    other = syn_record("rec-z", "unrelated live record")
    bundle = build_bundle("b-autodel", records=[authentic, other])
    result = load([bundle])
    assert [r["id"] for r in result.records] == ["rec-z"]
    assert result.dropped_ids == []


def test_budget_skip_is_not_in_dropped_ids():
    big = syn_record(
        "big", "x" * 100, priority="standard",
        max_chars=100, on_budget_exceed="skip",
    )
    small = syn_record("small", "aa", priority="standard", max_chars=10)
    bundle = build_bundle("b-skip", records=[big, small])
    result = load([bundle])
    assert [r["id"] for r in result.records] == ["small"]
    # skip is declared load_policy, not an integrity failure
    assert result.dropped_ids == []


def test_truncate_last_with_nothing_left_is_not_in_dropped_ids():
    r1 = syn_record(
        "r1", "12345", priority="standard",
        max_chars=5, on_budget_exceed="truncate_last",
    )
    r2 = syn_record(
        "r2", "xx", priority="standard",
        max_chars=5, on_budget_exceed="truncate_last",
    )
    bundle = build_bundle("b-trunc", records=[r1, r2])
    result = load([bundle])
    assert [r["id"] for r in result.records] == ["r1"]
    assert result.records[0]["body"] == "12345"
    assert result.dropped_ids == []


def test_dropped_ids_are_deterministic_across_input_orders():
    def _set():
        b1 = build_bundle(
            "b-det-1",
            records=[_bad_digest_copy(syn_record("drp-c", "forged c"))],
        )
        b2 = build_bundle(
            "b-det-2",
            records=[
                syn_record("rec-live", "live body"),
                _bad_digest_copy(syn_record("drp-a", "forged a")),
            ],
        )
        b3 = build_bundle(
            "b-det-3",
            records=[_bad_digest_copy(syn_record("drp-b", "forged b"))],
        )
        return b1, b2, b3

    b1, b2, b3 = _set()
    first = load([b1, b2, b3])
    second = load([b3, b2, b1])
    assert first.dropped_ids == ["drp-a", "drp-b", "drp-c"]
    assert second.dropped_ids == ["drp-a", "drp-b", "drp-c"]
    assert canonical_bytes(first.records) == canonical_bytes(second.records)


def test_load_bytes_serializes_records_only():
    good = syn_record("rec-good", "untouched body")
    bad = _bad_digest_copy(syn_record("rec-bad", "forged body"))
    bundle = build_bundle("b-bytes", records=[good, bad])
    assert load_bytes([bundle]) == canonical_bytes(load([bundle]).records)


def test_load_docstring_states_dropped_ids_honestly():
    doc = bundle_module.load.__doc__
    assert "dropped-ids are reported, not silently discarded" in doc
    # capability boundary: a report channel, not an interception mechanism
    assert "report channel only" in doc
