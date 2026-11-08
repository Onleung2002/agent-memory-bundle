"""Receipt supersession (SPEC 1.2.2, M3 round 3, RFC Q4/Q5).

Covers the whole supersession contract:

- the single re-issue trigger: a delete() retry whose target is already
  gone, whose latest receipt fails verification SOLELY because known
  removals grew (recovery log / evidence) — the retry writes a NEW
  immutable receipt whose ``supersedes`` is the old receipt's digest and
  whose ``removed_records`` cover every known removal;
- chain semantics: only the chain TAIL can verify ok; every ``supersedes``
  link must resolve to a real, digest-matching, same-target receipt;
  broken links, digest-mismatched links, cross-target links and circular
  chains are all ok:false (cycle detection is a RUNTIME check — JSON
  Schema has no graph constraints);
- no whitewash: a superseded receipt verified alone stays ok:false with
  both the superseded and the under-report problems, and its file on disk
  is never modified (receipts are immutable; supersession is append-only);
- idempotency: retries without new removals return the chain tail and
  write nothing; fail-closed for every non-growth failure (a tampered
  latest receipt still raises DeletionIncompleteError, never a re-issue).
"""

import json
import tempfile
from pathlib import Path

from m2_helpers import DELETED_AT, OWNER

import mbcp.deletion as deletion_module

from mbcp import (
    DeletionIncompleteError,
    L1DeletionService,
    ReceiptValidationError,
    build_bundle,
    build_receipt,
    canonical_bytes,
    canonical_sha256,
    make_record,
    make_tombstone,
)

from syn import FIXED_TS, assert_raises


def _service(tmp):
    service = L1DeletionService(Path(tmp) / "service", clock=lambda: DELETED_AT)
    service.put_bundle(
        build_bundle(
            "bundle-alpha",
            records=[
                make_record(
                    "rec-001", "fact", "synthetic one", OWNER, created=FIXED_TS
                ),
                make_record(
                    "rec-002", "fact", "synthetic two", OWNER, created=FIXED_TS
                ),
            ],
        )
    )
    return service


def _grow_recovery(service, variant="STALE variant"):
    """Re-introduce rec-002 with a NOVEL digest and recover() it, so the
    recovery log records a removal the original receipt does not name."""
    stale = make_record(
        "rec-002", "fact", variant, OWNER, created=FIXED_TS
    )
    service.put_bundle(build_bundle("bundle-stale", records=[stale]))
    assert service.recover() == ["rec-002"]
    return stale["integrity"]["digest"]


def _receipt_path(service, receipt):
    return service.receipts_dir / f"{receipt['receipt']['id']}.json"


def _write_receipt(service, receipt):
    deletion_module._atomic_write(
        _receipt_path(service, receipt), canonical_bytes(receipt)
    )


def test_underreport_retry_reissues_superseding_receipt():
    # SPEC 1.2.2 main body: delete -> receipt ok; recover() grows known
    # removals past the receipt -> ok:false (under-report); delete() retry
    # re-issues a fresh receipt superseding the old one, covering ALL
    # known removals; the old receipt stays ok:false and untouched.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        r1 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert service.verify_receipt(r1)["ok"] is True
        original_digest = r1["receipt"]["removed_records"][0]["digest"]

        stale_digest = _grow_recovery(service)
        assert stale_digest != original_digest

        failing = service.verify_receipt(r1)
        assert failing["ok"] is False
        assert any("under-report" in p for p in failing["problems"])
        assert any(stale_digest in p for p in failing["problems"])

        r1_bytes = _receipt_path(service, r1).read_bytes()

        r2 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")

        # fresh artifact: new id, supersedes link, full accounting
        assert r2["receipt"]["id"] != r1["receipt"]["id"]
        assert r2["receipt"]["supersedes"] == r1["integrity"]["digest"]
        covered = {
            (r["id"], r["digest"]) for r in r2["receipt"]["removed_records"]
        }
        assert covered == {
            ("rec-002", original_digest),
            ("rec-002", stale_digest),
        }
        tail = service.verify_receipt(r2)
        assert tail["ok"] is True, tail

        # no whitewash: the superseded receipt still fails, twice over —
        # it is stale (superseded) AND it still under-reports.
        old = service.verify_receipt(r1)
        assert old["ok"] is False
        assert any("superseded" in p for p in old["problems"])
        assert any("under-report" in p for p in old["problems"])

        # immutability: re-issue is append-only; the old file is untouched
        assert _receipt_path(service, r1).read_bytes() == r1_bytes
        assert len(service.receipt_paths()) == 2


def test_retry_without_new_removals_issues_no_new_receipt():
    # Idempotency: once the chain tail accounts for everything, further
    # retries return it unchanged and write nothing.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        _grow_recovery(service)
        r2 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert len(service.receipt_paths()) == 2

        again = service.delete("bundle-alpha", "rec-002", "synthetic erasure")

        assert again == r2
        assert len(service.receipt_paths()) == 2


def test_second_growth_supersedes_the_superseding_receipt():
    # Multi-link chain: each genuine growth adds exactly one link; the
    # walk from the newest tail traverses the whole chain to the origin.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        r1 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        _grow_recovery(service)
        r2 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        _grow_recovery(service, variant="STALE variant two")
        r3 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")

        assert r3["receipt"]["supersedes"] == r2["integrity"]["digest"]
        assert r2["receipt"]["supersedes"] == r1["integrity"]["digest"]
        assert len(r3["receipt"]["removed_records"]) == 3
        assert service.verify_receipt(r3)["ok"] is True
        for stale in (r2, r1):
            result = service.verify_receipt(stale)
            assert result["ok"] is False
            assert any("superseded" in p for p in result["problems"])
        assert len(service.receipt_paths()) == 3


def test_broken_chain_link_to_nonexistent_receipt():
    # A supersedes link pointing at a digest no on-disk receipt has is a
    # broken chain — ok:false. (Receipt handed in directly; only the link
    # TARGET needs to be on disk.)
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        r1 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        tombstone = r1["receipt"]["tombstone"]
        removed = [
            {"id": "rec-002", "integrity": {"digest": "ab" * 32}},
        ]
        r2 = build_receipt(
            "bundle-alpha", tombstone, removed, supersedes="ff" * 32
        )
        result = service.verify_receipt(r2)
        assert result["ok"] is False
        assert any("broken supersession chain" in p for p in result["problems"])
        assert any("ff" * 32 in p for p in result["problems"])


def test_chain_link_to_digest_mismatched_receipt():
    # The link target exists but its body no longer hashes to the link
    # value (tampered in place, integrity not recomputed) — the chain is
    # broken, ok:false.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        r1 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        path = _receipt_path(service, r1)
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["receipt"]["removed_records"] = []  # body changed, digest stale
        path.write_text(json.dumps(tampered), encoding="utf-8")

        tombstone = r1["receipt"]["tombstone"]
        removed = [{"id": "rec-002", "integrity": {"digest": "ab" * 32}}]
        r2 = build_receipt(
            "bundle-alpha",
            tombstone,
            removed,
            supersedes=r1["integrity"]["digest"],
        )
        result = service.verify_receipt(r2)
        assert result["ok"] is False
        assert any("broken supersession chain" in p for p in result["problems"])
        assert any("tampered link" in p for p in result["problems"])


def test_circular_supersession_chain_detected():
    # Hand-built circular fixture: A -> B -> A. A fully self-consistent
    # cycle is cryptographically infeasible (it would need a SHA-256 fixed
    # point), so the fixture makes A claim B's predecessor-identity via a
    # stale self-digest; the walk must still catch the revisit.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        tombstone = make_tombstone(
            "rec-002", "synthetic erasure", deleted_at=DELETED_AT
        )
        removed = [{"id": "rec-002", "integrity": {"digest": "ab" * 32}}]
        fake_digest = "bb" * 32
        b = build_receipt("bundle-alpha", tombstone, removed, supersedes=fake_digest)
        a = build_receipt(
            "bundle-alpha",
            tombstone,
            removed,
            supersedes=b["integrity"]["digest"],
        )
        a["integrity"]["digest"] = fake_digest
        _write_receipt(service, b)
        _write_receipt(service, a)

        result = service.verify_receipt(a)
        assert result["ok"] is False
        assert any("circular" in p for p in result["problems"])


def test_supersession_chain_crossing_targets_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        other_tomb = make_tombstone(
            "rec-999", "other target erasure", deleted_at=DELETED_AT
        )
        other_removed = [{"id": "rec-999", "integrity": {"digest": "cd" * 32}}]
        other = build_receipt("bundle-alpha", other_tomb, other_removed)
        _write_receipt(service, other)
        tombstone = make_tombstone(
            "rec-002", "synthetic erasure", deleted_at=DELETED_AT
        )
        removed = [{"id": "rec-002", "integrity": {"digest": "ab" * 32}}]
        r2 = build_receipt(
            "bundle-alpha",
            tombstone,
            removed,
            supersedes=other["integrity"]["digest"],
        )
        result = service.verify_receipt(r2)
        assert result["ok"] is False
        assert any("crosses target" in p for p in result["problems"])


def test_schema_rejects_malformed_supersedes():
    # The schema gate gets ONLY the hex64 format pattern (per Isaac's
    # ruling); graph constraints live in verify_receipt.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        r1 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        tombstone = r1["receipt"]["tombstone"]
        removed = [{"id": "rec-002", "integrity": {"digest": "ab" * 32}}]
        assert_raises(
            ReceiptValidationError,
            build_receipt,
            "bundle-alpha",
            tombstone,
            removed,
            supersedes="not-hex",
        )
        assert_raises(
            ReceiptValidationError,
            build_receipt,
            "bundle-alpha",
            tombstone,
            removed,
            supersedes="ab" * 31,  # too short
        )


def test_tampered_latest_receipt_stays_deletion_incomplete():
    # Fail-closed: re-issue heals ONLY accounted growth. A tampered latest
    # receipt (self-digest mismatch) still raises DeletionIncompleteError
    # and writes nothing.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        r1 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        path = _receipt_path(service, r1)
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["receipt"]["reason"] = "laundered reason"
        path.write_text(json.dumps(tampered), encoding="utf-8")

        assert_raises(
            DeletionIncompleteError,
            service.delete,
            "bundle-alpha",
            "rec-002",
            "synthetic erasure",
        )
        assert len(service.receipt_paths()) == 1


def test_receipt_without_supersedes_has_no_chain_field():
    # Optional field: a first-issue receipt carries no supersedes key at
    # all (and still verifies ok — no chain logic leaks into legacy flow).
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        r1 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert "supersedes" not in r1["receipt"]
        assert service.verify_receipt(r1)["ok"] is True


def test_reissued_receipt_rebinds_journal_and_evidence():
    # The superseding receipt is held to the SAME durable bindings as any
    # receipt: journal tombstone, per-tombstone-digest evidence, and the
    # recovery log. Verification failure messages name the union.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        stale_digest = _grow_recovery(service)
        r2 = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert service.verify_receipt(r2)["ok"] is True
        # the recovery-log binding is what the re-issue healed: dropping
        # the recovered digest from the claim must fail verification.
        broken = json.loads(json.dumps(r2))
        broken["receipt"]["removed_records"] = [
            r for r in broken["receipt"]["removed_records"]
            if r["digest"] != stale_digest
        ]
        broken["integrity"]["digest"] = canonical_sha256(broken["receipt"])
        result = service.verify_receipt(broken)
        assert result["ok"] is False
        assert any("under-report" in p for p in result["problems"])
