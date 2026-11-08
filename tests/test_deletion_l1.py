"""L1 deletion service: tombstone-first delete, receipts, crash recovery."""

import json
import tempfile
from pathlib import Path

from m2_helpers import DELETED_AT, IMPORTED_AT

import mbcp.deletion as deletion_module

from mbcp import (
    DeletionError,
    DeletionIncompleteError,
    L1DeletionService,
    UnknownTargetError,
    build_bundle,
    canonical_bytes,
    canonical_sha256,
    load,
    make_record,
    make_tombstone,
)

from syn import FIXED_TS, OWNER, assert_raises


def _manifest():
    records = [
        make_record("rec-001", "fact", "synthetic one", OWNER, created=FIXED_TS),
        make_record("rec-002", "fact", "synthetic two", OWNER, created=FIXED_TS),
        make_record("rec-003", "fact", "synthetic three", OWNER, created=FIXED_TS),
    ]
    return build_bundle("bundle-alpha", records=records)


def _service(tmp, manifest=None):
    service = L1DeletionService(Path(tmp) / "service", clock=lambda: DELETED_AT)
    service.put_bundle(manifest or _manifest())
    return service


def test_put_bundle_roundtrips_canonical_bytes():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        path = service.bundle_path("bundle-alpha")
        assert path.read_bytes() == canonical_bytes(_manifest())
        assert service.get_bundle("bundle-alpha") == _manifest()


def test_delete_removes_only_target_record():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure request")
        manifest = service.get_bundle("bundle-alpha")
        assert [r["id"] for r in manifest["records"]] == ["rec-001", "rec-003"]


def test_delete_appends_valid_tombstone_to_journal():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure request")
        journal = service.journal_tombstones()
        assert len(journal) == 1
        tomb = journal[0]
        assert tomb["target_id"] == "rec-002"
        assert tomb["deleted_at"] == DELETED_AT
        assert tomb["reason"] == "synthetic erasure request"


def test_delete_keeps_tombstone_in_manifest():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure request")
        manifest = service.get_bundle("bundle-alpha")
        assert [t["target_id"] for t in manifest["tombstones"]] == ["rec-002"]


def test_receipt_structure_is_l1_and_honest():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete(
            "bundle-alpha",
            "rec-002",
            "synthetic erasure request",
            derived_artifacts=["chunk:rec-002:0", "emb:rec-002"],
        )
        body = receipt["receipt"]
        assert body["level"] == "L1"
        assert body["spec_version"] == "0.1"
        assert body["bundle_id"] == "bundle-alpha"
        assert body["target_id"] == "rec-002"
        assert body["derived_artifacts"] == ["chunk:rec-002:0", "emb:rec-002"]
        assert body["derived_artifacts_verified"] is False
        assert body["propagation"] == {"propagated_to": []}
        # Honesty, not constant-copying: the prose must disclose L1 scope,
        # unverified derived-artifact erasure (L3) and non-certificate (L4).
        limitations = " ".join(body["limitations"]).lower()
        assert "l1 only" in limitations
        assert "l3" in limitations and "not verified" in limitations
        assert "l4" in limitations and "certificate" in limitations
        assert body["tombstone"]["target_id"] == "rec-002"
        assert body["tombstone_digest"] == canonical_sha256(body["tombstone"])
        assert body["issued_at"] == DELETED_AT


def test_receipt_records_removed_record_digest():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        original = {r["id"]: r for r in _manifest()["records"]}
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        removed = receipt["receipt"]["removed_records"]
        assert removed == [
            {"id": "rec-002", "digest": original["rec-002"]["integrity"]["digest"]}
        ]


def test_receipt_self_digest_matches_body():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert receipt["integrity"]["algo"] == "sha256"
        assert receipt["integrity"]["digest"] == canonical_sha256(receipt["receipt"])


def test_receipt_file_written_under_its_id():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        path = service.receipts_dir / f"{receipt['receipt']['id']}.json"
        assert path.exists()
        assert json.loads(path.read_text(encoding="utf-8")) == receipt


def test_verify_receipt_ok_after_delete():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        result = service.verify_receipt(receipt)
        assert result["ok"] is True, result
        assert result["problems"] == []
        assert result["receipt_id"] == receipt["receipt"]["id"]


def test_verify_receipt_accepts_path():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        path = service.receipts_dir / f"{receipt['receipt']['id']}.json"
        assert service.verify_receipt(path)["ok"] is True


def test_repeat_delete_is_idempotent():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        first = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        second = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert second["receipt"]["id"] == first["receipt"]["id"]
        assert len(service.journal_tombstones()) == 1
        assert len(service.receipt_paths()) == 1


def test_delete_unknown_target_raises():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        assert_raises(
            UnknownTargetError,
            service.delete,
            "bundle-alpha",
            "rec-404",
            "synthetic erasure",
        )
        assert service.journal_tombstones() == []


def test_tampered_receipt_fails_verification():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        tampered = json.loads(json.dumps(receipt))
        tampered["receipt"]["reason"] = "rewritten reason"
        result = service.verify_receipt(tampered)
        assert result["ok"] is False
        assert any("tampered" in problem for problem in result["problems"])


def test_receipt_fails_if_target_record_still_present():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        service.put_bundle(_manifest())  # stale copy restored, journal untouched
        result = service.verify_receipt(receipt)
        assert result["ok"] is False
        assert any("still present" in problem for problem in result["problems"])


def test_deleted_record_is_gone_from_load():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        ids = [r["id"] for r in load([service.get_bundle("bundle-alpha")])]
        assert ids == ["rec-001", "rec-003"]


def test_journal_is_append_only_and_monotonic():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-001", "first erasure")
        service.delete("bundle-alpha", "rec-003", "second erasure")
        targets = [t["target_id"] for t in service.journal_tombstones()]
        assert targets == ["rec-001", "rec-003"]
        assert len(service.receipt_paths()) == 2


def test_tombstone_is_durable_before_manifest_rewrite():
    # The core tombstone-first promise: if the manifest rewrite crashes, the
    # tombstone must already be on disk, and recovery must finish the delete.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        original_atomic_write = deletion_module._atomic_write

        def exploding_atomic_write(path, data):
            if "bundles" in str(path):
                raise OSError("simulated crash before manifest rewrite")
            return original_atomic_write(path, data)

        deletion_module._atomic_write = exploding_atomic_write
        try:
            assert_raises(
                OSError,
                service.delete,
                "bundle-alpha",
                "rec-002",
                "synthetic crash erasure",
            )
        finally:
            deletion_module._atomic_write = original_atomic_write

        # tombstone survived, manifest did not change, no receipt was written
        assert [t["target_id"] for t in service.journal_tombstones()] == ["rec-002"]
        assert "rec-002" in [r["id"] for r in service.get_bundle("bundle-alpha")["records"]]
        assert service.receipt_paths() == []

        # recovery closes the gap
        assert service.recover() == ["rec-002"]
        assert "rec-002" not in [
            r["id"] for r in service.get_bundle("bundle-alpha")["records"]
        ]


def test_recovery_replays_journal_after_simulated_crash():
    # Simulate a crash after the journal fsync but before the manifest rewrite:
    # the journal has the tombstone, the manifest still carries the record.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        tombstone = make_tombstone(
            "rec-002", "synthetic crash erasure", deleted_at=IMPORTED_AT
        )
        with open(service.journal_path, "ab") as fh:
            fh.write(canonical_bytes(tombstone) + b"\n")
        assert "rec-002" in [r["id"] for r in service.get_bundle("bundle-alpha")["records"]]

        removed = service.recover()

        assert removed == ["rec-002"]
        manifest = service.get_bundle("bundle-alpha")
        assert "rec-002" not in [r["id"] for r in manifest["records"]]
        assert "rec-002" in [t["target_id"] for t in manifest["tombstones"]]


def test_recovery_is_noop_on_consistent_state():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert service.recover() == []
        assert [r["id"] for r in service.get_bundle("bundle-alpha")["records"]] == [
            "rec-001",
            "rec-003",
        ]


def test_recovery_adds_journal_tombstone_to_untouched_manifest():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        tombstone = make_tombstone("rec-999", "never existed here", deleted_at=IMPORTED_AT)
        with open(service.journal_path, "ab") as fh:
            fh.write(canonical_bytes(tombstone) + b"\n")
        service.recover()
        manifest = service.get_bundle("bundle-alpha")
        assert len(manifest["records"]) == 3
        assert "rec-999" in [t["target_id"] for t in manifest["tombstones"]]


def test_derived_artifacts_from_journal_survive_merge():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete(
            "bundle-alpha",
            "rec-002",
            "synthetic erasure",
            derived_artifacts=["chunk:rec-002:0"],
        )
        merged = service.all_tombstones()
        assert merged[0]["derived_artifacts"] == ["chunk:rec-002:0"]


# ---------------------------------------------------------------------------
# Regression tests for the verifier's two MAJOR findings (M2 fix round).
# ---------------------------------------------------------------------------


def _cross_bundle_service(tmp):
    """Two bundles under one service root sharing the same record id."""
    service = L1DeletionService(Path(tmp) / "service", clock=lambda: DELETED_AT)
    service.put_bundle(
        build_bundle(
            "bundle-a",
            records=[
                make_record("rec-001", "fact", "alpha one", OWNER, created=FIXED_TS),
                make_record("rec-002", "fact", "alpha two", OWNER, created=FIXED_TS),
            ],
        )
    )
    service.put_bundle(
        build_bundle(
            "bundle-b",
            records=[
                make_record("rec-002", "fact", "beta two", OWNER, created=FIXED_TS),
                make_record("rec-009", "fact", "beta nine", OWNER, created=FIXED_TS),
            ],
        )
    )
    return service


def _ids(service, bundle_id):
    return [r["id"] for r in service.get_bundle(bundle_id)["records"]]


def test_delete_retry_after_crash_without_recover_is_truthful():
    # MAJOR-1 (i): after a crash between the journal append and the manifest
    # rewrite, retrying delete() WITHOUT recover() must finish the deletion
    # and return a receipt bound to the digest that was actually removed —
    # never a receipt for a record that is still present.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        original = {r["id"]: r for r in _manifest()["records"]}
        original_atomic_write = deletion_module._atomic_write

        def exploding_atomic_write(path, data):
            if "bundles" in str(path):
                raise OSError("simulated crash before manifest rewrite")
            return original_atomic_write(path, data)

        deletion_module._atomic_write = exploding_atomic_write
        try:
            assert_raises(
                OSError,
                service.delete,
                "bundle-alpha",
                "rec-002",
                "synthetic crash erasure",
            )
        finally:
            deletion_module._atomic_write = original_atomic_write
        assert service.receipt_paths() == []
        assert "rec-002" in _ids(service, "bundle-alpha")

        receipt = service.delete("bundle-alpha", "rec-002", "synthetic crash erasure")

        assert "rec-002" not in _ids(service, "bundle-alpha")
        assert receipt["receipt"]["removed_records"] == [
            {"id": "rec-002", "digest": original["rec-002"]["integrity"]["digest"]}
        ]
        result = service.verify_receipt(receipt)
        assert result["ok"] is True, result
        # the retry reused the journal tombstone instead of doubling it
        assert len(service.journal_tombstones()) == 1


def test_cross_bundle_same_id_delete_removes_every_copy():
    # MAJOR-1 (ii): a journal tombstone from bundle-a must not short-circuit
    # a delete that leaves bundle-b's copy in place. Every same-id copy under
    # the service root is removed, and the receipt names all of them.
    with tempfile.TemporaryDirectory() as tmp:
        service = _cross_bundle_service(tmp)
        digests = {
            bundle_id: {
                r["id"]: r["integrity"]["digest"]
                for r in service.get_bundle(bundle_id)["records"]
            }
            for bundle_id in ("bundle-a", "bundle-b")
        }

        receipt = service.delete("bundle-a", "rec-002", "synthetic erasure")

        assert "rec-002" not in _ids(service, "bundle-a")
        assert "rec-002" not in _ids(service, "bundle-b")
        removed = sorted(r["digest"] for r in receipt["receipt"]["removed_records"])
        assert removed == sorted(
            [digests["bundle-a"]["rec-002"], digests["bundle-b"]["rec-002"]]
        )
        assert service.verify_receipt(receipt)["ok"] is True

        # the second (already-satisfied) request stays truthful and idempotent
        again = service.delete("bundle-b", "rec-002", "synthetic erasure")
        assert again["receipt"]["removed_records"] == receipt["receipt"][
            "removed_records"
        ]
        assert service.verify_receipt(again)["ok"] is True


def test_delete_refuses_to_receipt_a_surviving_copy():
    # MAJOR-1: when a "successful" manifest write changes nothing, delete()
    # must notice the survivor, refuse to issue a receipt, and let a retry
    # finish the job honestly.
    with tempfile.TemporaryDirectory() as tmp:
        service = _cross_bundle_service(tmp)
        original_atomic_write = deletion_module._atomic_write

        def noop_atomic_write(path, data):
            if str(path).endswith("bundle-b.json"):
                return None  # pretends to succeed, writes nothing
            return original_atomic_write(path, data)

        deletion_module._atomic_write = noop_atomic_write
        try:
            assert_raises(
                DeletionIncompleteError,
                service.delete,
                "bundle-a",
                "rec-002",
                "synthetic erasure",
            )
        finally:
            deletion_module._atomic_write = original_atomic_write

        assert service.receipt_paths() == []
        assert "rec-002" in _ids(service, "bundle-b")

        receipt = service.delete("bundle-a", "rec-002", "synthetic erasure")
        assert "rec-002" not in _ids(service, "bundle-b")
        assert service.verify_receipt(receipt)["ok"] is True


def test_forged_receipt_with_recomputed_self_digest_is_rejected():
    # MAJOR-2: fabricated evidence plus a recomputed self-digest must fail —
    # tombstone_digest/reason/artifacts are bound to the journal, and
    # removed_records to the durable removal evidence.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        real = service.delete("bundle-alpha", "rec-002", "real synthetic erasure")

        forged = json.loads(json.dumps(real))
        body = forged["receipt"]
        body["removed_records"] = [{"id": "rec-002", "digest": "0" * 64}]
        body["reason"] = "fake reason"
        body["tombstone"]["reason"] = "fake reason"
        body["tombstone_digest"] = canonical_sha256(body["tombstone"])
        body["derived_artifacts"] = ["emb:fabricated"]
        body["issued_at"] = "2030-01-01T00:00:00Z"
        forged["integrity"]["digest"] = canonical_sha256(body)

        result = service.verify_receipt(forged)

        assert result["ok"] is False
        assert any("journal tombstone" in p for p in result["problems"])
        assert any("deletion evidence" in p for p in result["problems"])


def test_forged_removed_digest_alone_is_rejected():
    # MAJOR-2, minimal forgery: only removed_records is rewritten, every
    # other field (including a recomputed self-digest) stays consistent.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        real = service.delete("bundle-alpha", "rec-002", "synthetic erasure")

        forged = json.loads(json.dumps(real))
        body = forged["receipt"]
        body["removed_records"] = [{"id": "rec-002", "digest": "1" * 64}]
        forged["integrity"]["digest"] = canonical_sha256(body)

        result = service.verify_receipt(forged)

        assert result["ok"] is False
        assert any("deletion evidence" in p for p in result["problems"])


def test_receipt_without_journal_tombstone_is_rejected():
    # MAJOR-2: a receipt can only prove what the journal actually recorded.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        real = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        service.journal_path.write_text("", encoding="utf-8")  # journal lost

        result = service.verify_receipt(real)

        assert result["ok"] is False
        assert any("no tombstone for target in journal" in p for p in result["problems"])


def test_delete_retry_after_receipt_crash_reissues_receipt():
    # Crash between the manifest rewrite and the receipt: the removal
    # evidence must still allow a truthful receipt on retry (no empty
    # removed_records, no invented digests).
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        original = {r["id"]: r for r in _manifest()["records"]}
        original_atomic_write = deletion_module._atomic_write

        def exploding_atomic_write(path, data):
            if "receipts" in str(path):
                raise OSError("simulated crash before receipt write")
            return original_atomic_write(path, data)

        deletion_module._atomic_write = exploding_atomic_write
        try:
            assert_raises(
                OSError,
                service.delete,
                "bundle-alpha",
                "rec-002",
                "synthetic crash erasure",
            )
        finally:
            deletion_module._atomic_write = original_atomic_write

        assert service.receipt_paths() == []
        assert "rec-002" not in _ids(service, "bundle-alpha")

        receipt = service.delete("bundle-alpha", "rec-002", "synthetic crash erasure")

        assert receipt["receipt"]["removed_records"] == [
            {"id": "rec-002", "digest": original["rec-002"]["integrity"]["digest"]}
        ]
        assert service.verify_receipt(receipt)["ok"] is True


def test_delete_heals_resurrected_record_via_supersession():
    # A stale manifest restored after deletion is removed again on the next
    # delete, reusing the journal tombstone and the recorded evidence.
    # Advisory A-1 ruling (b): the healed delete replays the first receipt's
    # exact id preimage, so it must NOT overwrite the immutable receipt
    # file — it routes through supersession (new id, supersedes the chain
    # tail) and the first receipt stays byte-intact on disk.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        first = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        first_file = service.receipts_dir / f"{first['receipt']['id']}.json"
        first_bytes = first_file.read_bytes()
        service.put_bundle(_manifest())  # stale copy comes back
        assert "rec-002" in _ids(service, "bundle-alpha")

        second = service.delete("bundle-alpha", "rec-002", "synthetic erasure")

        assert "rec-002" not in _ids(service, "bundle-alpha")
        assert second["receipt"]["id"] != first["receipt"]["id"]
        assert second["receipt"]["supersedes"] == first["integrity"]["digest"]
        assert second["receipt"]["removed_records"] == first["receipt"][
            "removed_records"
        ]
        assert first_file.read_bytes() == first_bytes
        assert len(service.receipt_paths()) == 2
        assert len(service.journal_tombstones()) == 1
        assert service.verify_receipt(second)["ok"] is True
        superseded = service.verify_receipt(first)
        assert superseded["ok"] is False
        assert any("superseded" in p for p in superseded["problems"])


# ---------------------------------------------------------------------------
# Regression tests for verify round 2 advisory 2: recover() receipt laundering
# (BACKLOG M2 #4). Semantics (i): verify_receipt ok=True means the receipt
# accounts for every removal of the target known to the service root —
# recover() never rewrites receipts, so an under-reporting receipt keeps
# failing with a problem naming the unreported recovered digest.
# ---------------------------------------------------------------------------


def test_recover_does_not_launder_underreporting_receipt():
    # The verifier repro, as a regression test: delete -> receipt ok; a NEW
    # bundle reintroduces the target with a DIFFERENT digest ("STALE
    # variant"); verify_receipt is ok:False; recover() removes the stale
    # copy — the original receipt must STILL not verify ok, because it
    # under-reports the removal recover() just performed.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert service.verify_receipt(receipt)["ok"] is True

        stale = make_record(
            "rec-002", "fact", "STALE variant", OWNER, created=FIXED_TS
        )
        stale_digest = stale["integrity"]["digest"]
        assert stale_digest != receipt["receipt"]["removed_records"][0]["digest"]
        service.put_bundle(build_bundle("bundle-stale", records=[stale]))

        failing = service.verify_receipt(receipt)
        assert failing["ok"] is False
        assert any("still present" in p for p in failing["problems"])

        assert service.recover() == ["rec-002"]

        # The stale digest is in neither the receipt nor delete-time evidence
        # — that gap is exactly what the recovery log must close durably.
        recorded_digests = {
            e["digest"] for e in service._read_evidence("rec-002")["removals"]
        }
        assert stale_digest not in recorded_digests
        assert stale_digest not in {
            r["digest"] for r in receipt["receipt"]["removed_records"]
        }

        # (b) the under-reporting receipt must not return to ok:True
        result = service.verify_receipt(receipt)
        assert result["ok"] is False
        assert any("under-report" in p for p in result["problems"])
        assert any(stale_digest in p for p in result["problems"])


def test_recovery_log_records_every_removed_digest_attributably():
    # (a) after recover(), every digest it removed is retrievable from
    # durable evidence and attributable to recovery (recovery log line with
    # target id, digest, recovered_at), distinguishable from delete-time
    # removals in evidence/.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        service.put_bundle(_manifest())  # stale copy with the ORIGINAL digest
        assert service.recover() == ["rec-002"]

        assert service.recovery_path.exists()
        entries = service.recovery_removals("rec-002")
        assert len(entries) == 1
        entry = entries[0]
        assert entry["record_id"] == "rec-002"
        assert entry["bundle_id"] == "bundle-alpha"
        assert entry["digest"] == service._read_evidence("rec-002")["removals"][0][
            "digest"
        ]
        assert entry["recovered_at"] == DELETED_AT

        # the recovery log parses line-by-line straight off disk
        raw = [
            json.loads(line)
            for line in service.recovery_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert raw == [entry]


def test_recovery_log_line_written_before_manifest_rewrite():
    # (c) crash-safety ordering: the recovery log entry is durable BEFORE
    # the manifest rewrite, so a crash between them still attributes the
    # removal; re-running recover() finishes the job.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        service.put_bundle(_manifest())  # stale copy back
        original_atomic_write = deletion_module._atomic_write

        def exploding_atomic_write(path, data):
            if "bundles" in str(path):
                raise OSError("simulated crash during recovery rewrite")
            return original_atomic_write(path, data)

        deletion_module._atomic_write = exploding_atomic_write
        try:
            assert_raises(OSError, service.recover)
        finally:
            deletion_module._atomic_write = original_atomic_write

        # the removal is already attributable even though the record survives
        assert "rec-002" in _ids(service, "bundle-alpha")
        entries = service.recovery_removals("rec-002")
        assert len(entries) == 1
        assert entries[0]["recovered_at"] == DELETED_AT

        # retry finishes the deletion; the duplicate log line is tolerated
        assert service.recover() == ["rec-002"]
        assert "rec-002" not in _ids(service, "bundle-alpha")
        assert len(service.recovery_removals("rec-002")) == 1


def test_recover_remains_idempotent_and_log_stable():
    # (c) a second recover() on consistent state is a no-op and appends
    # nothing to the recovery log.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        service.put_bundle(_manifest())
        assert service.recover() == ["rec-002"]
        lines_after_first = service.recovery_path.read_text(encoding="utf-8")

        assert service.recover() == []
        assert service.recover() == []
        assert service.recovery_path.read_text(encoding="utf-8") == lines_after_first


def test_verify_receipt_ok_on_roots_without_recovery_log():
    # (d) backward compatibility: service roots created before the recovery
    # log existed have no recovery.jsonl; receipts there must still verify
    # and the service must not crash on the missing file.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        assert not service.recovery_path.exists()
        assert service.recovery_removals() == []
        result = service.verify_receipt(receipt)
        assert result["ok"] is True, result


def test_recovered_digest_matching_receipt_claim_does_not_fail():
    # recover() removing a copy whose digest the receipt ALREADY names is
    # fully accounted for: verification stays ok.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        original = json.loads(json.dumps(_manifest()))
        service.put_bundle(original)  # exact same digest as at delete time
        assert service.recover() == ["rec-002"]
        assert service.verify_receipt(receipt)["ok"] is True


def test_journal_tombstones_invalid_utf8_raises_typed_error():
    # M3 round-2 verify advisory 2, mirrored into the L1 reader: the
    # tombstone journal is decoded explicitly per line; invalid UTF-8
    # raises the typed DeletionError with path:lineno, never a bare
    # UnicodeDecodeError.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        with open(service.journal_path, "ab") as fh:
            fh.write(b"\xff\xfe\x00not-utf8\n")
        try:
            service.journal_tombstones()
        except DeletionError as err:
            assert "tombstones.jsonl" in str(err)
            assert "invalid UTF-8" in str(err)
        else:
            raise AssertionError("expected DeletionError")
