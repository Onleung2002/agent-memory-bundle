"""L1 deletion service: tombstone-first delete, receipts, crash recovery."""

import json
import tempfile
from pathlib import Path

from m2_helpers import DELETED_AT, IMPORTED_AT

import mbcp.deletion as deletion_module

from mbcp import (
    L1DeletionService,
    UnknownTargetError,
    build_bundle,
    canonical_bytes,
    canonical_sha256,
    load,
    make_record,
    make_tombstone,
)
from mbcp.deletion import L1_LIMITATIONS

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
        assert body["limitations"] == L1_LIMITATIONS
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
