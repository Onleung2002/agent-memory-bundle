"""Deletion-service durability + verification contracts (M2 fix round 2).

Closes mutation-verified false-green gaps that tests/test_deletion_l1.py did
not cover:

- journal fsync ordering: the tombstone journal fd must be fsynced BEFORE any
  bundle manifest is atomically rewritten (tombstone-first durability);
- verify_receipt schema gate: a self-digest-consistent receipt that violates
  schemas/deletion-receipt.v0.json must yield ok=False;
- all_tombstones() merge semantics: latest deleted_at/reason wins, derived
  artifacts are the sorted UNION across journal copies.
"""

import builtins
import json
import os
import tempfile
from pathlib import Path

from m2_helpers import DELETED_AT, OWNER

import mbcp.deletion as deletion_module

from mbcp import L1DeletionService, build_bundle, canonical_bytes, canonical_sha256, make_record, make_tombstone

from syn import FIXED_TS


def _service(tmp, *, clock=None):
    service = L1DeletionService(
        Path(tmp) / "service", clock=clock or (lambda: DELETED_AT)
    )
    service.put_bundle(
        build_bundle(
            "bundle-alpha",
            records=[
                make_record("rec-001", "fact", "synthetic one", OWNER, created=FIXED_TS),
                make_record("rec-002", "fact", "synthetic two", OWNER, created=FIXED_TS),
            ],
        )
    )
    return service


def test_journal_fsync_happens_before_manifest_rewrite():
    # Record every fsync (tagged by whether the fd belongs to the tombstone
    # journal) and every atomic bundle-manifest write; the journal fsync must
    # precede the FIRST manifest rewrite. Removing the fsync in
    # L1DeletionService._append_journal makes this test fail.
    events = []
    journal_fds = set()
    real_open = builtins.open
    real_fsync = os.fsync
    real_atomic_write = deletion_module._atomic_write

    class _JournalFile:
        """File proxy that un-registers its fd when closed, so a later fd
        reuse (e.g. the manifest tmp file) is never mistaken for the journal."""

        def __init__(self, fh):
            self._fh = fh
            self._fd = fh.fileno()

        def __enter__(self):
            self._fh.__enter__()
            return self

        def __exit__(self, *exc):
            try:
                return self._fh.__exit__(*exc)
            finally:
                journal_fds.discard(self._fd)

        def __getattr__(self, name):
            return getattr(self._fh, name)

        def fileno(self):
            return self._fd

        def close(self):
            try:
                return self._fh.close()
            finally:
                journal_fds.discard(self._fd)

    def tracking_open(path, mode="r", *args, **kwargs):
        fh = real_open(path, mode, *args, **kwargs)
        if "tombstones.jsonl" in str(path) and "a" in mode:
            journal_fds.add(fh.fileno())
            return _JournalFile(fh)
        return fh

    def tracking_fsync(fd):
        events.append(("fsync", fd in journal_fds))
        return real_fsync(fd)

    def tracking_atomic_write(path, data):
        if "bundles" in str(path):
            events.append(("manifest-write", str(path)))
        return real_atomic_write(path, data)

    builtins.open = tracking_open
    os.fsync = tracking_fsync
    deletion_module._atomic_write = tracking_atomic_write
    try:
        with tempfile.TemporaryDirectory() as tmp:
            service = _service(tmp)  # setup writes; not part of the contract
            baseline = len(events)
            service.delete("bundle-alpha", "rec-002", "synthetic erasure")
    finally:
        builtins.open = real_open
        os.fsync = real_fsync
        deletion_module._atomic_write = real_atomic_write

    events = events[baseline:]
    first_manifest_write = next(
        i for i, event in enumerate(events) if event[0] == "manifest-write"
    )
    journal_fsync_positions = [
        i for i, event in enumerate(events) if event == ("fsync", True)
    ]
    assert journal_fsync_positions, "journal fd was never fsynced"
    assert min(journal_fsync_positions) < first_manifest_write, events


def test_verify_receipt_rejects_schema_invalid_receipt_with_valid_self_digest():
    # A receipt that is internally self-consistent (integrity.digest
    # recomputed with canonical_sha256) but structurally invalid per
    # schemas/deletion-receipt.v0.json must not pass the schema gate.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")

        for mutate in (
            lambda body: body.update(level="L4"),
            lambda body: body.update(limitations=[]),
        ):
            forged = json.loads(json.dumps(receipt))
            mutate(forged["receipt"])
            forged["integrity"]["digest"] = canonical_sha256(forged["receipt"])

            result = service.verify_receipt(forged)

            assert result["ok"] is False, forged
            assert result["problems"], forged


def test_all_tombstones_merges_journal_copies_latest_wins_artifacts_union():
    # Two journal tombstones for the same target: the merged service view is
    # exactly ONE tombstone with the LATEST deleted_at/reason and the SORTED
    # UNION of derived_artifacts (SPEC 1.2: L3 evidence must never shrink).
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        older = make_tombstone(
            "rec-002",
            "first erasure",
            deleted_at="2026-11-06T00:00:00Z",
            derived_artifacts=["chunk:rec-002:0"],
        )
        newer = make_tombstone(
            "rec-002",
            "second erasure",
            deleted_at="2026-11-06T01:00:00Z",
            derived_artifacts=["emb:rec-002", "chunk:rec-002:0"],
        )
        with open(service.journal_path, "ab") as fh:
            fh.write(canonical_bytes(older) + b"\n")
            fh.write(canonical_bytes(newer) + b"\n")

        merged = service.all_tombstones()

        assert len(merged) == 1, merged
        assert merged[0]["target_id"] == "rec-002"
        assert merged[0]["deleted_at"] == "2026-11-06T01:00:00Z"
        assert merged[0]["reason"] == "second erasure"
        assert merged[0]["derived_artifacts"] == ["chunk:rec-002:0", "emb:rec-002"]


def test_all_tombstones_single_copy_roundtrips():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete(
            "bundle-alpha",
            "rec-002",
            "synthetic erasure",
            derived_artifacts=["emb:rec-002"],
        )
        merged = service.all_tombstones()
        assert len(merged) == 1
        assert merged[0]["reason"] == "synthetic erasure"
        assert merged[0]["derived_artifacts"] == ["emb:rec-002"]
