"""L2 propagation pack / ack contracts (M3 round 2, RFC Q1/Q2/Q3 + UC1).

Covers:

- export determinism (same journal state -> byte-identical pack);
- the pack digest chain (per-tombstone digest -> sorted-list pack digest
  -> attestation -> artifact integrity) and every forgery class that must
  be rejected: mutated tombstone with a stale digest list, pack_digest
  recomputed over the wrong set, missing attestation, tampered artifact;
- A-19 apply semantics: store records targeted by pack tombstones are
  removed through the tombstone-first machinery;
- idempotent re-import (no new journal lines, identical ack) and
  order-independence (same tombstones in a different pack order -> same
  final state, same ack);
- the pending->acked propagation.jsonl journal: line shape, fsync-before-
  return, corrupt line -> loud typed error;
- the explicit honesty contract: the ack limitation wording that says the
  digest chain is NOT a signature (mutation-checked: no overclaim).
"""

import builtins
import json
import os
import tempfile
from pathlib import Path

from m2_helpers import DELETED_AT, OWNER

import mbcp.propagation as propagation_module

from mbcp import (
    ACK_LIMITATIONS,
    L1DeletionService,
    PackValidationError,
    PropagationError,
    PropagationJournalError,
    build_bundle,
    canonical_bytes,
    canonical_sha256,
    export_propagation_pack,
    import_propagation_pack,
    load,
    make_record,
    read_propagation_journal,
    record_pending_propagation,
)

from syn import FIXED_TS, assert_raises

SOURCE_ROOT_ID = "root-source-synthetic"
DEST_ROOT_ID = "root-dest-synthetic"
IMPORTED_AT = "2026-11-06T02:00:00Z"


def _source_service(tmp, name="source"):
    """A source root with two bundles and two deletions in the journal."""
    service = L1DeletionService(Path(tmp) / name, clock=lambda: DELETED_AT)
    service.put_bundle(
        build_bundle(
            "bundle-alpha",
            records=[
                make_record("rec-001", "fact", "synthetic one", OWNER, created=FIXED_TS),
                make_record("rec-002", "fact", "synthetic two", OWNER, created=FIXED_TS),
            ],
        )
    )
    service.put_bundle(
        build_bundle(
            "bundle-beta",
            records=[
                make_record("rec-003", "fact", "synthetic three", OWNER, created=FIXED_TS),
            ],
        )
    )
    service.delete("bundle-alpha", "rec-002", "synthetic erasure one")
    service.delete("bundle-beta", "rec-003", "synthetic erasure two")
    return service


def _dest_service(tmp, name="dest"):
    """A destination root holding stale copies of every deleted id."""
    service = L1DeletionService(Path(tmp) / name, clock=lambda: DELETED_AT)
    service.put_bundle(
        build_bundle(
            "bundle-dest",
            records=[
                make_record("rec-001", "fact", "dest copy one", OWNER, created=FIXED_TS),
                make_record("rec-002", "fact", "dest stale copy two", OWNER, created=FIXED_TS),
                make_record("rec-003", "fact", "dest stale copy three", OWNER, created=FIXED_TS),
            ],
        )
    )
    return service


def _pack(tmp, name="source", **kwargs):
    """Export a pack from a fresh source root at <tmp>/<name>.

    (Round C1: two exports of the SAME journal state must use DIFFERENT
    directories — the write boundary now refuses to re-put manifests whose
    records carry tombstoned ids, which is exactly what a second _pack on
    one root would attempt.)
    """
    service = _source_service(tmp, name)
    kwargs.setdefault("source_root", SOURCE_ROOT_ID)
    return export_propagation_pack(
        service, now=FIXED_TS, **kwargs
    )


# -- export -----------------------------------------------------------------

def test_export_pack_is_deterministic_byte_identical():
    # Same journal state built in two separate roots (the write boundary
    # forbids re-putting tombstoned-id manifests into one root), explicit
    # source_root -> byte-identical packs.
    with tempfile.TemporaryDirectory() as tmp:
        pack1 = _pack(tmp, "source-1")
        pack2 = _pack(tmp, "source-2")
    assert canonical_bytes(pack1) == canonical_bytes(pack2)


def test_export_pack_digest_chain_verifies():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
    body = pack["pack"]
    digests = sorted(canonical_sha256(t) for t in body["tombstones"])
    assert body["tombstone_digests"] == digests
    # Round C1 (SPEC §2 audit-tightening, audit §7): the pack digest binds
    # the source root AND the sorted tombstone digest list.
    assert body["pack_digest"] == canonical_sha256({
        "source_root": SOURCE_ROOT_ID,
        "tombstone_digests": digests,
    })
    assert body["attestation"]["pack_digest"] == body["pack_digest"]
    assert body["attestation"]["source_root"] == SOURCE_ROOT_ID
    assert body["attestation"]["issued_at"] == FIXED_TS
    assert pack["integrity"]["digest"] == canonical_sha256(body)
    assert {t["target_id"] for t in body["tombstones"]} == {"rec-002", "rec-003"}


def test_same_tombstone_set_from_two_roots_is_different_packs():
    # audit §7 probe: two source roots holding the SAME tombstone set must
    # produce DIFFERENT pack digests, land on DIFFERENT ack paths, and
    # each ack must name its own for_source_root — the ack-attribution
    # collision across roots is closed.
    with tempfile.TemporaryDirectory() as tmp:
        pack_a = _pack(tmp, "source-a", source_root="root-a")
        pack_b = _pack(tmp, "source-b", source_root="root-b")
        assert (
            [t["target_id"] for t in pack_a["pack"]["tombstones"]]
            == [t["target_id"] for t in pack_b["pack"]["tombstones"]]
        )
        assert pack_a["pack"]["pack_digest"] != pack_b["pack"]["pack_digest"]

        dest = _dest_service(tmp, "dest")
        ack_a = import_propagation_pack(dest.root, pack_a, now=IMPORTED_AT)
        ack_b = import_propagation_pack(dest.root, pack_b, now=IMPORTED_AT)

        assert ack_a["ack"]["pack_digest"] == pack_a["pack"]["pack_digest"]
        assert ack_b["ack"]["pack_digest"] == pack_b["pack"]["pack_digest"]
        assert ack_a["ack"]["for_source_root"] == "root-a"
        assert ack_b["ack"]["for_source_root"] == "root-b"
        # separate ack artifacts, keyed by pack_digest[:16]
        assert pack_a["pack"]["pack_digest"][:16] != pack_b["pack"]["pack_digest"][:16]
        for pack in (pack_a, pack_b):
            ack_path = (
                dest.root / "propagation" / "acks"
                / f"{pack['pack']['pack_digest'][:16]}.json"
            )
            assert ack_path.exists()


def test_export_pack_target_ids_filter():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp, target_ids=["rec-002"])
    assert [t["target_id"] for t in pack["pack"]["tombstones"]] == ["rec-002"]


# -- forgery rejection (digest-chain integrity layer only) ------------------

def test_import_rejects_mutated_tombstone_with_stale_digest_list():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        forged = json.loads(json.dumps(pack))
        forged["pack"]["tombstones"][0]["reason"] = "laundered reason"
        dest = _dest_service(tmp)
        before = dest.journal_path.read_bytes() if dest.journal_path.exists() else b""
        assert_raises(
            PackValidationError,
            import_propagation_pack, dest.root, forged, now=IMPORTED_AT,
        )
        # nothing applied: journal untouched, record still present
        after = dest.journal_path.read_bytes() if dest.journal_path.exists() else b""
        assert before == after
        assert any(r["id"] == "rec-002" for r in dest.get_bundle("bundle-dest")["records"])


def test_import_rejects_pack_digest_recomputed_over_wrong_set():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        forged = json.loads(json.dumps(pack))
        # drop one tombstone AND its digest, but keep the ORIGINAL pack_digest
        # (recomputed over the full set, now the wrong set) + re-integrity.
        forged["pack"]["tombstones"] = forged["pack"]["tombstones"][1:]
        forged["pack"]["tombstone_digests"] = forged["pack"]["tombstone_digests"][1:]
        forged["integrity"]["digest"] = canonical_sha256(forged["pack"])
        dest = _dest_service(tmp)
        assert_raises(
            PackValidationError,
            import_propagation_pack, dest.root, forged, now=IMPORTED_AT,
        )
        assert dest.get_bundle("bundle-dest")["records"], "forged partial pack applied"


def test_import_rejects_missing_attestation():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        del pack["pack"]["attestation"]
        dest = _dest_service(tmp)
        assert_raises(
            PackValidationError,
            import_propagation_pack, dest.root, pack, now=IMPORTED_AT,
        )


def test_import_rejects_attestation_bound_to_other_pack():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        other = _pack(tmp, "other-source", target_ids=["rec-002"])
        forged = json.loads(json.dumps(pack))
        forged["pack"]["attestation"] = other["pack"]["attestation"]
        forged["integrity"]["digest"] = canonical_sha256(forged["pack"])
        dest = _dest_service(tmp)
        assert_raises(
            PackValidationError,
            import_propagation_pack, dest.root, forged, now=IMPORTED_AT,
        )


def test_import_rejects_tampered_artifact_integrity():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        forged = json.loads(json.dumps(pack))
        forged["pack"]["source_root"] = "root-impostor"
        # integrity.digest NOT recomputed -> whole-artifact tampering
        dest = _dest_service(tmp)
        assert_raises(
            PackValidationError,
            import_propagation_pack, dest.root, forged, now=IMPORTED_AT,
        )


# -- apply semantics (A-19) ---------------------------------------------------

def test_import_applies_tombstones_and_removes_targeted_records():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        dest = _dest_service(tmp)
        ack = import_propagation_pack(dest.root, pack, now=IMPORTED_AT)

        # store records targeted by pack tombstones are gone (id-wide)
        manifest = dest.get_bundle("bundle-dest")
        assert sorted(r["id"] for r in manifest["records"]) == ["rec-001"]
        # journal + manifest both gained the tombstones
        assert {t["target_id"] for t in dest.journal_tombstones()} == {
            "rec-002",
            "rec-003",
        }
        assert {t["target_id"] for t in manifest["tombstones"]} == {
            "rec-002",
            "rec-003",
        }
        # a stale re-import of the dest bundle cannot resurrect the ids
        assert [r["id"] for r in load([dest.get_bundle("bundle-dest")])] == ["rec-001"]

        # ack artifact is on disk, schema-shaped, self-consistent
        ack_path = (
            dest.root / "propagation" / "acks" / f"{pack['pack']['pack_digest'][:16]}.json"
        )
        assert ack_path.exists()
        assert json.loads(ack_path.read_text(encoding="utf-8")) == ack
        assert ack["ack"]["pack_digest"] == pack["pack"]["pack_digest"]
        assert ack["ack"]["for_source_root"] == SOURCE_ROOT_ID
        assert ack["ack"]["imported_tombstone_digests"] == sorted(
            canonical_sha256(t) for t in pack["pack"]["tombstones"]
        )
        assert ack["integrity"]["digest"] == canonical_sha256(ack["ack"])


# -- idempotency + order independence -----------------------------------------

def test_import_is_idempotent_no_new_journal_lines_same_ack():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        dest = _dest_service(tmp)
        ack1 = import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
        journal_lines_1 = dest.journal_path.read_text(encoding="utf-8").count("\n")
        ack2 = import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
        journal_lines_2 = dest.journal_path.read_text(encoding="utf-8").count("\n")
    assert journal_lines_1 == journal_lines_2
    assert ack1 == ack2


def _reversed_pack(pack):
    """Same tombstones in reverse pack order (integrity recomputed).

    The pack digest binds (source_root, SORTED tombstone digest list), so
    reordering the tombstones leaves it unchanged."""
    body = json.loads(json.dumps(pack["pack"]))
    body["tombstones"] = list(reversed(body["tombstones"]))
    body["tombstone_digests"] = [canonical_sha256(t) for t in body["tombstones"]]
    return {
        "pack": body,
        "integrity": {"algo": "sha256", "digest": canonical_sha256(body)},
    }


def test_import_is_order_independent_same_state_same_ack():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        dest_a = _dest_service(tmp, "dest-a")
        dest_b = _dest_service(tmp, "dest-b")
        ack_a = import_propagation_pack(dest_a.root, pack, now=IMPORTED_AT)
        ack_b = import_propagation_pack(
            dest_b.root, _reversed_pack(pack), now=IMPORTED_AT
        )
        assert ack_a == ack_b
        assert canonical_bytes(dest_a.get_bundle("bundle-dest")) == canonical_bytes(
            dest_b.get_bundle("bundle-dest")
        )


# -- propagation.jsonl journal -------------------------------------------------

def test_propagation_journal_records_acked_line_with_shape():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        dest = _dest_service(tmp)
        ack = import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
        entries = read_propagation_journal(dest.root)
    assert len(entries) == 1
    (entry,) = entries
    assert entry["status"] == "acked"
    assert entry["pack_digest"] == pack["pack"]["pack_digest"]
    assert entry["source_root"] == SOURCE_ROOT_ID
    assert entry["ack_digest"] == ack["integrity"]["digest"]
    assert entry["at"] == IMPORTED_AT


def test_pending_propagation_is_recorded_but_is_not_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        dest = _dest_service(tmp)
        record_pending_propagation(
            dest.root,
            pack_digest="ab" * 32,
            source_root=SOURCE_ROOT_ID,
            now=IMPORTED_AT,
        )
        entries = read_propagation_journal(dest.root)
        # fail-closed: nothing was applied, the line is explicitly pending
        assert [e["status"] for e in entries] == ["pending"]
        assert entries[0]["ack_digest"] is None
        assert {t["target_id"] for t in dest.journal_tombstones()} == set()
        assert len(dest.get_bundle("bundle-dest")["records"]) == 3


def test_propagation_journal_fsync_before_return():
    # The propagation.jsonl fd must be fsynced before import returns, and
    # only AFTER the ack artifact is durably written (fail-closed ordering).
    events = []
    journal_fds = set()
    real_open = builtins.open
    real_fsync = os.fsync
    real_atomic_write = propagation_module._atomic_write

    class _JournalFile:
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
        if "propagation.jsonl" in str(path) and "a" in mode:
            journal_fds.add(fh.fileno())
            return _JournalFile(fh)
        return fh

    def tracking_fsync(fd):
        events.append(("fsync", fd in journal_fds))
        return real_fsync(fd)

    def tracking_atomic_write(path, data):
        if str(path).endswith(".json") and "acks" in str(path):
            events.append(("ack-write", str(path)))
        return real_atomic_write(path, data)

    builtins.open = tracking_open
    os.fsync = tracking_fsync
    propagation_module._atomic_write = tracking_atomic_write
    try:
        with tempfile.TemporaryDirectory() as tmp:
            pack = _pack(tmp)
            dest = _dest_service(tmp)
            baseline = len(events)
            import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
    finally:
        builtins.open = real_open
        os.fsync = real_fsync
        propagation_module._atomic_write = real_atomic_write

    events = events[baseline:]
    ack_writes = [i for i, event in enumerate(events) if event[0] == "ack-write"]
    journal_fsyncs = [
        i for i, event in enumerate(events) if event == ("fsync", True)
    ]
    assert ack_writes, "ack artifact was never written"
    assert journal_fsyncs, "propagation.jsonl fd was never fsynced"
    assert max(ack_writes) < max(journal_fsyncs), events


def test_corrupt_propagation_journal_raises_typed_error():
    with tempfile.TemporaryDirectory() as tmp:
        dest = _dest_service(tmp)
        record_pending_propagation(
            dest.root, pack_digest="cd" * 32, source_root=SOURCE_ROOT_ID,
            now=IMPORTED_AT,
        )
        path = dest.root / "propagation.jsonl"
        with open(path, "ab") as fh:
            fh.write(b"this is not json\n")
        try:
            read_propagation_journal(dest.root)
        except PropagationJournalError as err:
            assert "propagation.jsonl" in str(err)
        else:
            raise AssertionError("expected PropagationJournalError")


def test_propagation_journal_is_attempts_audit_one_line_per_intake():
    # BACKLOG M3 round-2 advisory 1 (PIN, not a bug): propagation.jsonl is
    # an ATTEMPTS AUDIT — every successful intake, INCLUDING an idempotent
    # no-op re-import that applied nothing, appends exactly one acked line.
    # Growth per re-import is the specified behaviour; a future dedupe
    # refactor must change this test deliberately, not silently.
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        dest = _dest_service(tmp)
        import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
        import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
        entries = read_propagation_journal(dest.root)
    assert len(entries) == 2
    assert entries[0] == entries[1]
    assert all(e["status"] == "acked" for e in entries)


def test_propagation_journal_invalid_utf8_raises_typed_error():
    # BACKLOG M3 round-2 advisory 2: bytes are decoded explicitly per line;
    # invalid UTF-8 raises the typed error with path:lineno, never a bare
    # UnicodeDecodeError.
    with tempfile.TemporaryDirectory() as tmp:
        dest = _dest_service(tmp)
        record_pending_propagation(
            dest.root, pack_digest="ef" * 32, source_root=SOURCE_ROOT_ID,
            now=IMPORTED_AT,
        )
        path = dest.root / "propagation.jsonl"
        with open(path, "ab") as fh:
            fh.write(b"\xff\xfe\x00not-utf8\n")
        try:
            read_propagation_journal(dest.root)
        except PropagationJournalError as err:
            assert "propagation.jsonl" in str(err)
            assert "invalid UTF-8" in str(err)
        else:
            raise AssertionError("expected PropagationJournalError")


def test_noop_reimport_tampered_ack_is_reissued_not_returned():
    # BACKLOG M3 round-2 advisory 3: the no-op re-import read-back must not
    # return a tampered ack. The on-disk artifact's integrity.digest is
    # re-checked; a mismatch means the ack is re-issued from state (which
    # is idempotent — same content, correct integrity) and the tampered
    # bytes are overwritten.
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        dest = _dest_service(tmp)
        ack1 = import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
        ack_path = (
            dest.root / "propagation" / "acks"
            / f"{pack['pack']['pack_digest'][:16]}.json"
        )
        tampered = json.loads(ack_path.read_text(encoding="utf-8"))
        tampered["ack"]["imported_at"] = "2031-01-01T00:00:00Z"
        ack_path.write_text(json.dumps(tampered), encoding="utf-8")

        ack2 = import_propagation_pack(dest.root, pack, now=IMPORTED_AT)

        assert ack2 == ack1
        assert ack2["ack"]["imported_at"] == IMPORTED_AT
        assert ack2["integrity"]["digest"] == canonical_sha256(ack2["ack"])
        assert json.loads(ack_path.read_text(encoding="utf-8")) == ack1


def test_noop_reimport_corrupt_ack_raises_typed_error():
    # Advisory 3, corrupt case: an unparseable ack artifact raises the
    # typed PropagationError naming the path — never a bare JSONDecodeError.
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        dest = _dest_service(tmp)
        import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
        ack_path = (
            dest.root / "propagation" / "acks"
            / f"{pack['pack']['pack_digest'][:16]}.json"
        )
        ack_path.write_text("{not json", encoding="utf-8")
        try:
            import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
        except PropagationError as err:
            assert "corrupt ack artifact" in str(err)
        else:
            raise AssertionError("expected PropagationError")


# -- honesty: the ack must not overclaim ---------------------------------------

def test_ack_limitations_state_no_signature_wording():
    with tempfile.TemporaryDirectory() as tmp:
        pack = _pack(tmp)
        dest = _dest_service(tmp)
        ack = import_propagation_pack(dest.root, pack, now=IMPORTED_AT)
    limitations = ack["ack"]["limitations"]
    assert limitations == ACK_LIMITATIONS
    joined = " ".join(limitations)
    # The mutation-checked honesty contract: the artifact must NOT overclaim
    # cryptographic provenance. Exact required wording:
    assert (
        "digest-chain integrity only; tamper-evidence relies on the writer "
        "of this root not forging; cryptographic signing is M4/L4 scope."
    ) in joined
