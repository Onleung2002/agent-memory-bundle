"""M4 Round C Batch 2 — three audit-derived tightenings (worker: round C2).

FIX 1 (audit §3): a root-level advisory lock (``fcntl.flock`` on
``<root>/.mbcp.lock``) wraps delete()/recover()/propagation intake, so
racing writers on one service root cannot interleave journal/manifest
writes. Acquisition is bounded (``lock_timeout``, default 10s) and a
timeout raises the typed ``LockTimeoutError`` — never a silent retry.
Same-thread nested acquisition is re-entrant (held count); the OS
releases the flock if a holder crashes. The lock file is a root
dotfile, outside every scanner namespace.

FIX 2 (audit §13): every receipt carries an ``inventory`` block — the
sorted list of ALL bundle ids in the store root at deletion time
(pre-deletion state) plus the canonical SHA-256 over that sorted list —
so the receipt binds to the exact store SET, not only to the removed
records. ``verify_receipt(check_inventory=True)`` (opt-in, default off)
fails closed with a problem NAMING the divergent bundle ids when the
live store set differs.

FIX 3 (A-2 closure): recover()'s per-file except is narrowed —
genuinely unreadable entries (OSError/KeyError: directory-shaped entry,
permissions, vanished mid-scan) are SKIPPED and counted in
``service.last_recovery_skipped_unreadable`` (visible, never silent);
malformed content (TypeError/ValueError incl. NonFiniteConstantError
NaN poison) raises the typed ``DeletionError`` naming the file.

Concurrency tests force the race with explicit events (never
sleep-based timing); the lock-mutation target is the serialized-order /
typed-timeout assertions in test_lock_racing_delete_times_out_typed and
test_recover_raises_typed_on_malformed_manifest.
"""
import json
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mbcp.deletion as deletion_mod
from mbcp import (
    L1DeletionService,
    LockTimeoutError,
    build_bundle,
    canonical_sha256,
    export_propagation_pack,
    import_propagation_pack,
)
from mbcp.deletion import DeletionError, UnknownTargetError, inventory_digest

from syn import assert_raises, syn_record, write_bundle_direct

FIXED_NOW = "2026-11-06T00:00:00Z"


def _svc(tmp, **kwargs):
    kwargs.setdefault("clock", lambda: FIXED_NOW)
    return L1DeletionService(Path(tmp), **kwargs)


def _b(*pairs):
    return build_bundle(
        "bundle-alpha",
        records=[syn_record(rid, body) for rid, body in pairs],
    )


# --- FIX 1: root advisory lock (audit §3) ------------------------------------

def test_lock_racing_delete_times_out_typed():
    # Thread A enters delete() and blocks INSIDE the critical section (via
    # a clock hook waiting on an explicit event). Thread B's delete on the
    # same root must then fail to acquire the lock within its bounded
    # timeout — typed LockTimeoutError, deterministically (without the
    # lock, B would proceed and this assertion fails: the mutation test).
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one"), ("r2", "body two")))
        entered = threading.Event()
        release = threading.Event()
        results = {}

        def blocking_clock():
            entered.set()
            assert release.wait(10), "test event never released"
            return FIXED_NOW

        def delete_a():
            try:
                svc.delete("bundle-alpha", "r1", "first request")
                results["a"] = "ok"
            except Exception as err:  # noqa: BLE001
                results["a"] = err

        svc._clock = blocking_clock
        thread_a = threading.Thread(target=delete_a)
        thread_a.start()
        assert entered.wait(10), "thread A never reached the critical section"

        def delete_b():
            try:
                svc.delete("bundle-alpha", "r2", "second request",
                           lock_timeout=0.3)
                results["b"] = "ok"
            except Exception as err:  # noqa: BLE001
                results["b"] = err

        thread_b = threading.Thread(target=delete_b)
        thread_b.start()
        thread_b.join(10)
        assert not thread_b.is_alive(), "thread B blocked instead of timing out"
        assert isinstance(results["b"], LockTimeoutError), results

        release.set()
        thread_a.join(10)
        assert not thread_a.is_alive()
        assert results["a"] == "ok", results

        # With the lock free, B's retry succeeds; the journal shows both
        # tombstones with no interleaved corruption (every line parses,
        # exactly two entries, both receipts verify).
        svc._clock = lambda: FIXED_NOW
        receipt_b = svc.delete("bundle-alpha", "r2", "second request")
        tombstones = svc.journal_tombstones()
        assert {t["target_id"] for t in tombstones} == {"r1", "r2"}
        assert len(svc.journal_path.read_bytes().splitlines()) == 2
        assert svc.verify_receipt(receipt_b)["ok"] is True
        for path in svc.receipt_paths():
            assert svc.verify_receipt(path)["receipt_id"] is not None


def test_lock_released_on_exception_and_normal_paths():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        # exception path: unknown target raises inside the lock
        assert_raises(
            UnknownTargetError, svc.delete, "bundle-alpha", "ghost", "x",
            lock_timeout=1,
        )
        assert all(
            entry["owner"] is None
            for entry in deletion_mod._ROOT_LOCK_TABLE.values()
        )
        # normal path: a successful delete also releases
        svc.delete("bundle-alpha", "r1", "user request", lock_timeout=1)
        assert all(
            entry["owner"] is None
            for entry in deletion_mod._ROOT_LOCK_TABLE.values()
        )
        # and a bounded acquisition succeeds immediately afterwards
        assert svc.recover(lock_timeout=1) == []


def test_lock_same_thread_reentrant_via_propagation_intake():
    # import_propagation_pack holds the root lock and calls recover()
    # inside it (same thread): the nested acquisition must be re-entrant,
    # never a self-deadlock. The join timeout makes a regression a loud
    # test failure instead of a hang.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        svc.delete("bundle-alpha", "r1", "user request")
        pack = export_propagation_pack(svc, source_root="root-src", now=FIXED_NOW)
        done = threading.Event()

        def intake():
            import_propagation_pack(svc, pack, now=FIXED_NOW, lock_timeout=2)
            done.set()

        thread = threading.Thread(target=intake)
        thread.start()
        thread.join(10)
        assert not thread.is_alive(), "propagation intake deadlocked on its own lock"
        assert done.is_set()


def test_lock_file_is_root_dotfile_outside_every_scanner():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        svc.delete("bundle-alpha", "r1", "user request")
        lock_file = svc.root / ".mbcp.lock"
        assert lock_file.is_file()
        # the dotfile never leaks into a bundle/evidence/receipt namespace
        assert svc.bundle_inventory() == ["bundle-alpha"]
        assert [p.name for p in svc.bundles_dir.glob("*.json")] == [
            "bundle-alpha.json"
        ]
        assert len(svc.receipt_paths()) == 1
        assert svc.verify_receipt(svc.receipt_paths()[0])["ok"] is True


def test_lock_timeout_parameter_default_and_override():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        held = threading.Event()
        release = threading.Event()

        def holding():
            with svc._root_lock(1):
                held.set()
                release.wait(10)

        thread = threading.Thread(target=holding)
        thread.start()
        assert held.wait(10)
        try:
            assert_raises(
                LockTimeoutError, svc.delete, "bundle-alpha", "r1", "x",
                lock_timeout=0.1,
            )
        finally:
            release.set()
            thread.join(10)
        # default timeout is the documented 10s bound
        assert deletion_mod.DEFAULT_LOCK_TIMEOUT == 10.0
        svc.delete("bundle-alpha", "r1", "x")
        assert svc.verify_receipt(svc.receipt_paths()[0])["ok"] is True


# --- FIX 2: receipt inventory block (audit §13) ------------------------------

def test_receipt_binds_pre_deletion_store_inventory():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        svc.put_bundle(build_bundle(
            "bundle-beta", records=[syn_record("r1", "body one")]))
        svc.put_bundle(build_bundle(
            "bundle-gamma", records=[syn_record("r9", "keep me")]))
        receipt = svc.delete("bundle-alpha", "r1", "user request")
        inv = receipt["receipt"]["inventory"]
        # the inventory is the WHOLE pre-deletion store set, sorted
        assert inv["bundle_set"] == ["bundle-alpha", "bundle-beta", "bundle-gamma"]
        # the digest is canonical_sha256 over the sorted id list —
        # order-independent by construction
        assert inv["inventory_digest"] == inventory_digest(inv["bundle_set"])
        assert inv["inventory_digest"] == inventory_digest(
            ["bundle-gamma", "bundle-alpha", "bundle-beta"]
        )
        assert inv["inventory_digest"] == canonical_sha256(inv["bundle_set"])
        assert svc.verify_receipt(receipt)["ok"] is True
        assert svc.verify_receipt(receipt, check_inventory=True)["ok"] is True


def test_verify_receipt_historical_ok_then_divergence_detected():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        receipt = svc.delete("bundle-alpha", "r1", "user request")

        # unchanged root: the opt-in check passes
        assert svc.verify_receipt(receipt, check_inventory=True)["ok"] is True

        # a sibling bundle appears AFTER the deletion (a fresh id — a
        # resurrected copy of the target would rightly fail the plain
        # receipt check via the STALE gate): the receipt is a historical
        # record — plain verification stays ok...
        svc.put_bundle(build_bundle(
            "bundle-laundered", records=[syn_record("r9", "innocent")]))
        assert svc.verify_receipt(receipt)["ok"] is True
        # ...but the opt-in inventory check fails closed, NAMING the id
        check = svc.verify_receipt(receipt, check_inventory=True)
        assert check["ok"] is False
        assert any(
            "bundle-laundered" in problem for problem in check["problems"]
        ), check["problems"]

        # removal divergence is named too
        (svc.bundles_dir / "bundle-laundered.json").unlink()
        (svc.bundles_dir / "bundle-alpha.json").unlink()
        check = svc.verify_receipt(receipt, check_inventory=True)
        assert check["ok"] is False
        assert any("bundle-alpha" in p for p in check["problems"])


def test_verify_receipt_inventory_internal_consistency_is_checked():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        receipt = svc.delete("bundle-alpha", "r1", "user request")
        # hand-tamper the inventory, recompute the artifact digest so the
        # whole-body check passes: the inventory self-consistency check
        # must still catch the mismatch, named.
        forged = json.loads(json.dumps(receipt))
        forged["receipt"]["inventory"]["bundle_set"] = ["bundle-forged"]
        forged["integrity"]["digest"] = canonical_sha256(forged["receipt"])
        result = svc.verify_receipt(forged)
        assert result["ok"] is False
        assert any(
            "inventory_digest does not match" in p for p in result["problems"]
        ), result["problems"]


def test_receipt_without_inventory_block_fails_schema():
    # Breaking change, by design (audit §13): receipts issued before the
    # inventory block do not validate against the tightened schema.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        receipt = svc.delete("bundle-alpha", "r1", "user request")
        legacy = json.loads(json.dumps(receipt))
        del legacy["receipt"]["inventory"]
        legacy["integrity"]["digest"] = canonical_sha256(legacy["receipt"])
        result = svc.verify_receipt(legacy)
        assert result["ok"] is False
        assert any("invalid receipt" in p for p in result["problems"])


def test_reissued_receipt_carries_current_inventory():
    # growth-under-report re-issue path also records the store set.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        svc.delete("bundle-alpha", "r1", "user request")
        write_bundle_direct(svc, _b(("r1", "STALE COPY")))
        svc.recover()
        tail = svc.delete("bundle-alpha", "r1", "retry")
        assert tail["receipt"]["inventory"]["bundle_set"] == ["bundle-alpha"]
        assert svc.verify_receipt(tail, check_inventory=True)["ok"] is True


# --- FIX 3: A-2 silent-skip closure -------------------------------------------

def test_recover_raises_typed_on_malformed_manifest():
    # Mutation target: restore the broad `except (OSError, KeyError,
    # TypeError, ValueError): continue` and this test goes RED (the skip
    # swallows the poison instead of raising).
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one"), ("r2", "keep")))
        svc.delete("bundle-alpha", "r1", "user request")
        stale = svc.bundles_dir / "bundle-stale.json"
        write_bundle_direct(
            svc,
            build_bundle(
                "bundle-stale",
                records=[syn_record("r1", "STALE"), syn_record("s9", "x")],
            ),
        )
        poisoned = json.loads(stale.read_text(encoding="utf-8"))
        raw = json.dumps(poisoned)[:-1] + ', "zz_extra": NaN}'
        stale.write_text(raw, encoding="utf-8")
        try:
            svc.recover()
        except DeletionError as err:
            assert "bundle-stale.json" in str(err)
        else:
            raise AssertionError(
                "recover() silently skipped a malformed manifest (A-2 regression)"
            )
        # the stale copy was NOT laundered by the failed run: recover is
        # all-or-nothing loud — the poisoned file stops recovery before
        # any rewrite, and the typed error names it.
        assert svc.last_recovery_skipped_unreadable == 0


def test_recover_skips_unreadable_entry_and_makes_it_visible():
    # A directory-shaped entry (named *.json) is a GENUINELY unreadable
    # file, not malformed content: recover() skips it, still heals every
    # healthy manifest, and reports the skip count — visible, not silent.
    # (Directory-in-place-of-file is used instead of chmod 000 because
    # permission bits are unreliable when the suite runs as root.)
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one"), ("r2", "keep")))
        svc.delete("bundle-alpha", "r1", "user request")
        write_bundle_direct(
            svc,
            build_bundle(
                "bundle-stale",
                records=[syn_record("r1", "STALE"), syn_record("s9", "x")],
            ),
        )
        (svc.bundles_dir / "not-a-manifest.json").mkdir()
        removed = svc.recover()
        # the stale copy was healed despite the unreadable neighbor
        assert removed == ["r1"]
        manifest = json.loads(
            (svc.bundles_dir / "bundle-stale.json").read_text(encoding="utf-8")
        )
        assert [r["id"] for r in manifest["records"]] == ["s9"]
        assert svc.last_recovery_skipped_unreadable == 1
        # the count is per-run: once the unreadable entry is gone, a clean
        # re-run reports zero skips
        (svc.bundles_dir / "not-a-manifest.json").rmdir()
        assert svc.recover() == []
        assert svc.last_recovery_skipped_unreadable == 0


def test_delete_scan_fails_closed_typed_on_unreadable_entry():
    # The delete/verify scan must NOT skip (a hidden manifest could hold a
    # live copy of a deletion target): an unreadable entry fails closed,
    # typed, naming the file — never a bare IsADirectoryError.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b(("r1", "body one")))
        (svc.bundles_dir / "blocked.json").mkdir()
        try:
            svc.delete("bundle-alpha", "r1", "user request")
        except DeletionError as err:
            assert "blocked.json" in str(err)
            assert not isinstance(err, IsADirectoryError)
        else:
            raise AssertionError("delete() treated an unreadable entry as absent")
