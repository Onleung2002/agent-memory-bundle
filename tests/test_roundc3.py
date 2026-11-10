"""M4 Round C Batch 3 — three audit-derived tightenings (worker: round C3).

FIX 1 (ADV-C2-3): put_bundle and export_propagation_pack run under the
same root advisory lock as delete()/recover()/propagation intake. A put
racing a delete now WAITS for the lock instead of landing mid-delete —
after the deletion-time inventory snapshot but before the receipt is
written, the born-inventory-divergent receipt hole — and an export can no
longer read the bundles+journal torn mid-delete. Concurrency tests force
the race with explicit events and typed lock timeouts (never sleep-based
timing); the lock-mutation targets are the typed-timeout, ordering and
receipt-inventory assertions below.

FIX 2 (ADV-C2-3/A-4): _safe_id() is injective. The old trailing-punctuation
folding mapped distinct grammar-valid ids (``"abc"`` / ``"abc_"``) onto one
on-disk filename. Ids the folding leaves unchanged keep their verbatim
stem; a folded id gains a deterministic disambiguator (first 12 hex of its
canonical SHA-256) — identical ids always map to identical names, distinct
ids never collide, and a mapped filename already held by a DIFFERENT id is
refused with the typed BundleIdCollisionError (never a silent overwrite).

FIX 3 (SPEC 1.5, amended 2026-11-10): id comparison is NFC + ASCII
case-insensitive; storage stays verbatim. normalize_id() gained a pure-ASCII
case fold (translate, not Unicode lower()), so every comparison that
already routed through normalize_id — tombstone target vs record id, the
load pre-pass, duplicate resolution, the write-boundary gate, recover() —
became case-insensitive in one place, and the raw ``==`` comparisons in the
delete/verify paths now route through the same normalization. Residual:
NFC is identity on the ASCII grammar, so NFD closure stays
grammar-rejection-based (unchanged); bundle-id FILENAME lookup stays
verbatim (case-variant bundle ids are different files — documented, out of
scope for this batch).
"""
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mbcp import (
    L1DeletionService,
    LockTimeoutError,
    TombstonedIdRejectedError,
    build_bundle,
    canonical_bytes,
    canonical_sha256,
    export_propagation_pack,
    load,
    make_tombstone,
    normalize_id,
)
from mbcp.deletion import BundleIdCollisionError, _safe_id

from syn import assert_raises, syn_record, write_bundle_direct

FIXED_NOW = "2026-11-06T00:00:00Z"


def _svc(tmp, **kwargs):
    kwargs.setdefault("clock", lambda: FIXED_NOW)
    return L1DeletionService(Path(tmp), **kwargs)


def _b(bundle_id, *pairs):
    return build_bundle(
        bundle_id,
        records=[syn_record(rid, body) for rid, body in pairs],
    )


def _blocking_delete(svc, results, key, entered, release):
    """delete() whose clock blocks INSIDE the locked critical section."""

    def blocking_clock():
        entered.set()
        assert release.wait(10), "test event never released"
        return FIXED_NOW

    def run():
        svc._clock = blocking_clock
        try:
            svc.delete("bundle-alpha", "r1", "racing request")
            results[key] = "ok"
        except Exception as err:  # noqa: BLE001
            results[key] = err

    thread = threading.Thread(target=run)
    thread.start()
    return thread


# --- FIX 1: put_bundle + export under the root lock (ADV-C2-3) --------------

def test_put_bundle_racing_delete_blocks_then_times_out_typed():
    # Thread A enters delete() and blocks INSIDE the critical section.
    # Thread B's put_bundle on the same root must WAIT on the lock and,
    # past its bounded timeout, raise the typed LockTimeoutError —
    # deterministically (without the lock B would write instantly and this
    # assertion fails: the mutation target). The non-target bundle can no
    # longer land mid-delete.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b("bundle-alpha", ("r1", "body one"), ("r2", "keep")))
        entered = threading.Event()
        release = threading.Event()
        results = {}

        thread_a = _blocking_delete(svc, results, "a", entered, release)
        assert entered.wait(10), "thread A never reached the critical section"

        def put_b():
            try:
                svc.put_bundle(
                    _b("bundle-beta", ("r9", "innocent")),
                    lock_timeout=0.3,
                )
                results["b"] = "ok"
            except Exception as err:  # noqa: BLE001
                results["b"] = err

        thread_b = threading.Thread(target=put_b)
        thread_b.start()
        thread_b.join(10)
        assert not thread_b.is_alive(), "thread B blocked instead of timing out"
        assert isinstance(results["b"], LockTimeoutError), results
        # the put did NOT land mid-delete
        assert not (svc.bundles_dir / "bundle-beta.json").exists()

        release.set()
        thread_a.join(10)
        assert not thread_a.is_alive()
        assert results["a"] == "ok", results
        receipt = svc._latest_receipt("r1")
        assert receipt is not None
        # the receipt is NOT born inventory-divergent: its recorded store
        # set is exactly the deletion-time set, and the opt-in inventory
        # check passes (the bundle that raced the window never landed)
        assert receipt["receipt"]["inventory"]["bundle_set"] == ["bundle-alpha"]
        assert svc.verify_receipt(receipt, check_inventory=True)["ok"] is True

        # with the lock free, the same put succeeds immediately
        path = svc.put_bundle(_b("bundle-beta", ("r9", "innocent")))
        assert path.name == "bundle-beta.json"
        # ...and only THEN does store growth diverge from the historical
        # receipt (a bundle added after the deletion is named, fail-closed)
        check = svc.verify_receipt(receipt, check_inventory=True)
        assert check["ok"] is False
        assert any("bundle-beta" in p for p in check["problems"])


def test_put_bundle_racing_target_copy_waits_then_fail_closed_typed():
    # A copy of the DELETE TARGET put during the window now waits for the
    # lock, lands after the deletion is durable, and hits the write-
    # boundary gate: TombstonedIdRejectedError, typed. The delete itself
    # completes truthfully (receipt ok) — no interleaved state.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b("bundle-alpha", ("r1", "body one"), ("r2", "keep")))
        entered = threading.Event()
        release = threading.Event()
        results = {}

        thread_a = _blocking_delete(svc, results, "a", entered, release)
        assert entered.wait(10), "thread A never reached the critical section"

        def put_target_copy():
            try:
                svc.put_bundle(
                    _b("bundle-stale", ("r1", "resurrection attempt")),
                    lock_timeout=5,
                )
                results["b"] = "ok"
            except Exception as err:  # noqa: BLE001
                results["b"] = err

        thread_b = threading.Thread(target=put_target_copy)
        thread_b.start()
        release.set()
        thread_a.join(10)
        thread_b.join(10)
        assert not thread_a.is_alive() and not thread_b.is_alive()
        assert results["a"] == "ok", results
        assert isinstance(results["b"], TombstonedIdRejectedError), results
        assert not (svc.bundles_dir / "bundle-stale.json").exists()
        receipt = svc._latest_receipt("r1")
        assert svc.verify_receipt(receipt)["ok"] is True


def test_export_propagation_pack_racing_delete_times_out_typed():
    # An export's journal read must not run torn mid-delete: while a delete
    # holds the root lock, export_propagation_pack waits and past its
    # bounded timeout raises the typed LockTimeoutError (mutation target:
    # without the export-side lock the call proceeds instantly).
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b("bundle-alpha", ("r1", "body one")))
        entered = threading.Event()
        release = threading.Event()
        results = {}

        thread_a = _blocking_delete(svc, results, "a", entered, release)
        assert entered.wait(10), "thread A never reached the critical section"

        def export_b():
            try:
                export_propagation_pack(
                    svc, source_root="root-src", now=FIXED_NOW,
                    lock_timeout=0.3,
                )
                results["b"] = "ok"
            except Exception as err:  # noqa: BLE001
                results["b"] = err

        thread_b = threading.Thread(target=export_b)
        thread_b.start()
        thread_b.join(10)
        assert not thread_b.is_alive(), "export blocked instead of timing out"
        assert isinstance(results["b"], LockTimeoutError), results

        release.set()
        thread_a.join(10)
        assert results["a"] == "ok", results
        # with the lock free the export succeeds and binds the journal
        pack = export_propagation_pack(
            svc, source_root="root-src", now=FIXED_NOW)
        assert [t["target_id"] for t in pack["pack"]["tombstones"]] == ["r1"]


def test_racing_refresh_keeps_receipt_inventory_consistent():
    # W2 advisory scenario, locked version: a racing put that only REFRESHES
    # a bundle id already in the deletion-time store set waits out the
    # delete, lands afterwards, and the receipt's opt-in inventory check
    # still passes — the store SET never changed, so the receipt is not
    # born (nor becomes) inventory-divergent.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b("bundle-alpha", ("r1", "body one"), ("r2", "keep")))
        entered = threading.Event()
        release = threading.Event()
        results = {}

        thread_a = _blocking_delete(svc, results, "a", entered, release)
        assert entered.wait(10), "thread A never reached the critical section"

        def refresh_alpha():
            try:
                # same bundle id, refreshed content, no tombstoned id
                svc.put_bundle(
                    _b("bundle-alpha", ("r2", "keep"), ("r9", "added later")),
                    lock_timeout=5,
                )
                results["b"] = "ok"
            except Exception as err:  # noqa: BLE001
                results["b"] = err

        thread_b = threading.Thread(target=refresh_alpha)
        thread_b.start()
        release.set()
        thread_a.join(10)
        thread_b.join(10)
        assert not thread_a.is_alive() and not thread_b.is_alive()
        assert results["a"] == "ok", results
        assert results["b"] == "ok", results
        receipt = svc._latest_receipt("r1")
        assert receipt["receipt"]["inventory"]["bundle_set"] == ["bundle-alpha"]
        assert svc.verify_receipt(receipt, check_inventory=True)["ok"] is True
        # the refreshed content actually landed
        manifest = svc.get_bundle("bundle-alpha")
        assert sorted(r["id"] for r in manifest["records"]) == ["r2", "r9"]


# --- FIX 2: injective _safe_id (ADV-C2-3/A-4) --------------------------------

def test_safe_id_injective_distinct_files_both_usable():
    # "abc" and "abc_" are BOTH grammar-valid; the old folding mapped them
    # onto one file. Now: distinct stems, deterministic, roundtrip-usable.
    assert _safe_id("abc") == "abc"  # unchanged ids keep legacy names
    assert _safe_id("abc_") != _safe_id("abc")
    assert _safe_id("abc_") == _safe_id("abc_")  # determinism
    assert _safe_id("_lead") != _safe_id("lead")
    # the disambiguator is content-derived: a different folded id with the
    # same stem still gets its own file
    assert _safe_id("abc_") != _safe_id("abc__")
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b("abc", ("r1", "plain")))
        svc.put_bundle(_b("abc_", ("r2", "underscored")))
        files = sorted(p.name for p in svc.bundles_dir.glob("*.json"))
        assert files == sorted(
            f"{_safe_id(i)}.json" for i in ("abc", "abc_")
        ), files
        assert len(files) == 2
        # both usable through the service API (verbatim id roundtrip)
        assert svc.get_bundle("abc")["bundle"]["id"] == "abc"
        assert svc.get_bundle("abc_")["bundle"]["id"] == "abc_"
        # bundle_inventory sees both verbatim ids
        assert svc.bundle_inventory() == ["abc", "abc_"]


def test_safe_id_collision_refusal_stays_typed():
    # A mapped filename already held by a DIFFERENT id is refused typed —
    # never silently overwritten — under the injective scheme too.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        occupied = _safe_id("abc_")  # folded + disambiguated stem
        svc.bundles_dir.mkdir(parents=True)
        legacy = _b("other-id", ("rL", "legacy"))
        legacy_path = svc.bundles_dir / f"{occupied}.json"
        legacy_path.write_bytes(canonical_bytes(legacy))
        before = legacy_path.read_bytes()
        assert_raises(
            BundleIdCollisionError,
            svc.put_bundle,
            _b("abc_", ("rN", "new")),
        )
        assert legacy_path.read_bytes() == before  # untouched


def test_trailing_punctuation_bundle_full_lifecycle():
    # delete -> receipt -> recover roundtrip works end to end for a bundle
    # id whose filename the folding rewrites.
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b("abc_", ("r1", "body one"), ("r2", "keep")))
        receipt = svc.delete("abc_", "r1", "user request")
        assert receipt["receipt"]["bundle_id"] == "abc_"  # verbatim storage
        assert svc.verify_receipt(receipt)["ok"] is True
        # an out-of-band stale copy of the target (same channel the real
        # attack/legacy path uses) is healed by recover() against the
        # rewritten filename; the recovery grows known removals, so the
        # delete retry re-issues (supersession, semantics (i)) and the
        # chain tail verifies
        write_bundle_direct(
            svc, _b("abc_", ("r1", "STALE COPY"), ("r2", "keep")))
        assert svc.recover() == ["r1"]
        tail = svc.delete("abc_", "r1", "retry")
        assert tail["receipt"]["supersedes"] == receipt["integrity"]["digest"]
        assert svc.verify_receipt(tail)["ok"] is True
        assert svc.verify_receipt(receipt)["ok"] is False  # superseded
        # idempotent second recover, tombstone still filters at load
        assert svc.recover() == []
        manifest = svc.get_bundle("abc_")
        assert [r["id"] for r in manifest["records"]] == ["r2"]


# --- FIX 3: NFC + ASCII case-insensitive id comparison (SPEC 1.5) ------------

def test_normalize_id_ascii_case_fold():
    assert normalize_id("Rec-1") == normalize_id("rec-1") == "rec-1"
    assert normalize_id("REC-1") == "rec-1"
    # pure ASCII fold: non-ASCII passes through untouched (grammar rejects
    # it at ingest anyway; the fold must stay deterministic there too)
    assert normalize_id("café") == "café"
    # NFC still applies before the fold (NFD 'e + combining acute')
    assert normalize_id("café") == "café"
    # determinism / idempotence
    assert normalize_id(normalize_id("A_b-")) == normalize_id("A_b-")


def test_load_tombstone_filters_case_variant_both_directions():
    upper = build_bundle(
        "bundle-alpha",
        records=[syn_record("Rec-1", "upper copy")],
        tombstones=[make_tombstone(
            "Rec-1", "erased", deleted_at=FIXED_NOW)],
    )
    assert load([upper]) == []
    # reverse: lowercase tombstone target, uppercase record id
    lower = build_bundle(
        "bundle-alpha",
        records=[syn_record("rec-1", "lower copy")],
        tombstones=[make_tombstone(
            "rec-1", "erased", deleted_at=FIXED_NOW)],
    )
    assert load([lower]) == []
    # and the surviving SIBLING (distinct id) is untouched, verbatim
    mixed = build_bundle(
        "bundle-alpha",
        records=[syn_record("rec-1", "lower copy"), syn_record("rec-2", "keep")],
        tombstones=[make_tombstone(
            "REC-1", "erased", deleted_at=FIXED_NOW)],
    )
    loaded = load([mixed])
    assert [r["id"] for r in loaded] == ["rec-2"]


def test_duplicate_resolution_case_insensitive_digest_tiebreak():
    # "REC-1" and "rec-1" holding the SAME body are ONE record: the
    # case-insensitive group merges, and the winner is decided by the
    # duplicate tiebreak (greatest canonical SHA-256 of the record) —
    # fully order-independent.
    rec_upper = syn_record("REC-1", "same body")
    rec_lower = syn_record("rec-1", "same body")
    m_upper_first = build_bundle("bundle-a", records=[rec_upper])
    m_lower_first = build_bundle("bundle-b", records=[rec_lower])
    m_upper_only = build_bundle("bundle-a", records=[rec_upper])
    m_lower_only = build_bundle("bundle-b", records=[rec_lower])

    winner_digest = max(
        canonical_sha256(rec_upper), canonical_sha256(rec_lower)
    )
    for pair in (
        [m_upper_first, m_lower_only],
        [m_lower_only, m_upper_first],
    ):
        loaded = load(pair)
        assert len(loaded) == 1, loaded
        assert canonical_sha256(loaded[0]) == winner_digest
    # distinct-case DIFFERENT-content records also resolve by digest,
    # order-independently
    rec_other = syn_record("rec-1", "different body")
    m_other = build_bundle("bundle-b", records=[rec_other])
    first = load([m_upper_only, m_other])
    second = load([m_other, m_upper_only])
    assert len(first) == 1 and first == second
    assert canonical_sha256(first[0]) == max(
        canonical_sha256(rec_upper), canonical_sha256(rec_other)
    )


def test_put_bundle_rejects_case_variant_of_tombstoned_id():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b("bundle-alpha", ("Rec-1", "body one")))
        svc.delete("bundle-alpha", "Rec-1", "user request")
        # lowercase copy of the tombstoned id is the SAME id now
        assert_raises(
            TombstonedIdRejectedError,
            svc.put_bundle,
            _b("bundle-beta", ("rec-1", "resurrection")),
        )
        assert_raises(
            TombstonedIdRejectedError,
            svc.put_bundle,
            _b("bundle-beta", ("REC-1", "resurrection")),
        )
        # an id that merely shares a case-folded prefix is NOT tombstoned
        svc.put_bundle(_b("bundle-beta", ("rec-10", "unrelated")))
        assert svc.get_bundle("bundle-beta")["records"][0]["id"] == "rec-10"


def test_delete_matches_case_variant_target_verbatim_storage():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _svc(tmp)
        svc.put_bundle(_b("bundle-alpha", ("rec-1", "body one"), ("r2", "keep")))
        # the delete names the target in a different case: the stored copy
        # is removed, but the tombstone/receipt keep the CALLER's verbatim id
        receipt = svc.delete("bundle-alpha", "Rec-1", "user request")
        assert receipt["receipt"]["target_id"] == "Rec-1"
        assert svc.verify_receipt(receipt)["ok"] is True
        manifest = svc.get_bundle("bundle-alpha")
        assert [r["id"] for r in manifest["records"]] == ["r2"]
        # retry in yet another case returns the SAME chain-tail receipt
        again = svc.delete("bundle-alpha", "REC-1", "retry")
        assert again["receipt"]["id"] == receipt["receipt"]["id"]
        # a case-variant stale copy is healed by recover() too; the retry
        # re-issues over the grown recovery accounting (supersession) and
        # the chain tail verifies
        write_bundle_direct(
            svc, _b("bundle-alpha", ("REC-1", "STALE"), ("r2", "keep")))
        assert svc.recover() == ["REC-1"]
        tail = svc.delete("bundle-alpha", "rec-1", "retry after recovery")
        assert tail["receipt"]["supersedes"] == receipt["integrity"]["digest"]
        assert svc.verify_receipt(tail)["ok"] is True
