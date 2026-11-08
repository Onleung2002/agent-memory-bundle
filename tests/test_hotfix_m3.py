"""M3 hotfix regressions for the independent adversarial audit (2026-11-08).

Every probe flow from the audit is pinned here against the CORRECTED
behavior (audit §16 test-coverage gaps):

- HIGH#1 (audit §1, probes probe_orphan / probe_wedge / probe_wedge2):
  receipt accounting binds the TARGET, not the tombstone generation;
  a merged tombstone is made durable before any receipt embeds it; the
  receipt names the UNION of every evidence-documented removal plus the
  recovery log.
- HIGH#2 (audit §2): no delete() return path can hand back a receipt
  whose own verify_receipt is ok:False — self-verification runs before
  the receipt is persisted.
- §11 (probe_crash D/E + the wedge scenario): lone surrogates and
  NaN/Infinity are rejected as TYPED validation errors at every boundary
  (build, load, ingest, on-disk legacy files); a poison manifest fails
  before any durable mutation and can never permanently wedge the root.
- §4 (probe_surfaces 1/F): the bundle-id grammar is enforced on both
  validation paths; _safe_id collisions are refused loudly; manifest
  identity is checked on get and in verify_receipt; the receipt id
  preimage binds the tombstone digest.

Probe expectations that encoded the buggy behavior (a narrow ok:True
receipt, an aliased get_bundle, a silently overwritten bundle file) are
DELIBERATELY inverted here.
"""

import json
import tempfile
from pathlib import Path

from m2_helpers import DELETED_AT, OWNER

import mbcp
import mbcp.deletion as deletion_module

from mbcp import (
    BundleIdCollisionError,
    DeletionError,
    DeletionIncompleteError,
    L1DeletionService,
    LoadValidationError,
    build_bundle,
    load,
    make_record,
    validate_bundle,
)

from syn import FIXED_TS, assert_raises

D1 = "2026-11-01T00:00:00Z"
D2 = "2026-11-05T00:00:00Z"


def _record(record_id, body, *, created=FIXED_TS):
    return make_record(record_id, "fact", body, OWNER, created=created)


def _service(tmp, name="svc", *, clock=None):
    service = L1DeletionService(
        Path(tmp) / name, clock=clock or (lambda: DELETED_AT)
    )
    service.put_bundle(
        build_bundle(
            "bundle-alpha",
            records=[
                _record("rec-X", "original secret"),
                _record("rec-keep", "unrelated memory"),
            ],
        )
    )
    return service


def _digest(record):
    return record["integrity"]["digest"]


# ---------------------------------------------------------------------------
# HIGH#1 — audit §1 Repro A (probe_orphan): artifacts change across deletes
# ---------------------------------------------------------------------------


def test_repro_a_receipt_accounts_union_across_tombstone_generations():
    # delete -> a DIFFERENT-digest stale copy resurrects -> retry delete
    # naming a derived artifact. The old code issued an ok:True receipt
    # naming ONLY the stale copy, erasing the real deletion from the
    # accounting (and overwrote the first receipt's file). Corrected: the
    # receipt names the UNION of both removals and both receipt files
    # survive (the id preimage binds the tombstone digest).
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        original = _record("rec-X", "original secret")
        r1 = service.delete("bundle-alpha", "rec-X", "gdpr erasure")
        original_digest = _digest(original)
        assert service.verify_receipt(r1)["ok"] is True
        r1_file = service.receipts_dir / f"{r1['receipt']['id']}.json"
        r1_bytes = r1_file.read_bytes()

        stale = _record("rec-X", "STALE copy", created="2019-01-01T00:00:00Z")
        stale_digest = _digest(stale)
        assert stale_digest != original_digest
        service.put_bundle(build_bundle("bundle-stale", records=[stale]))

        r2 = service.delete(
            "bundle-alpha",
            "rec-X",
            "gdpr erasure",
            derived_artifacts=["embedding-cache-key-X"],
        )

        # CORRECTED probe expectation: the union, not the stale copy alone.
        claimed = {(r["id"], r["digest"]) for r in r2["receipt"]["removed_records"]}
        assert claimed == {("rec-X", original_digest), ("rec-X", stale_digest)}
        assert service.verify_receipt(r2)["ok"] is True
        # the first receipt's file is NOT overwritten (distinct id), and
        # its removal stays in the accounting.
        assert r2["receipt"]["id"] != r1["receipt"]["id"]
        assert len(service.receipt_paths()) == 2
        assert r1_file.read_bytes() == r1_bytes
        # the new tombstone generation is durable in the journal.
        assert any(
            t == r2["receipt"]["tombstone"] for t in service.journal_tombstones()
        )


def test_same_id_overwrite_path_reports_union():
    # The same-id overwrite can still occur when the tombstone generation
    # is unchanged (delete -> same-digest resurrection -> re-delete): the
    # receipt id preimage is identical. Post-fix it is ACCOUNTING-SAFE —
    # the re-issued receipt reports the target-wide union, so the
    # previously-issued receipt's removals never vanish.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        original = _record("rec-X", "original secret")
        original_digest = _digest(original)
        r1 = service.delete("bundle-alpha", "rec-X", "gdpr erasure")

        service.put_bundle(
            build_bundle("bundle-alpha", records=[original])  # same digest back
        )
        r2 = service.delete("bundle-alpha", "rec-X", "gdpr erasure")

        assert r2["receipt"]["id"] == r1["receipt"]["id"]  # overwrite path
        assert [(r["id"], r["digest"]) for r in r2["receipt"]["removed_records"]] == [
            ("rec-X", original_digest)
        ]
        assert service.verify_receipt(r2)["ok"] is True


# ---------------------------------------------------------------------------
# HIGH#1 — audit §1 Repro B (probe_wedge / probe_wedge2): L2-triggered
# generation split; the merged tombstone existed in NO journal generation
# ---------------------------------------------------------------------------


def _split_root(tmp):
    """Destination root with a two-generation journal for rec-X (via an L2
    import), then a resurrected stale copy — the audit's Repro B state."""
    dest = L1DeletionService(Path(tmp) / "dest", clock=lambda: D1)
    dest.put_bundle(
        build_bundle("db", records=[_record("rec-X", "original")])
    )
    dest.delete("db", "rec-X", "gdpr", derived_artifacts=["a"])

    src = L1DeletionService(Path(tmp) / "src", clock=lambda: D2)
    src.put_bundle(build_bundle("sb", records=[_record("rec-X", "copy")]))
    src.delete("sb", "rec-X", "gdpr", derived_artifacts=["b"])
    mbcp.import_propagation_pack(
        dest, mbcp.export_propagation_pack(src, source_root="root-src", now=D2)
    )

    dest.put_bundle(
        build_bundle("db2", records=[_record("rec-X", "stale again")])
    )
    return dest


def test_repro_b_delete_returns_self_verifying_receipt():
    # Old behavior: delete() returned a receipt whose verify_receipt was
    # ok:False ("receipt tombstone does not match any journal tombstone")
    # because the merged tombstone lived in no journal generation. FIX 1
    # appends it unconditionally; FIX 2 self-verifies every return path.
    with tempfile.TemporaryDirectory() as tmp:
        dest = _split_root(tmp)
        receipt = dest.delete("db", "rec-X", "gdpr")
        check = dest.verify_receipt(receipt)
        assert check["ok"] is True, check["problems"]
        assert any(
            t == receipt["receipt"]["tombstone"]
            for t in dest.journal_tombstones()
        )


def test_repro_b_retry_after_generation_split_covers_all_evidence():
    # probe_wedge2: a second delete after the split must return a receipt
    # that names EVERY evidence-documented removal (the old code returned
    # an ok:True receipt that dropped one).
    with tempfile.TemporaryDirectory() as tmp:
        dest = _split_root(tmp)
        r2 = dest.delete("db", "rec-X", "gdpr")
        evidence_digests = {
            entry["digest"] for entry in dest._read_evidence("rec-X")["removals"]
        }
        claimed = {r["digest"] for r in r2["receipt"]["removed_records"]}
        assert evidence_digests <= claimed
        check = dest.verify_receipt(r2)
        assert check["ok"] is True, check["problems"]
        # and the idempotent retry returns that same verifying receipt
        r3 = dest.delete("db", "rec-X", "gdpr")
        assert r3["receipt"]["id"] == r2["receipt"]["id"]
        assert dest.verify_receipt(r3)["ok"] is True


# ---------------------------------------------------------------------------
# HIGH#2 — audit §2: no delete() return path hands back a self-failing
# receipt (probe_surfaces #2 flow: a writer lands between the survivor
# scan and the receipt write)
# ---------------------------------------------------------------------------


def test_delete_never_returns_a_self_failing_receipt():
    # The BACKLOG M2 #1 contract on ALL paths: delete() either returns a
    # receipt that verifies ok against current state, or raises
    # DeletionIncompleteError. A concurrent writer landing after the
    # survivor scan makes the would-be receipt self-failing -> loud raise,
    # never a false claim (the TOCTOU window itself is a pending MEDIUM,
    # out of scope — but the returned receipt can no longer lie).
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp, clock=lambda: D1)
        original_write = service._write_receipt

        def racing_write(*args, **kwargs):
            service.put_bundle(
                build_bundle("b-racer", records=[_record("rec-X", "stale copy")])
            )
            return original_write(*args, **kwargs)

        service._write_receipt = racing_write
        assert_raises(
            DeletionIncompleteError,
            service.delete,
            "bundle-alpha",
            "rec-X",
            "erasure",
        )
        # no receipt was persisted for the failed issuance
        assert service.receipt_paths() == []


# ---------------------------------------------------------------------------
# §11 — hostile-but-parseable inputs are typed errors, never unwrapped
# exceptions; the permanent root wedge is impossible (probe_crash D/E/F,
# audit §11 wedge scenario)
# ---------------------------------------------------------------------------


def test_lone_surrogate_body_rejected_typed_on_load_and_build():
    # probe_crash D: "\ud800" is legal JSON text; it used to crash
    # canonical_bytes with an unwrapped UnicodeEncodeError.
    record = _record("r1", "body")
    record["body"] = "\ud800"
    manifest = {
        "bundle": {"id": "bundle-b"},
        "mbcp_version": "0.1",
        "records": [record],
        "tombstones": [],
    }
    # round-trip through JSON text exactly like the probe does
    wire = json.loads(json.dumps(manifest))
    assert_raises(LoadValidationError, load, [wire])
    from mbcp import _schema  # build-path strictness: ValidationError

    assert_raises(_schema.ValidationError, validate_bundle, wire)


def test_nan_float_rejected_typed_on_load():
    # probe_crash E: json.loads accepts NaN; the manifest dict then
    # crashed canonical_bytes with an unwrapped ValueError.
    manifest = json.loads(
        '{"bundle":{"id":"bundle-b"},"mbcp_version":"0.1",'
        '"records":[],"tombstones":[],"x":NaN}'
    )
    assert manifest["x"] != manifest["x"]  # it really is NaN
    assert_raises(LoadValidationError, load, [manifest])


def test_nan_literal_in_on_disk_manifest_rejected_typed():
    # A legacy file on disk (written by another producer) containing a NaN
    # literal must fail typed — never a bare ValueError from deep in the
    # scan.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        path = service.bundles_dir / "bundle-nan.json"
        path.write_text(
            '{"bundle":{"id":"bundle-nan"},"mbcp_version":"0.1",'
            '"records":[],"tombstones":[],"x":NaN}',
            encoding="utf-8",
        )
        assert_raises(DeletionError, service.get_bundle, "bundle-nan")
        assert_raises(DeletionError, service._bundle_manifests)


def test_put_bundle_rejects_surrogate_at_ingest():
    # The gate: a poison manifest can only reach bundles/ by bypassing
    # put_bundle (another producer writing files directly).
    record = _record("r1", "body")
    record["body"] = "\ud800"
    manifest = build_bundle("bundle-b", records=[])
    manifest["records"] = [record]
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(Path(tmp) / "svc")
        from mbcp import _schema

        assert_raises(_schema.ValidationError, service.put_bundle, manifest)
        assert not (service.bundles_dir / "bundle-b.json").exists()


def test_poison_manifest_fails_before_mutation_and_root_recovers():
    # Audit §11 wedge scenario, corrected: a poison manifest (written
    # directly, bypassing put_bundle) makes delete()/recover() fail with a
    # TYPED error naming the file, BEFORE any journal append; removing the
    # poison file restores full service. Nothing is left in a half-deleted
    # durable state.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        poison = build_bundle("bundle-b2", records=[])
        poison_record = _record("rec-poison", "x")
        poison_record["body"] = "\ud800"
        poison["records"] = [poison_record]
        poison_path = service.bundles_dir / "bundle-b2.json"

        # a healthy journal entry first, so recover() actually scans
        receipt_x = service.delete("bundle-alpha", "rec-X", "erase")
        assert service.verify_receipt(receipt_x)["ok"] is True
        journal_before = service.journal_path.read_text(encoding="utf-8")

        poison_path.write_text(json.dumps(poison), encoding="utf-8")

        try:
            service.delete("bundle-alpha", "rec-keep", "erase")
        except DeletionError as err:
            assert "bundle-b2.json" in str(err)  # names the offending file
        else:
            raise AssertionError("poisoned root: delete() did not fail closed")
        try:
            service.recover()
        except DeletionError as err:
            assert "bundle-b2.json" in str(err)
        else:
            raise AssertionError("poisoned root: recover() did not fail closed")
        # no tombstone was appended for the target we tried to delete:
        # validation ran before any mutation.
        assert service.journal_path.read_text(encoding="utf-8") == journal_before

        poison_path.unlink()
        receipt = service.delete("bundle-alpha", "rec-keep", "erase")
        assert service.verify_receipt(receipt)["ok"] is True


def test_surrogate_target_id_rejected_typed():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        assert_raises(
            DeletionError, service.delete, "bundle-alpha", "\ud800", "erase"
        )


def test_verify_receipt_with_surrogate_target_fails_typed_not_crash():
    # A forged receipt whose target id carries a surrogate must fail
    # verification with a problem, not crash with UnicodeEncodeError.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-X", "erase")
        forged = json.loads(json.dumps(receipt))
        forged["receipt"]["target_id"] = "\ud800"
        # keep the original integrity digest: the forgery is already
        # detectable, and verification must surface problems (including
        # the unreadable-evidence binding) instead of crashing on
        # UnicodeEncodeError inside evidence_path().
        result = service.verify_receipt(forged)
        assert result["ok"] is False
        assert result["problems"]


# ---------------------------------------------------------------------------
# §4 — bundle-id grammar, _safe_id collisions, manifest identity
# (probe_surfaces 1/F)
# ---------------------------------------------------------------------------


def test_bundle_id_grammar_enforced_on_build_and_load():
    from mbcp import _schema

    for bad in ("team/a", "team a", "café", "記憶", "..", "a" * 65, ""):
        assert_raises(
            _schema.ValidationError, build_bundle, bad, records=[]
        ), bad
        manifest = {
            "bundle": {"id": bad},
            "mbcp_version": "0.1",
            "records": [],
            "tombstones": [],
        }
        assert_raises(LoadValidationError, load, [manifest]), bad
    # grammar-valid ids still build
    build_bundle("team_a", records=[])
    build_bundle("a.b-c_d", records=[])


def test_put_bundle_refuses_safe_id_collision():
    # Legacy file on disk whose stored id differs from the requested one
    # (pre-grammar collision class) is NEVER silently overwritten.
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(Path(tmp) / "svc")
        legacy = build_bundle("legacy-id", records=[_record("rec-L", "legacy")])
        legacy_path = service.bundles_dir / "occupied.json"
        service.bundles_dir.mkdir(parents=True)
        legacy_path.write_text(json.dumps(legacy), encoding="utf-8")
        before = legacy_path.read_bytes()

        assert_raises(
            BundleIdCollisionError,
            service.put_bundle,
            build_bundle("occupied", records=[_record("rec-N", "new")]),
        )
        assert legacy_path.read_bytes() == before  # untouched


def test_put_bundle_same_id_overwrite_allowed():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        again = build_bundle(
            "bundle-alpha",
            records=[_record("rec-X", "original secret")],
        )
        service.put_bundle(again)  # same id: refresh, not a collision
        assert service.get_bundle("bundle-alpha") == again


def test_get_bundle_rejects_aliased_manifest():
    # probe_surfaces F, corrected: bundle_path('aliased') exists but the
    # manifest id is 'other-id' -> typed error, never a silent mismatch.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        (service.bundles_dir / "aliased.json").write_text(
            json.dumps(build_bundle("other-id", records=[_record("r2", "b")])),
            encoding="utf-8",
        )
        assert_raises(DeletionError, service.get_bundle, "aliased")
        # the aliased file itself is a VALID manifest (id 'other-id'), so
        # the whole-root scan still lists it — under its DECLARED id:
        scanned = {bid for bid, _p, _m in service._bundle_manifests()}
        assert scanned == {"bundle-alpha", "other-id"}


def test_verify_receipt_checks_bundle_manifest_id_match():
    # Existence is not identity: a receipt naming a bundle whose on-disk
    # manifest declares a DIFFERENT id must not verify ok.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-X", "erase")
        assert service.verify_receipt(receipt)["ok"] is True
        # swap the manifest for an aliased one (legacy/crafted state)
        (service.bundles_dir / "bundle-alpha.json").write_text(
            json.dumps(build_bundle("other-id", records=[])), encoding="utf-8"
        )
        result = service.verify_receipt(receipt)
        assert result["ok"] is False
        assert any("bundle manifest" in p for p in result["problems"])


def test_receipt_id_binds_tombstone_digest():
    # Audit §14 (cheap part): same target, same second, two tombstone
    # generations -> distinct receipt ids, so the first receipt file can
    # never be overwritten by the second (pre-image collision).
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp, clock=lambda: D1)
        r1 = service.delete("bundle-alpha", "rec-X", "erase")
        service.put_bundle(
            build_bundle("bundle-stale", records=[_record("rec-X", "stale")])
        )
        r2 = service.delete(
            "bundle-alpha", "rec-X", "erase", derived_artifacts=["emb:rec-X"]
        )
        assert r1["receipt"]["id"] != r2["receipt"]["id"]
        assert len(service.receipt_paths()) == 2
