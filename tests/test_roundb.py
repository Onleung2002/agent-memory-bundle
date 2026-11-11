"""M4 Round B: L4 ed25519 attestation (SPEC 1.2.6), fail-closed intake
authorization (SPEC 1.2.7), pending retry semantics (SPEC 1.2.8).

Covers the three FIX layers end to end through the public API:

FIX 1 — receipt envelopes are ed25519-signed by the issuing root's
per-root keypair (``.mbcp.key``, mode 0600, excluded from every scan like
``.mbcp.lock``); ``verify_receipt`` fails closed on (a) a missing
``attestation_sig`` field, (b) a body tampered and re-signed by a
DIFFERENT key while keeping the original embedded pubkey, and (c) envelope
bytes tampered while keeping the original signature. ed25519 is
deterministic: same envelope + same key -> byte-identical signature.

FIX 2 — propagation packs are signed by the source root's keypair and
intake verifies the signature BEFORE the digest-chain gate.

FIX 3 — intake authorization is fail-closed against the root's
authorized-source accept-list: no config / empty config / malformed
config / unknown key_id / pubkey mismatch all reject; only a listed
key_id with the matching pubkey imports. No accepted-unverified tier.

FIX 4 — the pending channel carries SIGNED packs only (unsigned enqueue
is a typed reject); retries are driven by an injected clock (deterministic
retry_count + next_attempt_at backoff); success acks resolve the pending
entry; repeated failure past MAX_PROPAGATION_RETRIES dead-letters the
entry (typed-visible via dead_lettered_entries(), terminal — never
silently dropped, never infinitely retried).
"""

import json
import stat
import tempfile
from pathlib import Path

from m2_helpers import DELETED_AT, OWNER

from mbcp import (
    L1DeletionService,
    MAX_PROPAGATION_RETRIES,
    RETRY_BACKOFF_SECONDS,
    AttestationVerifyError,
    AuthorizationRejectedError,
    DeadLetterPropagationError,
    MissingAttestationError,
    authorize_source,
    build_bundle,
    build_receipt,
    canonical_bytes,
    canonical_sha256,
    deauthorize_source,
    export_propagation_pack,
    import_propagation_pack,
    load_authorized_sources,
    load_keypair,
    make_record,
    make_tombstone,
    pending_propagation_entries,
    read_propagation_journal,
    record_pending_propagation,
    retry_pending_propagation,
    dead_lettered_entries,
    generate_keypair,
)
from mbcp.attestation import key_id_for_pubkey, sign_envelope

from syn import FIXED_TS, assert_raises, syn_keypair

T0 = "2026-11-10T00:00:00Z"
T1 = "2026-11-10T00:05:00Z"
T2 = "2026-11-10T00:10:00Z"


def _service(tmp, name="root", clock=None):
    service = L1DeletionService(
        Path(tmp) / name, clock=clock or (lambda: DELETED_AT)
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


def _delete_and_export(tmp):
    """A source root with one deletion, and its signed pack."""
    source = _service(tmp, "source")
    source.delete("bundle-alpha", "rec-002", "synthetic erasure")
    pack = export_propagation_pack(
        source, source_root="root-source", now=T0
    )
    return source, pack


# ---------------------------------------------------------------------------
# FIX 1: receipt envelope attestation
# ---------------------------------------------------------------------------


def test_service_receipt_carries_l4_attestation_and_verifies():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        body = receipt["receipt"]
        assert len(receipt["attestation_sig"]) == 128
        assert body["key_id"] == key_id_for_pubkey(
            bytes.fromhex(body["attestation_pubkey"])
        )
        key = load_keypair(service.root)
        assert body["attestation_pubkey"] == key.pubkey_hex
        assert body["key_id"] == key.key_id
        check = service.verify_receipt(receipt)
        assert check["ok"] is True, check
        assert check["problems"] == []


def test_receipt_signing_is_byte_deterministic():
    # ed25519 determinism pinned at the artifact level: same inputs +
    # same key -> byte-identical receipt (SPEC 1.2.6).
    keypair = syn_keypair()
    tombstone = make_tombstone("rec-002", "synthetic erasure", deleted_at=DELETED_AT)
    removed = [{"id": "rec-002", "integrity": {"digest": "ab" * 32}}]
    r1 = build_receipt(
        "bundle-alpha", tombstone, removed, issued_at=T0, keypair=keypair
    )
    r2 = build_receipt(
        "bundle-alpha", tombstone, removed, issued_at=T0, keypair=keypair
    )
    assert r1 == r2
    assert r1["attestation_sig"] == r2["attestation_sig"]


def test_verify_receipt_rejects_missing_attestation_sig_field():
    # forgery mode (a): NO signature field — the schema gate names it.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        unsigned = json.loads(json.dumps(receipt))
        del unsigned["attestation_sig"]
        check = service.verify_receipt(unsigned)
        assert check["ok"] is False
        assert any("attestation_sig" in p for p in check["problems"]), check


def test_verify_receipt_rejects_body_resigned_by_different_key():
    # forgery mode (b): the attacker tampers the body and re-signs with
    # their OWN key but keeps the ORIGINAL embedded pubkey — the signature
    # fails against the embedded pubkey, fail-closed, named.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        forged = json.loads(json.dumps(receipt))
        forged["receipt"]["reason"] = "laundered reason"
        forged["receipt"]["removed_records"] = [
            {"id": "rec-002", "digest": "0" * 64}
        ]
        forged["integrity"]["digest"] = canonical_sha256(forged["receipt"])
        attacker = generate_keypair()
        forged["attestation_sig"] = __import__(
            "mbcp._ed25519", fromlist=["signature"]
        ).signature(
            canonical_bytes(
                {k: v for k, v in forged.items() if k != "attestation_sig"}
            ),
            attacker.seed,
            bytes.fromhex(forged["receipt"]["attestation_pubkey"]),
        ).hex()
        check = service.verify_receipt(forged)
        assert check["ok"] is False
        assert any(
            "does not verify against the embedded pubkey" in p
            for p in check["problems"]
        ), check


def test_verify_receipt_full_attacker_resign_fails_at_evidence_binding():
    # honest layer documentation: an attacker who re-signs with their own
    # key AND replaces the embedded pubkey/key_id produces a receipt whose
    # ATTESTATION verifies (the signature is mathematically valid) — the
    # forgery is caught by the durable bindings underneath (journal
    # tombstone + removal evidence), which the attacker cannot fabricate.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        forged = json.loads(json.dumps(receipt))
        forged["receipt"]["removed_records"] = [
            {"id": "rec-002", "digest": "0" * 64}
        ]
        del forged["attestation_sig"]
        del forged["receipt"]["key_id"]
        del forged["receipt"]["attestation_pubkey"]
        forged = sign_envelope(forged, generate_keypair(), body_field="receipt")
        check = service.verify_receipt(forged)
        assert check["ok"] is False
        assert any("deletion evidence" in p for p in check["problems"]), check


def test_verify_receipt_rejects_tampered_envelope_with_original_sig():
    # forgery mode (c): envelope bytes tampered, ORIGINAL signature kept —
    # both the self-digest and the attestation fail, named.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        forged = json.loads(json.dumps(receipt))
        forged["receipt"]["reason"] = "rewritten reason"
        check = service.verify_receipt(forged)
        assert check["ok"] is False
        assert any("tampered" in p for p in check["problems"]), check


def test_verify_receipt_rejects_key_id_pubkey_fingerprint_mismatch():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        forged = json.loads(json.dumps(receipt))
        forged["receipt"]["key_id"] = "f" * 16
        # recompute the self-digest so the ONLY problem is the fingerprint
        forged["integrity"]["digest"] = canonical_sha256(forged["receipt"])
        # re-sign over the tampered body so the signature itself verifies
        key = load_keypair(service.root)
        forged["attestation_sig"] = sign_envelope(
            {"receipt": forged["receipt"], "integrity": forged["integrity"]},
            key,
            body_field="receipt",
        )["attestation_sig"]
        check = service.verify_receipt(forged)
        assert check["ok"] is False
        assert any("fingerprint mismatch" in p for p in check["problems"]), check


def test_key_file_permissions_and_scan_exclusion():
    # SPEC 1.2.6: .mbcp.key is written 0600 and excluded from ALL scans,
    # same discipline as .mbcp.lock (it lives at the root, outside the
    # bundles/receipts/journal namespaces — here pinned behaviorally).
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        key_path = service.root / ".mbcp.key"
        assert key_path.exists()
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        # inventory scans only bundles/: the key never appears
        assert service.bundle_inventory() == ["bundle-alpha"]
        assert ".mbcp.key" not in {
            p.name for p in service.bundles_dir.glob("*.json")
        }
        assert ".mbcp.key" not in {p.name for p in service.receipt_paths()}
        # recovery replays the journal and never touches the key file
        before = key_path.read_bytes()
        assert service.recover() == []
        assert key_path.read_bytes() == before


def test_key_survives_service_restart_and_receipts_still_verify():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        restarted = L1DeletionService(service.root, clock=lambda: DELETED_AT)
        check = restarted.verify_receipt(receipt)
        assert check["ok"] is True, check
        # the key file round-trips: same key, same key_id
        assert load_keypair(restarted.root).key_id == receipt["receipt"]["key_id"]


def test_corrupt_key_file_fails_typed_not_silent():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-002", "synthetic erasure")
        key_path = service.root / ".mbcp.key"
        key_path.write_text("{not json", encoding="utf-8")
        try:
            load_keypair(service.root)
        except Exception as err:
            assert "corrupt signing key" in str(err), err
        else:
            raise AssertionError("expected a typed corrupt-key error")
        # a fresh service instance refuses to sign with a corrupt key
        restarted = L1DeletionService(service.root, clock=lambda: DELETED_AT)
        assert_raises(Exception, restarted._attestation_keypair)


# ---------------------------------------------------------------------------
# FIX 2: propagation pack signing (layer order + determinism)
# ---------------------------------------------------------------------------


def test_pack_attestation_is_deterministic_per_root():
    with tempfile.TemporaryDirectory() as tmp:
        source, pack1 = _delete_and_export(tmp)
        pack2 = export_propagation_pack(
            source, source_root="root-source", now=T0
        )
    assert pack1["attestation_sig"] == pack2["attestation_sig"]
    assert canonical_bytes(pack1) == canonical_bytes(pack2)


def test_pack_import_verifies_signature_before_digest_chain():
    # a pack whose SIGNATURE is fine but whose digest chain is broken
    # must fail with PackValidationError (not an attestation error) —
    # proving the signature gate ran first and PASSED.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _service(tmp, "dest")
        authorize_source(
            dest.root, pack["pack"]["key_id"], pack["pack"]["attestation_pubkey"]
        )
        broken = json.loads(json.dumps(pack))
        broken["pack"]["tombstone_digests"] = []  # digest-chain break
        # re-sign with the SOURCE key so the signature gate PASSES and the
        # failure provably comes from the digest-chain layer underneath
        source_key = load_keypair(Path(tmp) / "source")
        del broken["attestation_sig"]
        del broken["pack"]["key_id"]
        del broken["pack"]["attestation_pubkey"]
        broken = sign_envelope(broken, source_key, body_field="pack")
        assert_raises(
            __import__("mbcp").PackValidationError,
            import_propagation_pack, dest.root, broken, now=T1,
        )


def test_intake_authorization_gate_runs_before_the_digest_chain_gate():
    # ADV-B3 (M4 Round B mini): the SAME digest-broken, source-re-signed
    # pack that test_pack_import_verifies_signature_before_digest_chain
    # proves fails at the digest-chain layer must instead fail with
    # AuthorizationRejectedError when the destination does NOT list the
    # source key. The signature still verifies (the source key signed the
    # broken bytes), so the failure can only come from the accept-list
    # gate — which therefore provably runs BEFORE _validate_pack.
    # An unrelated key IS listed here, so this pins the ordering rather
    # than the absent-config fail-closed path (pinned separately below).
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _service(tmp, "dest")
        foreign = generate_keypair()
        authorize_source(dest.root, foreign.key_id, foreign.pubkey_hex)
        broken = json.loads(json.dumps(pack))
        broken["pack"]["tombstone_digests"] = []  # digest-chain break
        source_key = load_keypair(Path(tmp) / "source")
        del broken["attestation_sig"]
        del broken["pack"]["key_id"]
        del broken["pack"]["attestation_pubkey"]
        broken = sign_envelope(broken, source_key, body_field="pack")
        assert_raises(
            AuthorizationRejectedError,
            import_propagation_pack, dest.root, broken, now=T1,
        )


# ---------------------------------------------------------------------------
# FIX 3: intake authorization accept-list (fail-closed matrix)
# ---------------------------------------------------------------------------


def _dest_with_stale_copy(tmp):
    dest = _service(tmp, "dest")
    return dest


def test_intake_without_accept_list_rejects_everything():
    # SPEC 1.2.7: absent config = typed reject of ALL packs.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        assert_raises(
            AuthorizationRejectedError,
            import_propagation_pack, dest.root, pack, now=T1,
        )
        # nothing applied
        assert {r["id"] for r in dest.get_bundle("bundle-alpha")["records"]} == {
            "rec-001",
            "rec-002",
        }
        assert read_propagation_journal(dest.root) == []


def test_intake_with_unrelated_accept_list_key_rejects():
    # config exists but lists ANOTHER key -> unknown key_id, reject.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        foreign = generate_keypair()
        authorize_source(dest.root, foreign.key_id, foreign.pubkey_hex)
        assert_raises(
            AuthorizationRejectedError,
            import_propagation_pack, dest.root, pack, now=T1,
        )


def test_intake_with_listed_pubkey_mismatch_rejects():
    # key_id is listed but the LISTED pubkey differs from the pack's
    # embedded pubkey (stale/hand-edited config entry — authorize_source
    # itself pins the fingerprint, so the divergence can only live in the
    # file, which is exactly what the fail-closed gate must catch).
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        authorize_source(
            dest.root, pack["pack"]["key_id"], pack["pack"]["attestation_pubkey"]
        )
        cfg = dest.root / ".mbcp.authorized_sources.json"
        stale = json.loads(cfg.read_text(encoding="utf-8"))
        stale[pack["pack"]["key_id"]] = generate_keypair().pubkey_hex
        cfg.write_text(json.dumps(stale), encoding="utf-8")
        assert_raises(
            AuthorizationRejectedError,
            import_propagation_pack, dest.root, pack, now=T1,
        )


def test_intake_with_authorized_key_imports():
    # the matrix green case: listed key_id + matching pubkey -> import.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        authorize_source(
            dest.root, pack["pack"]["key_id"], pack["pack"]["attestation_pubkey"]
        )
        ack = import_propagation_pack(dest.root, pack, now=T1)
        assert ack["ack"]["for_source_root"] == "root-source"
        assert "rec-002" not in {
            r["id"] for r in dest.get_bundle("bundle-alpha")["records"]
        }


def test_intake_malformed_accept_list_fails_closed_typed():
    # malformed config (unparseable / not an object / bad entry shapes) is
    # a typed reject, NEVER a crash and never an open gate.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        cfg = dest.root / ".mbcp.authorized_sources.json"
        for payload in ("{not json", "[1, 2]", '{"abcd": "not-hex-pubkey"}'):
            cfg.write_text(payload, encoding="utf-8")
            assert_raises(
                AuthorizationRejectedError,
                import_propagation_pack, dest.root, pack, now=T1,
            )
        # and an empty object is an EMPTY list -> fail-closed too
        cfg.write_text("{}", encoding="utf-8")
        assert_raises(
            AuthorizationRejectedError,
            import_propagation_pack, dest.root, pack, now=T1,
        )


def test_accept_list_is_root_config_outside_all_scans():
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        authorize_source(
            dest.root, pack["pack"]["key_id"], pack["pack"]["attestation_pubkey"]
        )
        # the config never appears in any store scan
        assert dest.bundle_inventory() == ["bundle-alpha"]
        assert ".mbcp.authorized_sources.json" not in {
            p.name for p in dest.bundles_dir.glob("*.json")
        }
        assert load_authorized_sources(dest.root) == {
            pack["pack"]["key_id"]: pack["pack"]["attestation_pubkey"]
        }
        # deauthorization closes the gate again
        deauthorize_source(dest.root, pack["pack"]["key_id"])
        assert_raises(
            AuthorizationRejectedError,
            import_propagation_pack, dest.root, pack, now=T1,
        )


# ---------------------------------------------------------------------------
# FIX 4: pending retry semantics (SPEC 1.2.8)
# ---------------------------------------------------------------------------


def test_unsigned_pack_cannot_enter_pending_channel():
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        unsigned = json.loads(json.dumps(pack))
        del unsigned["attestation_sig"]
        try:
            record_pending_propagation(dest.root, unsigned, now=T1)
        except MissingAttestationError as err:
            assert "attestation_sig" in str(err)
        else:
            raise AssertionError("expected MissingAttestationError")
        # nothing was enqueued
        assert read_propagation_journal(dest.root) == []


def test_retry_increments_counter_deterministically_and_acks_resolve():
    # deterministic clock: the retry story is a pure function of `now`.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        entry = record_pending_propagation(dest.root, pack, now=T0)
        assert entry["retry_count"] == 0
        assert entry["next_attempt_at"] == T0
        assert pending_propagation_entries(dest.root)[0]["pack_digest"] == (
            pack["pack"]["pack_digest"]
        )

        # retry 1 fails (no accept-list yet): counter increments, backoff set
        failed = retry_pending_propagation(dest.root, pack, now=T1)
        assert failed["status"] == "pending"
        assert failed["retry_count"] == 1
        assert failed["next_attempt_at"] == "2026-11-10T00:10:00Z"  # T1 + 300s

        # authorize, retry 2 succeeds: the acked line resolves the entry
        authorize_source(
            dest.root, pack["pack"]["key_id"], pack["pack"]["attestation_pubkey"]
        )
        result = retry_pending_propagation(dest.root, pack, now=T2)
        assert result["status"] == "acked"
        assert pending_propagation_entries(dest.root) == []
        statuses = [e["status"] for e in read_propagation_journal(dest.root)]
        assert statuses == ["pending", "pending", "acked"]


def test_pending_dead_letters_after_retry_limit_and_is_terminal():
    # failures are driven through AUTHORIZATION (a validly signed pack with
    # no accept-list): the signature gate passes, intake rejects, the
    # counter increments — deterministically, with the injected clock.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        record_pending_propagation(dest.root, pack, now=T0)
        last = None
        for _attempt in range(1, MAX_PROPAGATION_RETRIES + 2):
            last = retry_pending_propagation(dest.root, pack, now=T0)
        # after MAX_PROPAGATION_RETRIES failed retries the entry is dead
        assert last["status"] == "dead-lettered"
        assert last["retry_count"] == MAX_PROPAGATION_RETRIES + 1
        dead = dead_lettered_entries(dest.root)
        assert len(dead) == 1
        assert dead[0]["pack_digest"] == pack["pack"]["pack_digest"]
        # terminal: retrying a dead-lettered entry raises, visibly
        assert_raises(
            DeadLetterPropagationError,
            retry_pending_propagation, dest.root, pack, now=T0,
        )
        # never silently dropped: the dead-lettered line persists
        assert len(dead_lettered_entries(dest.root)) == 1


def test_backoff_scales_with_retry_count():
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        record_pending_propagation(dest.root, pack, now=T0)
        e1 = retry_pending_propagation(dest.root, pack, now=T0)
        assert e1["next_attempt_at"] == "2026-11-10T00:05:00Z"
        e2 = retry_pending_propagation(dest.root, pack, now=T0)
        assert e2["next_attempt_at"] == "2026-11-10T00:10:00Z"
        assert (
            RETRY_BACKOFF_SECONDS == 300
            and MAX_PROPAGATION_RETRIES == 5
        )


def test_hostile_non_hex_attestation_fields_fail_typed_not_crash():
    # §11 hostile input: non-hex sig/pubkey at the intake layer (which runs
    # BEFORE schema validation) must be a typed reject, never an untyped
    # fromhex crash.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        for field_path, value in (
            (("attestation_sig",), "zz" * 64),  # right length, non-hex
            (("pack", "attestation_pubkey"), "zz" * 32),
            (("pack", "key_id"), "nothexkeyid"),
        ):
            forged = json.loads(json.dumps(pack))
            target = forged
            for key in field_path[:-1]:
                target = target[key]
            target[field_path[-1]] = value
            assert_raises(
                AttestationVerifyError,
                import_propagation_pack, dest.root, forged, now=T1,
            )
            assert_raises(
                AttestationVerifyError,
                record_pending_propagation, dest.root, forged, now=T1,
            )


def test_journal_reader_tolerates_pre_1_2_8_lines():
    # old pending/acked lines without retry fields stay readable.
    with tempfile.TemporaryDirectory() as tmp:
        dest = _dest_with_stale_copy(tmp)
        path = dest.root / "propagation.jsonl"
        legacy = {
            "pack_digest": "ab" * 32,
            "source_root": "root-legacy",
            "status": "pending",
            "ack_digest": None,
            "at": T0,
        }
        path.write_text(canonical_bytes(legacy).decode("utf-8") + "\n",
                        encoding="utf-8")
        (entries,) = read_propagation_journal(dest.root)
        assert entries["status"] == "pending"
        assert "retry_count" not in entries
