"""M4 Round B HOTFIX pins (second independent audit, 2026-11-11):

- W1 — keypoint validation at the trust-anchor layer: identity,
  small-order (cofactor-subgroup), and non-canonically-encoded pubkeys
  are typed rejects at ``authorize_source`` / ``load_keypair``, and the
  embedded-pubkey gate in ``attestation_problems`` closes the audit's
  probe2b CHAIN attack end to end (identity-pubkey pack + forged
  zero-secret (R=B, S=1) signature in a hand-edited accept-list → typed
  reject at import, never a tombstone applied).
- W2 — key loss ≠ first use: ``ensure_keypair`` refuses to mint when the
  key file is gone but the root already carries receipts and/or a
  propagation journal (typed ``KeyMaterialLostError``); ``rotate_keypair``
  is the explicit escape hatch; journal-only roots refuse too.
- W5 — ``retry_pending_propagation`` catches DeletionError: the typed
  contract "failure → new pending line appended" holds for a corrupt
  destination manifest (no raw crash out of retry).
- W6 — retry-after-ack: the counter reads the last journal line with
  ``.get("retry_count", 0)`` — an acked line (no counter) restarts at 0,
  never a raw KeyError.
- W7 — the signed-only gate additionally schema-validates the pack body:
  a schema-invalid but self-consistently signed pack is a typed reject at
  enqueue AND retry (no raw KeyError('pack_digest')).
- W8 — dead-letter is terminal against re-enqueue:
  ``record_pending_propagation`` refuses when the last line for the
  pack_digest is dead-lettered.
- H6 (ruling) — ``next_attempt_at`` is ADVISORY metadata, not enforced:
  a pending line with a future next_attempt_at still retries when called
  (pinned here so any future throttle is a deliberate behavior change).
"""

import json
import tempfile
from pathlib import Path

from m2_helpers import DELETED_AT, OWNER

from mbcp import (
    KEY_FILE_NAME,
    AttestationVerifyError,
    AuthorizationRejectedError,
    DeadLetterPropagationError,
    InvalidKeypointError,
    KeyMaterialLostError,
    L1DeletionService,
    MAX_PROPAGATION_RETRIES,
    MissingAttestationError,
    PackValidationError,
    authorize_source,
    build_bundle,
    canonical_bytes,
    canonical_sha256,
    deauthorize_source,
    export_propagation_pack,
    generate_keypair,
    import_propagation_pack,
    load,
    load_keypair,
    make_record,
    read_propagation_journal,
    record_pending_propagation,
    retry_pending_propagation,
    rotate_keypair,
    validate_keypoint_pubkey,
)
from mbcp import _ed25519
from mbcp.attestation import key_id_for_pubkey, signing_bytes

from syn import FIXED_TS, assert_raises

T0 = "2026-11-10T00:00:00Z"
T1 = "2026-11-10T00:05:00Z"

# The ed25519 identity point encoding (y=1, x=0): 0x01 || 0x00*31.
IDENTITY_PUBKEY = b"\x01" + b"\x00" * 31
# A point of order 2: (x=0, y=-1 mod q). 8*P == identity, P != identity.
ORDER2_PUBKEY = (_ed25519._q - 1).to_bytes(32, "little")
# A non-canonical encoding: y == q is out of range (must be y < q).
NONCANONICAL_PUBKEY = _ed25519._q.to_bytes(32, "little")


def _service(tmp, name="root"):
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
    return service


def _delete_and_export(tmp):
    """A source root with one deletion, and its signed pack."""
    source = _service(tmp, "source")
    source.delete("bundle-alpha", "rec-002", "synthetic erasure")
    pack = export_propagation_pack(source, source_root="root-source", now=T0)
    return source, pack


def _dest_with_stale_copy(tmp, name="dest"):
    dest = _service(tmp, name)
    dest.put_bundle(
        build_bundle(
            "bundle-stale",
            records=[
                make_record("rec-002", "fact", "dest stale copy two", OWNER, created=FIXED_TS),
            ],
        )
    )
    return dest


def _authorize(dest, pack):
    authorize_source(
        dest.root, pack["pack"]["key_id"], pack["pack"]["attestation_pubkey"]
    )


# ---------------------------------------------------------------------------
# W1: keypoint validation at the trust-anchor layer
# ---------------------------------------------------------------------------


def test_keypoint_validator_accepts_legitimate_keys():
    # The legitimate-key matrix (pin e): every generated keypair passes,
    # enroll/verify keep working unchanged (the existing 313-test matrix
    # stays green — this pins the validator itself is not over-broad).
    keypair = generate_keypair()
    assert validate_keypoint_pubkey(keypair.pubkey) == keypair.pubkey
    from syn import syn_keypair
    assert validate_keypoint_pubkey(syn_keypair().pubkey) == syn_keypair().pubkey
    with tempfile.TemporaryDirectory() as tmp:
        dest = _service(tmp)
        authorize_source(dest.root, keypair.key_id, keypair.pubkey_hex)
        sources = json.loads(
            (dest.root / ".mbcp.authorized_sources.json").read_text("utf-8")
        )
        assert sources[keypair.key_id] == keypair.pubkey_hex


def test_authorize_source_rejects_identity_pubkey_typed():
    with tempfile.TemporaryDirectory() as tmp:
        dest = _service(tmp)
        assert_raises(
            InvalidKeypointError,
            authorize_source,
            dest.root,
            key_id_for_pubkey(IDENTITY_PUBKEY),
            IDENTITY_PUBKEY.hex(),
        )
        # nothing was enrolled
        assert not (dest.root / ".mbcp.authorized_sources.json").exists()


def test_authorize_source_rejects_small_order_point_typed():
    with tempfile.TemporaryDirectory() as tmp:
        dest = _service(tmp)
        # order-2 point: 8*P == identity but P != identity
        assert _ed25519._scalarmult(_ed25519._decode_point(ORDER2_PUBKEY), 8) == [0, 1]
        assert_raises(
            InvalidKeypointError,
            authorize_source,
            dest.root,
            key_id_for_pubkey(ORDER2_PUBKEY),
            ORDER2_PUBKEY.hex(),
        )


def test_authorize_source_rejects_noncanonical_encoding_typed():
    with tempfile.TemporaryDirectory() as tmp:
        dest = _service(tmp)
        assert_raises(
            InvalidKeypointError,
            authorize_source,
            dest.root,
            key_id_for_pubkey(NONCANONICAL_PUBKEY),
            NONCANONICAL_PUBKEY.hex(),
        )


def test_load_keypair_rejects_identity_pubkey_typed():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        payload = {
            "algo": "ed25519",
            "seed_hex": (b"\x07" * 32).hex(),
            "pubkey_hex": IDENTITY_PUBKEY.hex(),
            "key_id": key_id_for_pubkey(IDENTITY_PUBKEY),
        }
        (root / KEY_FILE_NAME).write_text(
            canonical_bytes(payload).decode("utf-8"), encoding="utf-8"
        )
        assert_raises(InvalidKeypointError, load_keypair, root)


def test_identity_pubkey_zero_secret_forgery_chain_fails_at_new_gate():
    # The audit's probe2b CHAIN attack, pinned as a regression test: the
    # identity pubkey is listed in a HAND-EDITED accept-list (operator
    # misconfiguration precondition) and the pack signature is forged
    # with ZERO secret material (R=B, S=1). Pre-fix this imported and
    # removed the victim record; the new embedded-pubkey keypoint gate
    # must reject it typed BEFORE anything is applied.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)

        # Precondition proof: the raw vendored equation still accepts the
        # zero-secret forgery against the identity pubkey — the catch is
        # the new gate one layer up, not a vendored checkvalid change.
        forged_sig = (
            _ed25519._encode_point(_ed25519._B) + _ed25519._encode_int(1)
        )
        identity_key_id = key_id_for_pubkey(IDENTITY_PUBKEY)

        forged = json.loads(json.dumps(pack))
        body = forged["pack"]
        body["attestation_pubkey"] = IDENTITY_PUBKEY.hex()
        body["key_id"] = identity_key_id
        forged["integrity"]["digest"] = canonical_sha256(body)
        forged["attestation_sig"] = forged_sig.hex()
        assert _ed25519.checkvalid(
            forged_sig, signing_bytes(forged), IDENTITY_PUBKEY
        ) is True

        # Operator misconfiguration: identity pubkey hand-listed (bypasses
        # the enroll-time validator, exactly like the audit probe).
        (dest.root / ".mbcp.authorized_sources.json").write_text(
            canonical_bytes({identity_key_id: IDENTITY_PUBKEY.hex()}).decode(
                "utf-8"
            ),
            encoding="utf-8",
        )

        # Intake: typed reject at the attestation layer, nothing applied.
        assert_raises(
            AttestationVerifyError,
            import_propagation_pack, dest.root, forged, now=T1,
        )
        assert not (dest.root / "tombstones.jsonl").exists()
        stale = dest.get_bundle("bundle-stale")
        assert [r["id"] for r in load([stale])] == ["rec-002"]
        # Same gate at the pending channel.
        assert_raises(
            AttestationVerifyError,
            record_pending_propagation, dest.root, forged, now=T1,
        )
        assert read_propagation_journal(dest.root) == []


def test_small_order_receipt_pubkey_fails_verification_typed():
    # Receipts are self-anchored, but a receipt whose embedded pubkey is
    # a small-order point must not ride the cofactorless equation either.
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        receipt = service.delete(
            "bundle-alpha", "rec-002", "synthetic erasure"
        )
        forged = json.loads(json.dumps(receipt))
        body = forged["receipt"]
        body["attestation_pubkey"] = ORDER2_PUBKEY.hex()
        body["key_id"] = key_id_for_pubkey(ORDER2_PUBKEY)
        forged["integrity"]["digest"] = canonical_sha256(body)
        order2_sig = (
            _ed25519._encode_point(_ed25519._B) + _ed25519._encode_int(0)
        )
        forged["attestation_sig"] = order2_sig.hex()
        check = service.verify_receipt(forged)
        assert check["ok"] is False
        assert any("trust anchor" in p for p in check["problems"])


# ---------------------------------------------------------------------------
# W2: key loss ≠ first use (ensure_keypair fail-closed)
# ---------------------------------------------------------------------------


def test_key_loss_after_delete_refuses_typed_and_writes_no_receipt():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-001", "synthetic erasure one")
        key_path = service.root / KEY_FILE_NAME
        assert key_path.exists()
        receipts_before = set(service.receipt_paths())

        # Key loss: the file is gone before a NEW service instance (the
        # in-memory cache of the old instance is still valid key material
        # — loss bites the next process/use that must reload from disk).
        key_path.unlink()
        service2 = L1DeletionService(service.root, clock=lambda: DELETED_AT)
        try:
            service2.delete("bundle-alpha", "rec-002", "synthetic erasure two")
        except KeyMaterialLostError as err:
            assert "key material lost" in str(err)
        else:
            raise AssertionError("expected KeyMaterialLostError")
        # No receipt was written under the lost key; no new key minted.
        assert set(service2.receipt_paths()) == receipts_before
        assert not key_path.exists()


def test_key_loss_blocks_export_too():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        service.delete("bundle-alpha", "rec-001", "synthetic erasure")
        (service.root / KEY_FILE_NAME).unlink()
        service2 = L1DeletionService(service.root, clock=lambda: DELETED_AT)
        assert_raises(
            KeyMaterialLostError, export_propagation_pack, service2, now=T1
        )


def test_first_use_on_empty_root_still_mints():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)  # bundles only: no receipts, no journal
        receipt = service.delete(
            "bundle-alpha", "rec-001", "synthetic erasure"
        )
        assert (service.root / KEY_FILE_NAME).exists()
        assert service.verify_receipt(receipt)["ok"] is True
        # ensure is stable: a second signing use reloads the SAME key.
        kp1 = load_keypair(service.root)
        service2 = L1DeletionService(service.root, clock=lambda: DELETED_AT)
        service2.delete("bundle-alpha", "rec-002", "second erasure")
        assert load_keypair(service.root).key_id == kp1.key_id


def test_journal_only_root_refuses_silent_mint():
    # Receipts gone but a propagation journal remains: still history.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        service = _service(tmp, "dest")
        record_pending_propagation(service.root, pack, now=T0)
        assert not (service.root / KEY_FILE_NAME).exists()
        assert_raises(
            KeyMaterialLostError,
            service.delete, "bundle-alpha", "rec-001", "synthetic erasure",
        )


def test_rotate_keypair_is_the_explicit_unblock():
    with tempfile.TemporaryDirectory() as tmp:
        service = _service(tmp)
        old_receipt = service.delete(
            "bundle-alpha", "rec-001", "synthetic erasure one"
        )
        old_key_id = load_keypair(service.root).key_id
        (service.root / KEY_FILE_NAME).unlink()

        # Explicit escape hatch: deliberate new identity (a fresh service
        # instance loads it from disk — the old instance's cache predates
        # the rotation).
        new_keypair = rotate_keypair(service.root)
        assert new_keypair.key_id != old_key_id
        service2 = L1DeletionService(service.root, clock=lambda: DELETED_AT)
        receipt_two = service2.delete(
            "bundle-alpha", "rec-002", "synthetic erasure two"
        )
        # Old history still verifies self-anchored; the tail is new-key.
        assert service2.verify_receipt(old_receipt)["ok"] is True
        assert service2.verify_receipt(receipt_two)["ok"] is True
        assert receipt_two["receipt"]["key_id"] == new_keypair.key_id


# ---------------------------------------------------------------------------
# W5/W6/W7/W8 + H6 ruling: pending typed contract narrowing
# ---------------------------------------------------------------------------


def test_retry_after_ack_appends_line_without_keyerror():
    # W6: import acks, source is later deauthorized, retry fails the
    # intake gate; the last journal line for the pack is the ACKED one
    # (no retry_count key) — the counter must restart at 0, typed.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        _authorize(dest, pack)
        import_propagation_pack(dest.root, pack, now=T0)
        deauthorize_source(dest.root, pack["pack"]["key_id"])

        result = retry_pending_propagation(dest.root, pack, now=T1)
        assert result["status"] == "pending"
        assert result["retry_count"] == 1
        lines = read_propagation_journal(dest.root)
        assert lines[-1]["status"] == "pending"
        assert lines[-1]["retry_count"] == 1
        statuses = [e["status"] for e in lines]
        assert statuses == ["acked", "pending"]


def test_retry_corrupt_dest_manifest_holds_typed_contract():
    # W5: a corrupt destination manifest makes recover() raise the typed
    # DeletionError INSIDE the import attempt — the contract "failure →
    # new pending line appended" must hold; no raw DeletionError escapes.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        record_pending_propagation(dest.root, pack, now=T0)
        _authorize(dest, pack)
        # Corrupt the destination manifest (malformed content, not merely
        # unreadable): recover() raises the typed DeletionError.
        (dest.root / "bundles" / "bundle-stale.json").write_bytes(b'{"broken": ')

        result = retry_pending_propagation(dest.root, pack, now=T1)
        assert result["status"] == "pending"
        assert result["retry_count"] == 1
        lines = read_propagation_journal(dest.root)
        assert len(lines) == 2
        assert lines[-1]["status"] == "pending"
        assert lines[-1]["retry_count"] == 1


def test_schema_invalid_signed_pack_rejected_typed_at_enqueue_and_retry():
    # W7: a minimal pack {pack: {key_id, attestation_pubkey}} with a VALID
    # signature over its signing bytes but NO schema body — the signed-
    # only gate must schema-reject it typed, never raw-KeyError.
    with tempfile.TemporaryDirectory() as tmp:
        dest = _dest_with_stale_copy(tmp)
        keypair = generate_keypair()
        minimal = {
            "pack": {
                "key_id": keypair.key_id,
                "attestation_pubkey": keypair.pubkey_hex,
            }
        }
        sig = _ed25519.signature(
            signing_bytes(minimal), keypair.seed, keypair.pubkey
        )
        minimal["attestation_sig"] = sig.hex()

        assert_raises(
            PackValidationError,
            record_pending_propagation, dest.root, minimal, now=T0,
        )
        assert_raises(
            PackValidationError,
            retry_pending_propagation, dest.root, minimal, now=T0,
        )
        assert read_propagation_journal(dest.root) == []


def test_record_pending_unsigned_pack_still_missing_attestation():
    # The W7 schema addition must not blur the missing-signature error.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        unsigned = json.loads(json.dumps(pack))
        del unsigned["attestation_sig"]
        assert_raises(
            MissingAttestationError,
            record_pending_propagation, dest.root, unsigned, now=T0,
        )
        # unauthorized-but-signed still enters pending (deliberate: the
        # accept-list is an intake concern, enforced at retry).
        record_pending_propagation(dest.root, pack, now=T0)
        assert read_propagation_journal(dest.root)[0]["status"] == "pending"


def test_dead_lettered_pack_cannot_be_reenqueued():
    # W8: terminal is terminal — record_pending refuses a pack whose last
    # journal line is dead-lettered.
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        record_pending_propagation(dest.root, pack, now=T0)
        last = None
        for _attempt in range(MAX_PROPAGATION_RETRIES + 1):
            last = retry_pending_propagation(dest.root, pack, now=T0)
        assert last["status"] == "dead-lettered"

        lines_before = read_propagation_journal(dest.root)
        assert_raises(
            DeadLetterPropagationError,
            record_pending_propagation, dest.root, pack, now=T0,
        )
        assert read_propagation_journal(dest.root) == lines_before


def test_next_attempt_at_is_advisory_not_enforced():
    # H6 ruling (docstring-corrected, enforced-alternative rejected): a
    # pending line whose next_attempt_at is in the future still retries
    # when called — backoff is scheduling metadata for the caller, not a
    # throttle inside retry. Pinned so making it a hard gate later is a
    # deliberate, visible behavior change (it would contradict the pinned
    # fixed-clock dead-letter drive).
    with tempfile.TemporaryDirectory() as tmp:
        _source, pack = _delete_and_export(tmp)
        dest = _dest_with_stale_copy(tmp)
        record_pending_propagation(
            dest.root, pack, now=T0, next_attempt_at="2099-01-01T00:00:00Z"
        )
        result = retry_pending_propagation(dest.root, pack, now=T0)
        # The attempt RAN (failed on the fail-closed accept-list, as
        # expected) — it was not skipped by the future next_attempt_at.
        assert result["status"] == "pending"
        assert result["retry_count"] == 1
