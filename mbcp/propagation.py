"""L2: cross-root tombstone propagation packs (RFC Q1/Q2/Q3), L4-attested.

Scope (RFC §1 Q1–Q3, approved 2026-11-06; attestation added M4 Round B,
SPEC 1.2.6/1.2.7/1.2.8): a *source* root exports a **propagation pack** —
the tombstone set of its journal (deduped with :meth:`L1DeletionService.all_tombstones`
semantics, optionally filtered to target ids), each tombstone with its
canonical SHA-256, a pack-level digest chain, an attestation block, and a
deterministic ed25519 signature from the source root's per-root keypair
(the pack body embeds the ``key_id`` fingerprint and ``attestation_pubkey``
— the export carries its pubkey). A *destination* root imports the pack
through the existing tombstone-first machinery (journal append, then
:meth:`L1DeletionService.recover`, so store records targeted by pack
tombstones are removed and can never resurrect).

Integrity model — READ THIS BEFORE RELYING ON A PACK OR ACK:

Propagation packs carry TWO integrity layers (SPEC 1.2.6 Round B):

1. **ed25519 attestation** (outermost): the pack body is signed by the
   source root's key; intake verifies the signature BEFORE anything else
   and authorizes the source against the destination root's
   authorized-source accept-list (SPEC 1.2.7, fail-closed). This closes
   the M3 honesty gap: a writer of the DESTINATION root can no longer
   forge a self-consistent pack — forgery requires the SOURCE root's
   private key. Honest threat model (verbatim discipline): the source
   private key lives inside the source root, so a full source-root
   compromise equals key compromise; signatures defend against partial
   tampering and third-party forgery, not total root breach. Binding a
   key to an identity still needs an out-of-band anchor.
2. **Digest-chain integrity** (underneath): per-tombstone digests, the
   sorted-list pack digest binding the source root, the attestation
   block, and the artifact integrity digest. This detects accidental
   corruption and truncation; it no longer carries the anti-forgery
   burden alone.

Acks remain digest-chain-only artifacts: the ack records WHAT a verified
intake applied; it is not itself signed (see ``ACK_LIMITATIONS``).

Failure semantics (Q3, tightened SPEC 1.2.8): propagation is best-effort.
The append-only ``propagation.jsonl`` journal records every intake attempt
as ``pending``/``acked``/``dead-lettered``; fsynced before the call
returns. This is an **attempts audit**, NOT a deduped state log: every
successful intake — including an idempotent no-op re-import that applied
nothing — appends exactly one ``acked`` line, so the line count grows by
one per import (BACKLOG M3 round-2 advisory 1, pinned; do not "fix" the
growth without a deliberate design change). Pending entries carry a
``retry_count`` and ``next_attempt_at``; :func:`retry_pending_propagation`
re-attempts a signed pack, increments the counter deterministically, and
past :data:`MAX_PROPAGATION_RETRIES` failed attempts the entry is
**dead-lettered**: typed-visible via :func:`dead_lettered_entries`, never
silently dropped, never retried forever. UNSIGNED packs never enter the
pending channel — enqueue is a typed reject (SPEC 1.2.8). Fail-closed,
per the tombstone-first philosophy: an unacked propagation is NOT
evidence of propagation, and ``verify_receipt`` never consults
propagation state, so a pending (or forged-acked) line can never launder
a receipt into ok:True.

Layout of a service root using propagation (in addition to the L1 layout)::

    propagation.jsonl            # append-only pending->acked/dead-lettered journal
    propagation/acks/<hex16>.json  # ack artifacts, keyed by pack_digest[:16]
    .mbcp.authorized_sources.json  # intake accept-list: key_id -> pubkey hex
                                   # (root config dotfile, outside all scans)

Determinism: a pack is a pure function of (journal tombstone set,
target_ids, source_root, issued_at, source keypair) — tombstones are
sorted by canonical SHA-256, the pack digest binds the source root AND
the sorted digest list, and the whole artifact is canonical JSON
(SPEC 1.4). Same inputs -> byte-identical pack.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import _schema
from .attestation import (
    AttestationError,
    AttestationVerifyError,
    AuthorizationRejectedError,
    MissingAttestationError,
    attestation_problems,
    check_authorization,
    sign_envelope,
)
from .bundle import validate_tombstone
from .canonical import (
    NonFiniteConstantError,
    canonical_bytes,
    canonical_sha256,
    json_loads_strict,
    utc_now,
)
from .deletion import (
    DEFAULT_LOCK_TIMEOUT,
    L1DeletionService,
    _atomic_write,
    _fsync_dir,
)

PACK_SCHEMA = None
ACK_SCHEMA = None

# Spec 1.2.8 pending-retry constants (Round B ruling, documented values):
# a pending entry is dead-lettered after MAX_PROPAGATION_RETRIES failed
# retry attempts; next_attempt_at backs off RETRY_BACKOFF_SECONDS per
# failed attempt (deterministic given the injected clock — no wall-clock
# reads in the logic).
MAX_PROPAGATION_RETRIES = 5
RETRY_BACKOFF_SECONDS = 300

# The ack is a digest-chain-only record of what a VERIFIED intake applied.
# Wording pinned by tests (mutation-checked honesty contract): it must say
# that the pack attestation was verified at intake and that the ack
# artifact itself is not independently signed.
ACK_LIMITATIONS = [
    "propagation pack ed25519 attestation verified at intake against the "
    "destination root's authorized-source accept-list; this ack artifact "
    "itself carries digest-chain integrity only and is not independently "
    "signed."
]


class PropagationError(ValueError):
    """Base class for L2 propagation failures."""


class PackValidationError(PropagationError):
    """Raised when a propagation pack is malformed or its attestation /
    digest chain does not verify (tampered tombstone, stale digest list,
    recomputed pack digest over the wrong set, missing attestation, ...).

    Rejection at this layer means the pack was SIGNATURE-VERIFIED and
    SOURCE-AUTHORIZED but its internal digest chain does not hold. The
    layers ABOVE this one have their own typed errors (SPEC 1.2.6/1.2.7):
    :class:`~mbcp.attestation.MissingAttestationError` (no signature
    field), :class:`~mbcp.attestation.AttestationVerifyError` (signature
    does not verify / key mismatch), and
    :class:`~mbcp.attestation.AuthorizationRejectedError` (fail-closed
    accept-list). All run BEFORE this digest-chain gate.
    """


class PropagationJournalError(PropagationError):
    """Raised when ``propagation.jsonl`` is corrupt (A-15 hygiene: a loud
    typed error naming the line, never a bare JSONDecodeError)."""


class DeadLetterPropagationError(PropagationError):
    """Raised when a dead-lettered pending entry is retried (SPEC 1.2.8).

    Dead-lettering is TERMINAL: the entry stays listable via
    :func:`dead_lettered_entries` (never silently dropped) and is never
    retried again (never infinite retry). Retrying one is a typed,
    visible error — not a silent no-op.
    """


def _pack_schema():
    global PACK_SCHEMA
    if PACK_SCHEMA is None:
        PACK_SCHEMA = _schema.load_schema("propagation-pack.v0")
    return PACK_SCHEMA


def _ack_schema():
    global ACK_SCHEMA
    if ACK_SCHEMA is None:
        ACK_SCHEMA = _schema.load_schema("propagation-ack.v0")
    return ACK_SCHEMA


def _as_service(root):
    """Accept a path or an existing L1DeletionService; return the service."""
    if isinstance(root, L1DeletionService):
        return root
    return L1DeletionService(root)


def _validate_pack(pack):
    """Structural + digest-chain verification of an incoming pack.

    Order matters: the schema gate runs first so every later check can
    assume the shape exists, then the chain is verified from the inside
    out (tombstones -> digest list -> pack digest -> attestation ->
    artifact integrity). Any failure raises PackValidationError; nothing
    is applied on failure.
    """
    try:
        _schema.validate(pack, _pack_schema())
    except _schema.ValidationError as err:
        raise PackValidationError(f"invalid propagation pack: {err}") from err

    body = pack["pack"]
    # 1. every listed digest must match a tombstone, and every tombstone
    #    must be listed (the chain covers the WHOLE set, not a subset).
    computed = sorted(canonical_sha256(t) for t in body["tombstones"])
    listed = sorted(body["tombstone_digests"])
    if listed != computed:
        raise PackValidationError(
            "tombstone_digests do not match the pack tombstones "
            "(mutated tombstone or stale digest list)"
        )
    # 2. pack digest binds the SOURCE ROOT and the sorted tombstone digest
    #    list (SPEC §2 audit-tightening note, 2026-11-08): the digest is
    #    the canonical SHA-256 of the object {"source_root": ...,
    #    "tombstone_digests": [...]} (deterministic shape — canonical form
    #    sorts the keys). Two roots exporting the SAME tombstone set now
    #    produce DIFFERENT pack digests, so their acks never collide on
    #    one ack path/key and ack attribution cannot be forged across
    #    roots (audit §7).
    if body["pack_digest"] != canonical_sha256({
        "source_root": body["source_root"],
        "tombstone_digests": computed,
    }):
        raise PackValidationError(
            "pack_digest does not match the recomputed digest over "
            "(source_root, sorted tombstone digest list)"
        )
    # 3. the attestation must bind THIS pack, not some other one.
    attestation = body["attestation"]
    if attestation["pack_digest"] != body["pack_digest"]:
        raise PackValidationError(
            "attestation pack_digest does not match the pack pack_digest"
        )
    if attestation["source_root"] != body["source_root"]:
        raise PackValidationError(
            "attestation source_root does not match the pack source_root"
        )
    # 4. the artifact as a whole must be canonical-intact.
    if pack["integrity"]["digest"] != canonical_sha256(body):
        raise PackValidationError(
            "pack integrity digest does not match the pack body (tampered)"
        )
    return body


def _verify_pack_attestation(pack, dest_root):
    """L4 intake gate for a propagation pack (SPEC 1.2.6/1.2.7).

    Runs BEFORE the digest-chain gate (:func:`_validate_pack`), in this
    order, each failure typed and nothing applied:

    1. attestation fields present (``attestation_sig`` names the field
       when missing) — :class:`MissingAttestationError`;
    2. the ed25519 signature verifies against the pubkey embedded in the
       pack body over the artifact bytes minus the sig
       — :class:`AttestationVerifyError`;
    3. the source is authorized: the pack's ``key_id`` must be listed in
       the destination root's accept-list with the SAME pubkey
       — :class:`AuthorizationRejectedError` (fail-closed: an absent,
       empty or malformed accept-list rejects EVERY pack).

    Returns the pack body on success.
    """
    if not isinstance(pack, dict):
        raise MissingAttestationError(
            "propagation pack is not an object; missing 'attestation_sig'"
        )
    sig_hex = pack.get("attestation_sig")
    if not isinstance(sig_hex, str):
        raise MissingAttestationError(
            "propagation pack is missing required field 'attestation_sig' "
            "(hex128 ed25519 signature, SPEC 1.2.6)"
        )
    body = pack.get("pack")
    if not isinstance(body, dict):
        raise MissingAttestationError(
            "propagation pack is missing required field 'pack'"
        )
    pubkey_hex = body.get("attestation_pubkey")
    if not isinstance(pubkey_hex, str):
        raise MissingAttestationError(
            "propagation pack body is missing required field "
            "'attestation_pubkey'"
        )
    key_id = body.get("key_id")
    if not isinstance(key_id, str):
        raise MissingAttestationError(
            "propagation pack body is missing required field 'key_id'"
        )
    problems = attestation_problems(pack, body_field="pack")
    if problems:
        raise AttestationVerifyError(
            f"propagation pack attestation does not verify: "
            f"{'; '.join(problems)}"
        )
    check_authorization(dest_root, key_id, pubkey_hex)
    return body


def export_propagation_pack(
    root,
    target_ids=None,
    *,
    source_root=None,
    now=None,
    lock_timeout=DEFAULT_LOCK_TIMEOUT,
):
    """Export this root's tombstone journal as a propagation pack (RFC Q1).

    ``root`` is a service-root path or an :class:`L1DeletionService`.
    Tombstones come from ``all_tombstones()`` (deduped, A-16 tiebreak
    semantics); ``target_ids`` optionally restricts the export. Tombstones
    are sorted by canonical SHA-256 so the pack is independent of journal
    write order. The pack digest is the canonical SHA-256 of the object
    ``{"source_root": ..., "tombstone_digests": [<sorted digests>]}`` —
    it binds the source root AND the tombstone set (SPEC §2 audit-
    tightening note, 2026-11-08): two roots exporting the same tombstone
    set are DIFFERENT packs with different ack paths, so ack attribution
    cannot collide across roots (audit §7).

    The journal read holds the root advisory lock (audit §3, ADV-C2-3):
    an export must not observe the journal/bundles torn mid-delete.
    ``lock_timeout`` bounds the wait; a timeout raises the typed
    :class:`~mbcp.deletion.LockTimeoutError`. The lock is re-entrant, so
    an export nested inside an already-locked flow on the same root is
    safe.

    L4 attestation (SPEC 1.2.6): the pack is signed with THIS root's
    per-root ed25519 keypair (created 0600 on first use), so the export
    carries its own pubkey (``key_id`` + ``attestation_pubkey`` embedded
    in the pack body, ``attestation_sig`` at the artifact level) and the
    destination can verify provenance and authorize the source. The
    source keypair is ensured INSIDE the root lock.

    Deterministic: same journal state + same (``source_root``, ``now``)
    -> byte-identical pack (the keypair is per-root and stable, so it
    does not disturb export determinism on one root).
    """
    service = _as_service(root)
    with service._root_lock(lock_timeout):
        tombstones = service.all_tombstones()
        if target_ids is not None:
            wanted = set(target_ids)
            tombstones = [t for t in tombstones if t["target_id"] in wanted]
        # sort by full canonical digest: fully content-determined, so any two
        # exports of the same tombstone set list identical digests.
        tombstones = sorted(tombstones, key=canonical_sha256)
        digests = [canonical_sha256(t) for t in tombstones]
        source_root = source_root if source_root is not None else str(service.root)
        # pack digest binds source_root + the sorted tombstone digest list
        # (SPEC §2 audit-tightening note): same set, different root -> different
        # pack, different ack path (audit §7 ack-attribution collision closed).
        pack_digest = canonical_sha256({
            "source_root": source_root,
            "tombstone_digests": digests,
        })
        issued_at = now or utc_now()
        body = {
            "source_root": source_root,
            "issued_at": issued_at,
            "tombstones": tombstones,
            "tombstone_digests": digests,
            "pack_digest": pack_digest,
            "attestation": {
                "source_root": source_root,
                "pack_digest": pack_digest,
                "issued_at": issued_at,
            },
        }
        pack = {
            "pack": body,
            "integrity": {"algo": "sha256", "digest": canonical_sha256(body)},
        }
        # L4 attestation (SPEC 1.2.6): sign the whole artifact minus the
        # sig field, with this root's keypair.
        pack = sign_envelope(pack, service._attestation_keypair(), body_field="pack")
        _schema.validate(pack, _pack_schema())
        return pack


def import_propagation_pack(root, pack, *, now=None, lock_timeout=DEFAULT_LOCK_TIMEOUT):
    """Import a propagation pack into this root (RFC UC1 minimal intake gate).

    Intake is gated in layers, outermost first (SPEC 1.2.6/1.2.7), and a
    failure in ANY layer rejects the pack with a TYPED error, nothing
    applied:

    1. **L4 attestation**: the pack must carry ``attestation_sig`` and the
       ed25519 signature must verify against the pubkey embedded in the
       pack body (missing field → :class:`MissingAttestationError`,
       invalid signature → :class:`AttestationVerifyError`).
    2. **Intake authorization** (fail-closed): the pack's ``key_id`` must
       be listed in this root's authorized-source accept-list
       (``<root>/.mbcp.authorized_sources.json``) with the same pubkey —
       unknown key, key mismatch, or an absent/empty/malformed
       accept-list all raise :class:`AuthorizationRejectedError`. There
       is no "accepted-unverified" behavioural tier (SPEC 1.2.7).
    3. **Digest chain**: the existing attestation/digest-chain gate
       (:class:`PackValidationError`).

    Accepted tombstones are applied tombstone-first: each is appended to
    ``tombstones.jsonl`` (fsynced) unless the identical tombstone is
    already in the journal (idempotent re-import appends nothing), then
    :meth:`L1DeletionService.recover` rewrites every manifest, so store
    records targeted by pack tombstones are removed and the manifests gain
    the tombstones (A-19 semantics).

    Emits an ack artifact at ``propagation/acks/<pack_digest[:16]>.json``
    and appends one ``acked`` line to ``propagation.jsonl`` (fsynced
    before returning). A re-import that applied nothing returns the
    existing ack unchanged. An ack is NOT an erasure certificate: see
    ``ACK_LIMITATIONS`` — the ack records what a VERIFIED intake applied,
    and is itself digest-chain-only (not independently signed).

    The whole intake holds the destination root's advisory lock (audit §3):
    the journal append below routes around the service's locked
    :meth:`~mbcp.deletion.L1DeletionService.recover`, so intake takes the
    lock itself for its full duration (the nested recover() acquisition is
    re-entrant — same thread). ``lock_timeout`` bounds the wait; a timeout
    raises the typed :class:`~mbcp.deletion.LockTimeoutError`.
    """
    service = _as_service(root)
    with service._root_lock(lock_timeout):
        return _import_propagation_pack_locked(service, pack, now=now)


def _import_propagation_pack_locked(service, pack, *, now=None):
    """Locked body of :func:`import_propagation_pack`."""
    # L4 gate BEFORE the digest-chain gate (SPEC 1.2.6/1.2.7): signature
    # verification, then fail-closed source authorization. Nothing is
    # applied on failure at either layer.
    _verify_pack_attestation(pack, service.root)
    body = _validate_pack(pack)
    pack_digest = body["pack_digest"]
    source_root = body["source_root"]

    # 1. journal first: append only tombstones not already in the journal.
    existing = {canonical_sha256(t) for t in service.journal_tombstones()}
    imported = [
        t for t in body["tombstones"] if canonical_sha256(t) not in existing
    ]
    for tombstone in imported:
        validate_tombstone(tombstone)
        service._append_journal(tombstone)

    # 2. apply through the existing tombstone-first machinery (removes
    #    store records targeted by the (now durable) journal tombstones).
    service.recover()

    # 3. ack artifact (idempotent: an ack already on disk for a no-op
    #    re-import is returned unchanged — but ONLY after its integrity is
    #    re-checked on read-back: a corrupt artifact raises a typed error
    #    and a tampered one is re-issued from state, never returned).
    acks_dir = service.root / "propagation" / "acks"
    ack_path = acks_dir / f"{pack_digest[:16]}.json"
    ack = None
    if not imported and ack_path.exists():
        ack = _read_ack(ack_path)
        if ack["integrity"]["digest"] != canonical_sha256(ack["ack"]):
            ack = None  # tampered: re-issue from state below
    if ack is None:
        imported_digests = sorted(
            {canonical_sha256(t) for t in body["tombstones"]}
        )
        ack_body = {
            "for_source_root": source_root,
            "pack_digest": pack_digest,
            "imported_tombstone_digests": imported_digests,
            "imported_at": now or utc_now(),
            "limitations": list(ACK_LIMITATIONS),
        }
        ack = {
            "ack": ack_body,
            "integrity": {"algo": "sha256", "digest": canonical_sha256(ack_body)},
        }
        _schema.validate(ack, _ack_schema())
        _atomic_write(ack_path, canonical_bytes(ack))

    # 4. pending->acked journal, fsynced before returning (fail-closed:
    #    the line claims "acked" only after the ack artifact is durable).
    #    Attempts audit: one acked line per intake attempt, INCLUDING
    #    no-op re-imports (BACKLOG M3 round-2 advisory 1).
    entry = {
        "pack_digest": pack_digest,
        "source_root": source_root,
        "status": "acked",
        "ack_digest": ack["integrity"]["digest"],
        "at": now or utc_now(),
    }
    _append_propagation_line(service.root, entry)
    return ack


def record_pending_propagation(root, pack, *, now=None, retry_count=0,
                               next_attempt_at=None):
    """Record a propagation attempt that could not yet be acked (Q3,
    tightened SPEC 1.2.8).

    The pending channel carries SIGNED packs only: the pack's ed25519
    attestation is verified BEFORE the entry is enqueued — an unsigned or
    bad-signature pack is a typed reject (:class:`MissingAttestationError`
    / :class:`AttestationVerifyError`) and never enters
    ``propagation.jsonl``. (The accept-list is an INTAKE concern and is
    deliberately NOT checked here: a pending entry records that a
    delivery was attempted, and authorization is enforced when the retry
    reaches intake.)

    The durable entry carries the pack's own ``pack_digest`` /
    ``source_root`` (signature-bound values from the pack body, not
    caller-supplied), the attempt timestamp ``at``, a ``retry_count``
    (0 for a first attempt) and ``next_attempt_at`` (when the next retry
    becomes eligible; the enqueue time for a fresh entry). Fail-closed:
    an unacked propagation is not evidence of propagation — a pending
    line never influences ``verify_receipt`` and must never be presented
    as proof of erasure.
    """
    now = now or utc_now()
    body = _verify_pack_signed_only(pack)
    entry = {
        "pack_digest": body["pack_digest"],
        "source_root": body["source_root"],
        "status": "pending",
        "ack_digest": None,
        "at": now,
        "retry_count": int(retry_count),
        "next_attempt_at": next_attempt_at if next_attempt_at is not None else now,
    }
    _append_propagation_line(_as_service(root).root, entry)
    return entry


def _verify_pack_signed_only(pack):
    """Verify ONLY the ed25519 attestation of a pack (no accept-list, no
    digest chain). Shared by the pending-enqueue gate and the retry path:
    unsigned packs never enter or traverse the pending channel."""
    if not isinstance(pack, dict) or not isinstance(pack.get("pack"), dict):
        raise MissingAttestationError(
            "propagation pack is missing required field 'attestation_sig' "
            "(pending channel carries signed packs only, SPEC 1.2.8)"
        )
    sig_hex = pack.get("attestation_sig")
    if not isinstance(sig_hex, str):
        raise MissingAttestationError(
            "propagation pack is missing required field 'attestation_sig' "
            "(pending channel carries signed packs only, SPEC 1.2.8)"
        )
    problems = attestation_problems(pack, body_field="pack")
    if problems:
        raise AttestationVerifyError(
            f"propagation pack attestation does not verify: "
            f"{'; '.join(problems)}"
        )
    return pack["pack"]


def _plus_seconds(timestamp, seconds):
    """Deterministic RFC3339 arithmetic (whole-second UTC 'Z' form)."""
    dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    dt = dt.astimezone(timezone.utc) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def retry_pending_propagation(root, pack, *, now=None,
                              lock_timeout=DEFAULT_LOCK_TIMEOUT):
    """One retry attempt of a pending propagation (SPEC 1.2.8).

    Deterministic (clock injected via ``now``; no wall-clock reads in the
    logic):

    - the pack must be signed — an unsigned pack is a typed reject and
      never enters/traverses the pending channel;
    - a dead-lettered entry is TERMINAL: retrying it raises the typed
      :class:`DeadLetterPropagationError` (visible, never an infinite
      retry, never a silent drop);
    - on success the intake appends its ``acked`` line, which resolves
      the pending entry (the journal is append-only, so the resolution is
      a new line — the attempts-audit philosophy of BACKLOG M3 round-2
      advisory 1, unchanged); returns ``{"status": "acked", "ack": ack}``;
    - on failure a new line is appended with ``retry_count`` incremented
      and ``next_attempt_at = now + RETRY_BACKOFF_SECONDS * retry_count``;
      once the counter passes :data:`MAX_PROPAGATION_RETRIES` the line's
      status is ``dead-lettered`` (typed-visible via
      :func:`dead_lettered_entries`). Returns the new entry.

    The whole retry holds the destination root's advisory lock (audit §3).
    """
    service = _as_service(root)
    with service._root_lock(lock_timeout):
        now = now or utc_now()
        body = _verify_pack_signed_only(pack)
        pack_digest = body["pack_digest"]
        entries = [
            e for e in read_propagation_journal(service.root)
            if e["pack_digest"] == pack_digest
        ]
        if entries and entries[-1]["status"] == "dead-lettered":
            raise DeadLetterPropagationError(
                f"pending propagation {pack_digest[:16]}... is dead-lettered "
                f"after {MAX_PROPAGATION_RETRIES} failed retries (SPEC 1.2.8); "
                f"dead-lettered entries are terminal — listed by "
                f"dead_lettered_entries(), never retried, never dropped"
            )
        try:
            ack = _import_propagation_pack_locked(service, pack, now=now)
        except (PropagationError, AttestationError) as err:
            # The retry failed again: increment the counter durably.
            previous = entries[-1]["retry_count"] if entries else 0
            retry_count = previous + 1
            dead = retry_count > MAX_PROPAGATION_RETRIES
            entry = {
                "pack_digest": pack_digest,
                "source_root": body["source_root"],
                "status": "dead-lettered" if dead else "pending",
                "ack_digest": None,
                "at": now,
                "retry_count": retry_count,
                "next_attempt_at": _plus_seconds(
                    now, RETRY_BACKOFF_SECONDS * retry_count
                ),
            }
            _append_propagation_line(service.root, entry)
            return entry
        return {"status": "acked", "ack": ack}


def dead_lettered_entries(root):
    """Every dead-lettered propagation entry, in write order (SPEC 1.2.8).

    Dead-lettered entries are typed-visible: they are NEVER silently
    dropped and never retried again. An operator resolves a dead-letter by
    deliberate intervention (fix the source/authorization, then handle the
    pack as a fresh intake).
    """
    return [
        entry for entry in read_propagation_journal(root)
        if entry["status"] == "dead-lettered"
    ]


def pending_propagation_entries(root):
    """Latest state of every pack_digest whose current status is
    ``pending`` (chronological by last line), with the entry's
    ``next_attempt_at`` eligibility visible."""
    latest = {}
    for entry in read_propagation_journal(root):
        latest[entry["pack_digest"]] = entry
    return [
        entry for _digest, entry in sorted(
            latest.items(), key=lambda kv: (kv[1]["at"], kv[1]["pack_digest"])
        )
        if entry["status"] == "pending"
    ]


def _read_ack(path):
    """Read an ack artifact back from disk (no-op re-import path).

    BACKLOG M3 round-2 advisory 3: the read-back must not return garbage.
    A corrupt artifact (unparseable or schema-invalid) raises the typed
    :class:`PropagationError` naming the path; a TAMPERED one (valid shape
    but integrity digest mismatch) is the caller's job to detect — this
    helper only guarantees a structurally sound artifact comes back.
    """
    try:
        ack = json_loads_strict(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, NonFiniteConstantError) as err:
        raise PropagationError(f"corrupt ack artifact {path}: {err}") from err
    try:
        _schema.validate(ack, _ack_schema())
    except _schema.ValidationError as err:
        raise PropagationError(f"corrupt ack artifact {path}: {err}") from err
    return ack


def read_propagation_journal(root):
    """All ``propagation.jsonl`` lines, in write order.

    Corrupt lines raise :class:`PropagationJournalError` naming the line
    (A-15 hygiene: a loud typed error, never a bare JSONDecodeError).
    Decode hygiene (M3 round-2 verify advisory 2): the journal is read as
    bytes and each line decoded explicitly — invalid UTF-8 raises the typed
    error with path:lineno, never a bare UnicodeDecodeError (the L1
    ``journal_tombstones`` reader shares this pattern).

    Line shape: the five pre-Round-B keys (``pack_digest``,
    ``source_root``, ``status``, ``ack_digest``, ``at``) are required on
    every line; ``retry_count`` (non-negative integer) and
    ``next_attempt_at`` (RFC3339 string or null, SPEC 1.2.8) are
    validated when present — pre-1.2.8 lines without them stay readable
    (tolerant reader; the journal is append-only). Status is one of
    ``pending`` / ``acked`` / ``dead-lettered``.
    """
    path = _as_service(root).root / "propagation.jsonl"
    if not path.exists():
        return []
    entries = []
    required = {"pack_digest", "source_root", "status", "ack_digest", "at"}
    for lineno, line in enumerate(path.read_bytes().splitlines(), 1):
        if not line.strip():
            continue
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as err:
            raise PropagationJournalError(
                f"corrupt propagation journal {path}:{lineno}: invalid UTF-8: {err}"
            ) from err
        try:
            entry = json_loads_strict(text)
        except (json.JSONDecodeError, NonFiniteConstantError) as err:
            raise PropagationJournalError(
                f"corrupt propagation journal {path}:{lineno}: {err}"
            ) from err
        if not isinstance(entry, dict) or not required <= set(entry):
            raise PropagationJournalError(
                f"corrupt propagation journal {path}:{lineno}: bad entry"
            )
        if entry["status"] not in ("pending", "acked", "dead-lettered"):
            raise PropagationJournalError(
                f"corrupt propagation journal {path}:{lineno}: "
                f"unknown status {entry['status']!r}"
            )
        if "retry_count" in entry:
            rc = entry["retry_count"]
            if not isinstance(rc, int) or isinstance(rc, bool) or rc < 0:
                raise PropagationJournalError(
                    f"corrupt propagation journal {path}:{lineno}: "
                    f"retry_count must be a non-negative integer"
                )
        if "next_attempt_at" in entry:
            na = entry["next_attempt_at"]
            if na is not None and not isinstance(na, str):
                raise PropagationJournalError(
                    f"corrupt propagation journal {path}:{lineno}: "
                    f"next_attempt_at must be an RFC3339 string or null"
                )
        entries.append(entry)
    return entries


def _append_propagation_line(root, entry):
    """Append one fsynced line to ``<root>/propagation.jsonl``."""
    path = Path(root) / "propagation.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as fh:
        fh.write(canonical_bytes(entry) + b"\n")
        fh.flush()
        os.fsync(fh.fileno())
    _fsync_dir(path.parent)
