"""L2 minimal: cross-root tombstone propagation packs (RFC Q1/Q2/Q3).

Scope (RFC §1 Q1–Q3, approved 2026-11-06): the smallest cross-service-root
propagation. A *source* root exports a **propagation pack** — the tombstone
set of its journal (deduped with :meth:`L1DeletionService.all_tombstones`
semantics, optionally filtered to target ids), each tombstone with its
canonical SHA-256, a pack-level digest chain and an attestation block. A
*destination* root imports the pack through the existing tombstone-first
machinery (journal append, then :meth:`L1DeletionService.recover`, so store
records targeted by pack tombstones are removed and can never resurrect).

Integrity model — READ THIS BEFORE RELYING ON A PACK OR ACK:

Propagation packs and acks provide **digest-chain integrity only;
tamper-evidence relies on the writer of this root not forging; cryptographic
signing is M4/L4 scope.** There are no signatures anywhere in this module:
anyone who can write the destination root can forge a self-consistent pack
that "verifies". The digest chain detects accidental corruption and
truncation, and binds an ack to exactly the tombstones that were applied —
it does NOT prove to a third party that the source root really issued the
pack. That proof waits for ed25519 signatures (M4, RFC §3.2 Q6).

Failure semantics (Q3): propagation is best-effort. The append-only
``propagation.jsonl`` journal records every intake attempt as
``pending``/``acked``; fsynced before the call returns. This is an
**attempts audit**, NOT a deduped state log: every successful intake —
including an idempotent no-op re-import that applied nothing — appends
exactly one ``acked`` line, so the line count grows by one per import
(BACKLOG M3 round-2 advisory 1, pinned; do not "fix" the growth without
a deliberate design change). Fail-closed, per the tombstone-first
philosophy: an unacked propagation is NOT evidence of propagation, and
``verify_receipt`` never consults propagation state, so a pending (or
forged-acked) line can never launder a receipt into ok:True.

Layout of a service root using propagation (in addition to the L1 layout)::

    propagation.jsonl            # append-only pending->acked intake journal
    propagation/acks/<hex16>.json  # ack artifacts, keyed by pack_digest[:16]

Determinism: a pack is a pure function of (journal tombstone set,
target_ids, source_root, issued_at) — tombstones are sorted by canonical
SHA-256, the pack digest binds the source root AND the sorted digest
list, and the whole artifact is canonical JSON (SPEC 1.4). Same inputs ->
byte-identical pack.
"""

import json
import os
from pathlib import Path

from . import _schema
from .bundle import validate_tombstone
from .canonical import (
    NonFiniteConstantError,
    canonical_bytes,
    canonical_sha256,
    json_loads_strict,
    utc_now,
)
from .deletion import L1DeletionService, _atomic_write, _fsync_dir

PACK_SCHEMA = None
ACK_SCHEMA = None

# Verbatim-ish no-signature limitation, required in every ack (and mirrored
# in docstrings): the digest chain is NOT a cryptographic provenance proof.
ACK_LIMITATIONS = [
    "digest-chain integrity only; tamper-evidence relies on the writer of "
    "this root not forging; cryptographic signing is M4/L4 scope."
]


class PropagationError(ValueError):
    """Base class for L2 propagation failures."""


class PackValidationError(PropagationError):
    """Raised when a propagation pack is malformed or its attestation /
    digest chain does not verify (tampered tombstone, stale digest list,
    recomputed pack digest over the wrong set, missing attestation, ...).

    Rejection lives at the digest-chain integrity layer ONLY: a
    self-consistent pack produced by the writer of the source root cannot be
    told apart from a forgery, because there are no signatures (M4/L4).
    """


class PropagationJournalError(PropagationError):
    """Raised when ``propagation.jsonl`` is corrupt (A-15 hygiene: a loud
    typed error naming the line, never a bare JSONDecodeError)."""


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


def export_propagation_pack(root, target_ids=None, *, source_root=None, now=None):
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

    Deterministic: same journal state + same (``source_root``, ``now``)
    -> byte-identical pack. No signatures — digest-chain integrity only;
    tamper-evidence relies on the writer of this root not forging;
    cryptographic signing is M4/L4 scope.
    """
    service = _as_service(root)
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
    _schema.validate(pack, _pack_schema())
    return pack


def import_propagation_pack(root, pack, *, now=None):
    """Import a propagation pack into this root (RFC UC1 minimal intake gate).

    Intake is gated: a pack whose attestation/digest chain does not verify
    (missing attestation, mutated tombstone, stale digest list, pack digest
    recomputed over the wrong set, mismatched artifact integrity) is
    rejected with :class:`PackValidationError` and NOTHING is applied.
    Verification is digest-chain integrity ONLY — no anti-forgery promise
    is claimed, because no signatures exist (M4/L4 scope).

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
    ``ACK_LIMITATIONS`` — digest-chain integrity only; tamper-evidence
    relies on the writer of this root not forging; cryptographic signing
    is M4/L4 scope.
    """
    service = _as_service(root)
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


def record_pending_propagation(root, *, pack_digest, source_root, now=None):
    """Record a propagation attempt that could not yet be acked (Q3).

    Best-effort semantics: when a pack cannot be imported (target root
    offline, verification deferred, apply failed partway), the intake is
    durably recorded as ``pending``. Fail-closed: an unacked propagation is
    not evidence of propagation — a pending line never influences
    ``verify_receipt`` and must never be presented as proof of erasure.
    """
    entry = {
        "pack_digest": pack_digest,
        "source_root": source_root,
        "status": "pending",
        "ack_digest": None,
        "at": now or utc_now(),
    }
    _append_propagation_line(_as_service(root).root, entry)
    return entry


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
    bytes and each line decoded explicitly — invalid UTF-8 raises the
    typed error with path:lineno, never a bare UnicodeDecodeError (the L1
    ``journal_tombstones`` reader shares this pattern).
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
        if entry["status"] not in ("pending", "acked"):
            raise PropagationJournalError(
                f"corrupt propagation journal {path}:{lineno}: "
                f"unknown status {entry['status']!r}"
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
