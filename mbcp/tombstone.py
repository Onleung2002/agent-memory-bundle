"""Tombstone-first import.

Deletion semantics (SPEC 1.2): importers MUST apply ALL tombstones before
any addition, so a stale bundle carrying already-deleted rows can never
resurrect them.

Write boundary (SPEC 1.2, v0.1 audit §6 tightening, Isaac ruling
2026-11-08): resurrection is rejected at INGEST, not only at load time.
Any incoming record copy whose id is already targeted by a tombstone the
STORE knows about is refused with the typed
:class:`TombstonedIdRejectedError` — the whole id is dead, regardless of
the copy's digest. Copies whose ids are targeted only by tombstones the
INCOMING bundle itself carries are not a resurrection vector (tombstone
first still wins over them silently — the importer contract is
``build_import_bundle(..., tombstones=service.all_tombstones())``), so
only the store-side journal gates ingestion.
"""

from datetime import datetime, timezone

from .canonical import canonical_sha256, normalize_id


def _norm(value):
    """NFC-normalize for id comparison; pass non-strings through untouched.

    ``import_bundle``/``apply_tombstones`` are the raw layer (no structural
    validation — SPEC 1.5 validation lives at the load/build gates), so a
    hostile store could carry a non-string id; comparison must degrade to
    the pre-tightening behavior (never match a tombstone target), never an
    untyped TypeError.
    """
    return normalize_id(value) if isinstance(value, str) else value


class TombstonedIdRejectedError(ValueError):
    """Raised when an ingest path (``import_bundle`` /
    ``L1DeletionService.put_bundle``) is asked to accept a record copy
    whose id is already tombstoned (SPEC 1.2 write boundary, audit §6).

    The tombstone kills the whole id, so the rejection is id-level: it
    fires for ANY copy of a tombstoned id, regardless of the copy's
    ``integrity.digest``. The error names the rejected id.
    """


def apply_tombstones(records, tombstones):
    """Return records minus any whose id is targeted by a tombstone.

    Both sides are NFC-normalized before comparison (SPEC 1.5, audit §12)
    so an NFD variant of a tombstoned id cannot survive the filter; ids
    themselves are returned verbatim.
    """
    deleted = {_norm(t["target_id"]) for t in tombstones}
    return [r for r in records if _norm(r["id"]) not in deleted]


def _parse_ts(value):
    """Parse an RFC3339 timestamp for chronological comparison.

    The string-fallback branch (lexicographic order on the raw value) is
    DEFENSIVE-ONLY: load-path validation (check_tombstone_on_load, A-15)
    and build-path validation (validate_tombstone) guarantee that every
    ``deleted_at`` reaching this point already parsed as an RFC3339
    timestamp with timezone info. The fallback exists solely to keep the
    comparison total and deterministic if an unvalidated caller ever
    reaches this code — same defensive-only pattern as the non-string-body
    note in SPEC 1.6.
    """
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (0, dt, "")
    except (ValueError, AttributeError):
        return (1, None, value)


def _merge_tombstones(tombstones):
    """Dedupe tombstones by target_id.

    The copy with the latest ``deleted_at`` wins for ``deleted_at`` and
    ``reason``, but ``derived_artifacts`` is the sorted UNION of every
    copy's list (SPEC 1.2): L3 proof-of-reach evidence must never shrink
    through a merge. ``deleted_at`` is compared as an RFC3339 instant, and
    copies tied on ``deleted_at`` are resolved by GREATEST canonical
    SHA-256 of the tombstone (SPEC 1.2 dedupe tie), so the result is
    fully order-independent.

    The dedupe key is the VERBATIM ``target_id`` (merge bookkeeping, not
    an id-vs-id security comparison); NFC normalization applies where a
    tombstone target is compared against record ids (``apply_tombstones``,
    the ingest gate, the load pre-pass).
    """
    by_target = {}
    for tomb in tombstones:
        tid = tomb["target_id"]
        entry = by_target.setdefault(tid, {"copies": [], "artifacts": set()})
        entry["copies"].append(tomb)
        entry["artifacts"].update(tomb.get("derived_artifacts", []))
    merged = []
    for tid in sorted(by_target):
        entry = by_target[tid]
        latest = max(
            entry["copies"],
            key=lambda t: (_parse_ts(t["deleted_at"]), canonical_sha256(t)),
        )
        merged.append({
            "target_id": tid,
            "deleted_at": latest["deleted_at"],
            "reason": latest["reason"],
            "derived_artifacts": sorted(entry["artifacts"]),
        })
    return merged


def import_bundle(store, bundle):
    """Import ``bundle`` into ``store``, tombstone-first.

    ``store`` and the return value are dicts {"records": [...],
    "tombstones": [...]}; ``bundle`` is a manifest dict.

    Write boundary (SPEC 1.2, audit §6): before anything is merged, every
    incoming record copy is checked against the tombstones the STORE
    already knows; a copy of a store-tombstoned id is rejected with the
    typed :class:`TombstonedIdRejectedError` naming the id. Copies
    targeted only by tombstones the incoming bundle itself carries are
    still handled by the silent tombstone-first filter (importer
    contract), not by rejection.

    Ordering guarantee: every tombstone known to either side is applied
    BEFORE any record is added, so ordering inside the incoming bundle
    (records listed before tombstones, etc.) cannot change the outcome.
    Existing store records win over incoming duplicates by id.
    """
    store_tombstones = list(store.get("tombstones", []))
    incoming_tombstones = list(bundle.get("tombstones", []))
    store_tombstoned_ids = {_norm(t["target_id"]) for t in store_tombstones}
    for record in bundle.get("records", []):
        rid = _norm(record["id"])
        if rid in store_tombstoned_ids:
            raise TombstonedIdRejectedError(
                f"record id {record['id']!r} is tombstoned in the store "
                "journal; refusing to ingest a copy of a deleted id "
                "(SPEC 1.2 write boundary, audit §6)"
            )
    all_tombstones = store_tombstones + incoming_tombstones
    # 1. delete first — never resurrect
    kept = apply_tombstones(store.get("records", []), all_tombstones)
    survivors = apply_tombstones(bundle.get("records", []), all_tombstones)
    # 2. then add
    have = {r["id"] for r in kept}
    merged = kept + [r for r in survivors if r["id"] not in have]
    return {
        "records": merged,
        "tombstones": _merge_tombstones(all_tombstones),
    }
