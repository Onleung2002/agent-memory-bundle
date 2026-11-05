"""Tombstone-first import.

Deletion semantics (SPEC 1.2): importers MUST apply ALL tombstones before
any addition, so a stale bundle carrying already-deleted rows can never
resurrect them.
"""


def apply_tombstones(records, tombstones):
    """Return records minus any whose id is targeted by a tombstone."""
    deleted = {t["target_id"] for t in tombstones}
    return [r for r in records if r["id"] not in deleted]


def _merge_tombstones(tombstones):
    """Dedupe tombstones by target_id, keeping the latest deleted_at.

    deleted_at is normalized whole-second UTC RFC3339, so lexicographic
    max is chronological max.
    """
    latest = {}
    for tomb in tombstones:
        tid = tomb["target_id"]
        if tid not in latest or tomb["deleted_at"] > latest[tid]["deleted_at"]:
            latest[tid] = tomb
    return [latest[tid] for tid in sorted(latest)]


def import_bundle(store, bundle):
    """Import ``bundle`` into ``store``, tombstone-first.

    ``store`` and the return value are dicts {"records": [...],
    "tombstones": [...]}; ``bundle`` is a manifest dict.

    Ordering guarantee: every tombstone known to either side is applied
    BEFORE any record is added, so ordering inside the incoming bundle
    (records listed before tombstones, etc.) cannot change the outcome.
    Existing store records win over incoming duplicates by id.
    """
    all_tombstones = list(store.get("tombstones", [])) + list(
        bundle.get("tombstones", [])
    )
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
