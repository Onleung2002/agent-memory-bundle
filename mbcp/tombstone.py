"""Tombstone-first import.

Deletion semantics (SPEC 1.2): importers MUST apply ALL tombstones before
any addition, so a stale bundle carrying already-deleted rows can never
resurrect them.
"""

from datetime import datetime, timezone


def apply_tombstones(records, tombstones):
    """Return records minus any whose id is targeted by a tombstone."""
    deleted = {t["target_id"] for t in tombstones}
    return [r for r in records if r["id"] not in deleted]


def _parse_ts(value):
    """Parse an RFC3339 timestamp for chronological comparison.

    Falls back to the raw string (lexicographic order) for unparseable
    values so comparison stays total and deterministic.
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
    through a merge.
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
        latest = max(entry["copies"], key=lambda t: _parse_ts(t["deleted_at"]))
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
