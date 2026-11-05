"""Bundle build/validate + deterministic cross-bundle load_policy adjudication."""

import copy
import hashlib
from collections import defaultdict

from . import _schema
from .canonical import canonical_bytes, utc_now

MBCP_VERSION = "0.1"

PRIORITY_ORDER = {"critical": 0, "standard": 1, "opportunistic": 2}

_RECORD_SCHEMA = None
_MANIFEST_SCHEMA = None
_TOMBSTONE_SCHEMA = None


class BudgetExceeded(ValueError):
    """Raised when a priority class exceeds its max_chars budget
    and the record's on_budget_exceed policy is "error"."""


class MergeConflict(ValueError):
    """Raised when duplicate record ids collide and any copy declares
    merge = "error_on_conflict"."""


def _record_schema():
    global _RECORD_SCHEMA
    if _RECORD_SCHEMA is None:
        _RECORD_SCHEMA = _schema.load_schema("bundle-record.v0")
    return _RECORD_SCHEMA


def _manifest_schema():
    global _MANIFEST_SCHEMA
    if _MANIFEST_SCHEMA is None:
        _MANIFEST_SCHEMA = _schema.load_schema("manifest.v0")
    return _MANIFEST_SCHEMA


def _tombstone_schema():
    global _TOMBSTONE_SCHEMA
    if _TOMBSTONE_SCHEMA is None:
        _TOMBSTONE_SCHEMA = _schema.load_schema("tombstone.v0")
    return _TOMBSTONE_SCHEMA


def validate_record(record):
    _schema.validate(record, _record_schema())
    return record


def validate_tombstone(tombstone):
    _schema.validate(tombstone, _tombstone_schema())
    return tombstone


def validate_bundle(manifest):
    _schema.validate(manifest, _manifest_schema())
    return manifest


def make_record(
    record_id,
    kind,
    body,
    owner,
    *,
    source="synthetic",
    created=None,
    lifecycle="active",
    retention=None,
    exportable=True,
    priority="standard",
    max_chars=4096,
    on_budget_exceed="skip",
    merge="append_first_wins",
):
    """Build a conforming record dict. Integrity digest is the SHA-256 of
    the canonical body."""
    consent = {"exportable": exportable}
    if retention is not None:
        consent["retention"] = retention
    record = {
        "id": record_id,
        "kind": kind,
        "body": body,
        "scope": {"owner": owner},
        "time": {"created": created or utc_now()},
        "lifecycle": lifecycle,
        "provenance": {"source": source},
        "consent": consent,
        "integrity": {
            "algo": "sha256",
            "digest": hashlib.sha256(canonical_bytes(body)).hexdigest(),
        },
        "mbcp": {
            "load_policy": {
                "priority": priority,
                "max_chars": max_chars,
                "on_budget_exceed": on_budget_exceed,
                "merge": merge,
            }
        },
    }
    return validate_record(record)


def make_tombstone(target_id, reason, *, deleted_at=None, derived_artifacts=()):
    """Build a conforming tombstone dict."""
    tombstone = {
        "target_id": target_id,
        "deleted_at": deleted_at or utc_now(),
        "reason": reason,
        "derived_artifacts": list(derived_artifacts),
    }
    return validate_tombstone(tombstone)


def build_bundle(bundle_id, records=(), tombstones=(), *, mbcp_version=MBCP_VERSION):
    """Build and validate a manifest dict."""
    manifest = {
        "bundle": {"id": bundle_id},
        "mbcp_version": mbcp_version,
        "records": list(records),
        "tombstones": list(tombstones),
    }
    return validate_bundle(manifest)


def _policy(record):
    return record["mbcp"]["load_policy"]


def _size_of(record):
    body = record["body"]
    if isinstance(body, str):
        return len(body)
    return len(canonical_bytes(body))


def _resolve_duplicates(entries):
    """Merge records sharing an id, deterministically.

    ``entries`` is a list of (record, bundle_id, index) already in
    deterministic (bundle_id, index) order. Returns a list of winners in
    the same relative order as their first occurrence.
    """
    groups = {}
    order = []
    for record, bundle_id, index in entries:
        rid = record["id"]
        if rid not in groups:
            groups[rid] = []
            order.append(rid)
        groups[rid].append(record)

    winners = []
    for rid in order:
        group = groups[rid]
        if len(group) == 1:
            winners.append(group[0])
            continue
        modes = {_policy(r)["merge"] for r in group}
        if "error_on_conflict" in modes:
            raise MergeConflict(
                f"record id {rid!r} appears in {len(group)} bundles "
                "with merge='error_on_conflict'"
            )
        if modes == {"append_last_wins"}:
            winners.append(group[-1])
        else:
            # append_first_wins (or mixed first/last): first occurrence wins
            winners.append(group[0])
    return winners


def load(bundles):
    """Deterministic cross-bundle load.

    Same set of bundles + same consumer version -> byte-identical result:
    1. records gathered in (bundle id, in-bundle index) order
    2. duplicate ids merged per load_policy.merge
    3. ordered by priority (critical > standard > opportunistic), then
       (bundle id, in-bundle index) as stable tie-break
    4. per-priority-class max_chars budget enforced per
       load_policy.on_budget_exceed (truncate_last | skip | error)
    """
    entries = []
    for manifest in sorted(bundles, key=lambda m: m["bundle"]["id"]):
        bundle_id = manifest["bundle"]["id"]
        for index, record in enumerate(manifest.get("records", [])):
            entries.append((record, bundle_id, index))

    winners = _resolve_duplicates(entries)

    keyed = []
    position = {id(r): i for i, (r, _, _) in enumerate(entries)}
    for record in winners:
        keyed.append((PRIORITY_ORDER[_policy(record)["priority"]], position[id(record)], record))
    keyed.sort(key=lambda t: (t[0], t[1]))

    budget_used = defaultdict(int)
    loaded = []
    for _, _, record in keyed:
        policy = _policy(record)
        priority = policy["priority"]
        remaining = policy["max_chars"] - budget_used[priority]
        size = _size_of(record)
        if size <= remaining:
            loaded.append(record)
            budget_used[priority] += size
            continue
        mode = policy["on_budget_exceed"]
        if mode == "error":
            raise BudgetExceeded(
                f"record {record['id']!r} ({size} chars) exceeds remaining "
                f"budget {remaining} for class {priority!r}"
            )
        if mode == "skip":
            continue
        # truncate_last: keep the record with its body cut to the remaining
        # budget; if nothing remains, the record drops out entirely.
        if remaining <= 0 or not isinstance(record["body"], str):
            continue
        truncated = copy.deepcopy(record)
        truncated["body"] = truncated["body"][:remaining]
        loaded.append(truncated)
        budget_used[priority] += remaining
    return loaded


def load_bytes(bundles):
    """Canonical bytes of the deterministic load result."""
    return canonical_bytes(load(bundles))
