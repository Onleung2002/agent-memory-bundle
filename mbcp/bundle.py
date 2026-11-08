"""Bundle build/validate + deterministic cross-bundle load_policy adjudication."""

import copy
import hashlib
import math
import re
from collections import defaultdict
from datetime import datetime

from . import _schema
from .canonical import canonical_bytes, canonical_sha256, utc_now

MBCP_VERSION = "0.1"

PRIORITY_ORDER = {"critical": 0, "standard": 1, "opportunistic": 2}
_MERGE_MODES = {"append_first_wins", "append_last_wins", "error_on_conflict"}
_BUDGET_MODES = {"truncate_last", "skip", "error"}
_LIFECYCLES = {"active", "archived", "deleted"}
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
# Bundle-id grammar (adversarial audit §4, SPEC-level ruling): a bundle id
# is a safe filename component — no characters that _safe_id() would have
# to rewrite (which made distinct ids collide on one file), no "..".
BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_RECORD_SCHEMA = None
_MANIFEST_SCHEMA = None
_TOMBSTONE_SCHEMA = None


class BudgetExceeded(ValueError):
    """Raised when a priority class exceeds its max_chars budget
    and the record's on_budget_exceed policy is "error"."""


class MergeConflict(ValueError):
    """Raised when duplicate record ids collide and any copy declares
    merge = "error_on_conflict"."""


class LoadValidationError(ValueError):
    """Raised when load() input is structurally malformed (bad types,
    missing required fields, bogus digest format). Unknown EXTRA fields
    are not an error: they pass through and are retained (SPEC P3)."""


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


def _reject_hostile_values(value, path="$", error_cls=None):
    """Reject hostile-but-parseable JSON values anywhere in ``value``.

    Adversarial audit §11: a conforming JSON document can carry lone
    surrogates (``"\\ud800"`` — legal per RFC 8259, NOT encodable UTF-8)
    and ``NaN``/``Infinity`` floats (accepted by ``json.loads``). Both
    crash ``canonical_bytes`` with UNTYPED errors (UnicodeEncodeError /
    ValueError) deep in the deletion path — after durable mutations, in
    the worst case permanently wedging the whole service root. Reject
    them here, at the boundary, as typed validation errors.

    ``error_cls`` defaults to :class:`LoadValidationError`; the build
    path passes ``_schema.ValidationError`` for equivalent strictness.
    """
    if error_cls is None:
        error_cls = LoadValidationError
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as err:
            raise error_cls(
                f"{path}: string is not encodable UTF-8 (lone surrogate): {err}"
            ) from err
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise error_cls(
                f"{path}: non-finite number {value!r} is not canonical JSON"
            )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_hostile_values(key, f"{path}.<key>", error_cls)
            _reject_hostile_values(item, f"{path}.{key}", error_cls)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_hostile_values(item, f"{path}[{index}]", error_cls)


def _check_bundle_id_grammar(bundle_id, error_cls=None):
    """Enforce the bundle-id grammar on both validation paths.

    The JSON Schema pattern pins ``^[A-Za-z0-9._-]{1,64}$``; ``..`` is
    rejected here (the minimal validator has no ``not`` keyword). The
    deletion service relies on this: ``_safe_id()`` must be injective
    over grammar-valid ids or two bundles would share one file.
    """
    if error_cls is None:
        error_cls = LoadValidationError
    if (
        not isinstance(bundle_id, str)
        or not BUNDLE_ID_RE.match(bundle_id)
        or ".." in bundle_id
    ):
        raise error_cls(
            f"$.bundle.id: bundle id must match ^[A-Za-z0-9._-]{{1,64}}$ "
            f"and must not contain '..', got {bundle_id!r}"
        )


def check_sensitivity_invariant(record):
    """Machine-checkable invariant (BACKLOG M2 #6, Isaac ruling 2026-11-06).

    ``provenance.sensitivity == "secret"`` combined with
    ``consent.exportable is True`` is REJECTED on the build path: a secret
    record must never be marked exportable. Deterministic — pure function of
    the record, raises ValueError naming the violated rule. Records with no
    sensitivity field (or any non-secret value) pass. This is the mbcp-layer
    single source of truth; importers/_common.py delegates here.
    """
    provenance = record.get("provenance")
    consent = record.get("consent")
    if (
        isinstance(provenance, dict)
        and provenance.get("sensitivity") == "secret"
        and isinstance(consent, dict)
        and consent.get("exportable") is True
    ):
        raise ValueError(
            "invariant violation: provenance.sensitivity='secret' must not be "
            "combined with consent.exportable=true (Isaac ruling 2026-11-06, "
            "BACKLOG M2 #6)"
        )
    return record


def validate_record(record):
    _schema.validate(record, _record_schema())
    _reject_hostile_values(record, "$", _schema.ValidationError)
    return check_sensitivity_invariant(record)


def validate_tombstone(tombstone):
    _schema.validate(tombstone, _tombstone_schema())
    _reject_hostile_values(tombstone, "$", _schema.ValidationError)
    _check_deleted_at_rfc3339(tombstone["deleted_at"], "$.tombstones[].deleted_at")
    return tombstone


def validate_bundle(manifest):
    _schema.validate(manifest, _manifest_schema())
    _reject_hostile_values(manifest, "$", _schema.ValidationError)
    _check_bundle_id_grammar(manifest["bundle"]["id"], _schema.ValidationError)
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
    sensitivity=None,
    priority="standard",
    max_chars=4096,
    on_budget_exceed="skip",
    merge="append_first_wins",
):
    """Build a conforming record dict. Integrity digest is the SHA-256 of
    the canonical body.

    ``sensitivity`` (optional) is recorded in ``provenance.sensitivity``;
    the sensitivity invariant is enforced here on the build path:
    ``sensitivity="secret"`` with ``exportable=True`` raises ValueError.
    """
    consent = {"exportable": exportable}
    if retention is not None:
        consent["retention"] = retention
    provenance = {"source": source}
    if sensitivity is not None:
        provenance["sensitivity"] = sensitivity
    record = {
        "id": record_id,
        "kind": kind,
        "body": body,
        "scope": {"owner": owner},
        "time": {"created": created or utc_now()},
        "lifecycle": lifecycle,
        "provenance": provenance,
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
    return check_sensitivity_invariant(validate_record(record))


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
    """Build and validate a manifest dict.

    Every record is checked against the build-path sensitivity invariant
    (BACKLOG M2 #6): a bundle containing a secret record marked exportable
    cannot be built. The load path (``load``/``check_record_on_load``) stays
    a tolerant reader for records already on disk (SPEC 1.5) and does NOT
    enforce this invariant.
    """
    records = list(records)
    for record in records:
        check_sensitivity_invariant(record)
    manifest = {
        "bundle": {"id": bundle_id},
        "mbcp_version": mbcp_version,
        "records": records,
        "tombstones": list(tombstones),
    }
    return validate_bundle(manifest)


# ---------------------------------------------------------------------------
# load-time structural validation (SPEC 1.5)
#
# Tolerant by design: unknown EXTRA fields anywhere in a record pass through
# and are retained (unknown-field retention, SPEC P3). Malformed STRUCTURE
# (missing required fields, wrong types, invalid enum values, bogus digest
# format) raises LoadValidationError — never a bare KeyError/TypeError.
# ---------------------------------------------------------------------------


def _err(path, msg):
    return LoadValidationError(f"{path}: {msg}")


def _check(cond, path, msg):
    if not cond:
        raise _err(path, msg)


def _check_str(obj, key, path, *, min_len=0, required=True):
    if key not in obj:
        _check(not required, path, f"missing required property {key!r}")
        return None
    value = obj[key]
    _check(isinstance(value, str), f"{path}.{key}", "expected string")
    _check(len(value) >= min_len, f"{path}.{key}", f"shorter than {min_len}")
    return value


def _check_dict(obj, key, path, *, required=True):
    if key not in obj:
        _check(not required, path, f"missing required property {key!r}")
        return None
    value = obj[key]
    _check(isinstance(value, dict), f"{path}.{key}", "expected object")
    return value


def _check_deleted_at_rfc3339(value, path):
    """A-15 (SPEC 1.2): ``deleted_at`` must parse as RFC3339 WITH timezone
    info — ``Z`` or a numeric ``±HH:MM`` offset. Naive timestamps (no
    offset) and unparseable strings are rejected. Shared by the build path
    (validate_tombstone) and the load path (check_tombstone_on_load).
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise _err(
            path,
            "deleted_at must be a parseable RFC3339 timestamp "
            "(e.g. '2026-06-01T00:00:00Z')",
        )
    if parsed.tzinfo is None:
        raise _err(
            path,
            "deleted_at must carry timezone info ('Z' or a numeric offset); "
            "naive timestamps are rejected",
        )
    return value


def check_record_on_load(record, path="$.records[]"):
    """Structurally validate a record for load; raise LoadValidationError.

    Tolerant-reader scope (SPEC 1.5): this checks STRUCTURE only. It does
    NOT enforce the build-path sensitivity invariant (secret + exportable)
    — that invariant is enforced by make_record/validate_record/build_bundle
    and must not silently turn the load path into a validator; records that
    were already on disk keep loading.
    """
    _check(isinstance(record, dict), path, "expected object")
    _check_str(record, "id", path, min_len=1)
    _check_str(record, "kind", path, min_len=1)
    # A-07 (SPEC 1.6): a non-string body is NOT malformed structure on the
    # load path — the record is DROPPED silently later in load(), not
    # rejected. Only a MISSING body is a validation error here; the build
    # path (validate_record) still rejects non-string bodies outright.
    _check("body" in record, path, "missing required property 'body'")
    scope = _check_dict(record, "scope", path)
    _check_str(scope, "owner", f"{path}.scope", min_len=1)
    time_ = _check_dict(record, "time", path)
    _check_str(time_, "created", f"{path}.time", min_len=1)
    _check(
        record.get("lifecycle") in _LIFECYCLES,
        f"{path}.lifecycle",
        f"expected one of {sorted(_LIFECYCLES)}",
    )
    provenance = _check_dict(record, "provenance", path)
    _check_str(provenance, "source", f"{path}.provenance", min_len=1)
    consent = _check_dict(record, "consent", path)
    _check(
        isinstance(consent.get("exportable"), bool),
        f"{path}.consent.exportable",
        "expected boolean",
    )
    integrity = _check_dict(record, "integrity", path)
    _check(
        integrity.get("algo") == "sha256",
        f"{path}.integrity.algo",
        "expected 'sha256'",
    )
    digest = integrity.get("digest")
    _check(
        isinstance(digest, str) and _DIGEST_RE.match(digest) is not None,
        f"{path}.integrity.digest",
        "expected 64 lowercase hex chars",
    )
    mbcp = _check_dict(record, "mbcp", path)
    policy = _check_dict(mbcp, "load_policy", f"{path}.mbcp")
    _check(
        policy.get("priority") in PRIORITY_ORDER,
        f"{path}.mbcp.load_policy.priority",
        f"expected one of {sorted(PRIORITY_ORDER)}",
    )
    max_chars = policy.get("max_chars")
    _check(
        isinstance(max_chars, int) and not isinstance(max_chars, bool)
        and max_chars >= 0,
        f"{path}.mbcp.load_policy.max_chars",
        "expected non-negative integer",
    )
    _check(
        policy.get("on_budget_exceed") in _BUDGET_MODES,
        f"{path}.mbcp.load_policy.on_budget_exceed",
        f"expected one of {sorted(_BUDGET_MODES)}",
    )
    _check(
        policy.get("merge") in _MERGE_MODES,
        f"{path}.mbcp.load_policy.merge",
        f"expected one of {sorted(_MERGE_MODES)}",
    )
    return record


def check_tombstone_on_load(tombstone, path="$.tombstones[]"):
    _check(isinstance(tombstone, dict), path, "expected object")
    _check_str(tombstone, "target_id", path, min_len=1)
    _check_str(tombstone, "deleted_at", path, min_len=1)
    _check_deleted_at_rfc3339(tombstone["deleted_at"], f"{path}.deleted_at")
    _check_str(tombstone, "reason", path)
    artifacts = tombstone.get("derived_artifacts")
    _check(
        isinstance(artifacts, list)
        and all(isinstance(a, str) for a in artifacts),
        f"{path}.derived_artifacts",
        "expected array of strings",
    )
    return tombstone


def check_manifest_on_load(manifest):
    _check(isinstance(manifest, dict), "$", "expected manifest object")
    # audit §11: hostile-but-parseable values (lone surrogates, NaN /
    # Infinity floats) are rejected HERE, as LoadValidationError, before
    # any canonical_bytes call — never an unwrapped UnicodeEncodeError /
    # ValueError from inside the loader or the deletion path.
    _reject_hostile_values(manifest)
    bundle = _check_dict(manifest, "bundle", "$")
    _check_str(bundle, "id", "$.bundle", min_len=1)
    # audit §4: the same bundle-id grammar as the build path / schema.
    _check_bundle_id_grammar(bundle["id"])
    records = manifest.get("records", [])
    _check(isinstance(records, list), "$.records", "expected array")
    tombstones = manifest.get("tombstones", [])
    _check(isinstance(tombstones, list), "$.tombstones", "expected array")
    for i, record in enumerate(records):
        check_record_on_load(record, f"$.records[{i}]")
    for i, tombstone in enumerate(tombstones):
        check_tombstone_on_load(tombstone, f"$.tombstones[{i}]")
    return manifest


def _policy(record):
    return record["mbcp"]["load_policy"]


def _size_of(record):
    body = record["body"]
    if isinstance(body, str):
        return len(body)
    return len(canonical_bytes(body))


def _digest_ok(record):
    """Verify integrity.digest against the body (SPEC 1.6)."""
    digest = hashlib.sha256(canonical_bytes(record["body"])).hexdigest()
    return digest == record["integrity"]["digest"]


def _resolve_duplicates(entries):
    """Merge records sharing an id, deterministically.

    ``entries`` is a list of (record, sort_key) already in deterministic
    order. Returns a list of (record, sort_key) winners.

    Mixed merge modes (SPEC 1.1): ``error_on_conflict`` anywhere in the
    group raises MergeConflict; else if ALL copies declare
    ``append_last_wins`` the last copy wins; otherwise the first copy wins.
    """
    groups = {}
    order = []
    for record, key in entries:
        rid = record["id"]
        if rid not in groups:
            groups[rid] = []
            order.append(rid)
        groups[rid].append((record, key))

    winners = []
    for rid in order:
        group = groups[rid]
        if len(group) == 1:
            winners.append(group[0])
            continue
        modes = {_policy(r)["merge"] for r, _ in group}
        if "error_on_conflict" in modes:
            raise MergeConflict(
                f"record id {rid!r} appears in {len(group)} bundles "
                "with merge='error_on_conflict'"
            )
        if modes == {"append_last_wins"}:
            winners.append(group[-1])
        else:
            winners.append(group[0])
    return winners


def load(bundles):
    """Deterministic cross-bundle load.

    Same set of bundles + same consumer version -> byte-identical result:

    0. every manifest/record/tombstone is structurally validated
       (LoadValidationError on malformed input; unknown extra fields pass
       through and are retained)
    1. integrity digests are verified; records whose digest does not match
       their body are dropped (SPEC 1.6)
    2. id-wide deletion pre-pass (SPEC 1.2): the ids targeted by ALL
       tombstones from ALL bundles PLUS the ids of ALL records with
       lifecycle="deleted" from ALL bundles are gathered BEFORE any record
       is emitted. A record carrying such an id is excluded entirely —
       even an active (or archived) copy of the same id in another bundle
       cannot load. lifecycle="deleted" is thus an id-wide deletion signal,
       treated exactly like a tombstone; lifecycle="archived" is unaffected
    3. manifests are ordered by (bundle id, canonical SHA-256 of the
       manifest) — duplicate bundle ids get a content-digest tiebreak, so
       the result never depends on input order (SPEC 1.4)
    4. duplicate ids merged per load_policy.merge (mixed modes:
       error_on_conflict dominates; all-last -> last; otherwise first)
    5. ordered by priority (critical > standard > opportunistic), then the
       deterministic manifest position as stable tie-break
    6. max_chars is the CLASS budget: the effective budget of a priority
       class is the MINIMUM max_chars declared by any loaded record of
       that class, consumed cumulatively; over-budget records follow
       load_policy.on_budget_exceed. truncate_last re-digests the
       truncated body and marks integrity.truncated = true (SPEC 1.6).
    """
    manifests = [check_manifest_on_load(m) for m in bundles]
    # deterministic order, content-digest tiebreak for duplicate bundle ids
    manifests.sort(key=lambda m: (m["bundle"]["id"], canonical_sha256(m)))

    # SPEC 1.2 id-wide deletion pre-pass, applied BEFORE any record is
    # emitted. Two equivalent deletion signals, gathered across ALL input
    # manifests: explicit tombstones, and records whose lifecycle is
    # "deleted" (an id-wide deletion signal, not merely a per-record
    # filter). Every copy of a targeted id — active, archived, deleted —
    # in ANY bundle is excluded from the result, so a bundle holding an
    # active copy of an id deleted elsewhere can never resurrect it.
    tombstoned = set()
    for manifest in manifests:
        for tombstone in manifest.get("tombstones", []):
            tombstoned.add(tombstone["target_id"])
    deleted_ids = set()
    for manifest in manifests:
        for record in manifest.get("records", []):
            if record.get("lifecycle") == "deleted":
                deleted_ids.add(record["id"])
    excluded = tombstoned | deleted_ids

    entries = []
    for manifest_index, manifest in enumerate(manifests):
        for index, record in enumerate(manifest.get("records", [])):
            if record["id"] in excluded:
                continue
            # A-07 (SPEC 1.6): non-string body -> silent drop, no exception
            if not isinstance(record["body"], str):
                continue
            if not _digest_ok(record):
                continue
            entries.append((record, (manifest_index, index)))

    winners = _resolve_duplicates(entries)

    budgets = {}
    for record, _ in winners:
        priority = _policy(record)["priority"]
        declared = _policy(record)["max_chars"]
        budgets[priority] = min(declared, budgets.get(priority, declared))

    keyed = [
        (PRIORITY_ORDER[_policy(record)["priority"]], key, record)
        for record, key in winners
    ]
    keyed.sort(key=lambda t: (t[0], t[1]))

    budget_used = defaultdict(int)
    loaded = []
    for _, _, record in keyed:
        policy = _policy(record)
        priority = policy["priority"]
        remaining = budgets[priority] - budget_used[priority]
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
        # budget, re-digested and marked; if nothing remains (or the body
        # is not a string) the record drops out entirely.
        if remaining <= 0 or not isinstance(record["body"], str):
            continue
        truncated = copy.deepcopy(record)
        truncated["body"] = truncated["body"][:remaining]
        truncated["integrity"]["digest"] = hashlib.sha256(
            canonical_bytes(truncated["body"])
        ).hexdigest()
        truncated["integrity"]["truncated"] = True
        loaded.append(truncated)
        budget_used[priority] += remaining
    return loaded


def load_bytes(bundles):
    """Canonical bytes of the deterministic load result."""
    return canonical_bytes(load(bundles))
