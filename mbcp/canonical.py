"""Deterministic canonical JSON for MBCP (stdlib only).

Canonical form guarantees (SPEC 1.4):
- object keys recursively sorted (byte order of UTF-8 code points)
- no insignificant whitespace
- VALUES ARE PRESERVED VERBATIM: user strings (including RFC3339
  timestamps with sub-second precision and UTC offsets) are never
  rewritten. Canonicalization normalizes STRUCTURE only, so event
  ordering information in timestamps survives a canonical round-trip
  (json.loads(canonical_bytes(x)) == x for every conforming value).
- NaN / Infinity rejected (not representable in canonical JSON)
"""

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone


class NonFiniteConstantError(ValueError):
    """JSON text contained ``NaN``/``Infinity``/``-Infinity``.

    These literals are accepted by ``json.loads`` by default but are not
    canonical JSON (SPEC 1.4) and crash ``canonical_bytes`` later with an
    untyped ``ValueError``. Readers of externally-supplied bytes reject
    them at parse time via :func:`json_loads_strict`.
    """


def _reject_constant(value):
    raise NonFiniteConstantError(
        f"non-finite JSON constant {value!r} is not canonical JSON"
    )


def json_loads_strict(text):
    """Parse JSON text, rejecting NaN/Infinity literals as typed errors.

    Drop-in for ``json.loads`` on externally-supplied bytes (bundle
    manifests, tombstone journals, removal evidence, recovery logs,
    receipts, propagation packs/acks/journals).
    """
    return json.loads(text, parse_constant=_reject_constant)

_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def utc_now():
    """Current time as a whole-second UTC RFC3339 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_timestamp(value):
    """Normalize an RFC3339 timestamp string to whole-second UTC 'Z' form.

    Non-timestamp values are returned unchanged. NOTE: this is a display /
    comparison helper — canonicalization does NOT call it (values are
    preserved verbatim in the canonical form).
    """
    if not isinstance(value, str) or not _TS_RE.match(value):
        return value
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_id(text):
    """Unicode NFC normalization for id COMPARISON (SPEC 1.5, audit §12).

    Comparison semantics only: ids are stored verbatim, never rewritten.
    Every id comparison (tombstone ``target_id`` vs record id, duplicate
    resolution, write-boundary rejection sets) normalizes BOTH sides with
    NFC first, so an NFD variant of an id cannot bypass a tombstone
    filter. Case variants are NOT folded (``Rec-1`` vs ``rec-1`` stay
    distinct — a known residual, per SPEC 1.5).
    """
    return unicodedata.normalize("NFC", text)


def canonical_bytes(obj):
    """Serialize ``obj`` to deterministic canonical JSON bytes.

    Structure is normalized (sorted keys, compact separators); values are
    emitted verbatim.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(obj):
    """SHA-256 hex digest of the canonical form of ``obj``."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()
