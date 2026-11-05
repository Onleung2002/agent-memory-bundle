"""Deterministic canonical JSON for MBCP (stdlib only).

Canonical form guarantees:
- object keys recursively sorted (byte order of UTF-8 code points)
- no insignificant whitespace
- RFC3339 timestamps normalized to whole-second UTC ("Z" suffix)
- NaN / Infinity rejected (not representable in canonical JSON)
"""

import hashlib
import json
import re
from datetime import datetime, timezone

_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def utc_now():
    """Current time as a whole-second UTC RFC3339 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_timestamp(value):
    """Normalize an RFC3339 timestamp string to whole-second UTC 'Z' form.

    Non-timestamp values are returned unchanged.
    """
    if not isinstance(value, str) or not _TS_RE.match(value):
        return value
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    dt = dt.astimezone(timezone.utc).replace(microsecond=0)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _normalize(value):
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return normalize_timestamp(value)


def canonical_bytes(obj):
    """Serialize ``obj`` to deterministic canonical JSON bytes."""
    return json.dumps(
        _normalize(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(obj):
    """SHA-256 hex digest of the canonical form of ``obj``."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()
