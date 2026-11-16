"""Standalone re-implementation of the SPEC 1.4 canonical JSON rules.

This module deliberately does NOT import ``mbcp``: a third party
verifying an anchored receipt digest may not have the MBCP package
installed, so the digest-replay path is self-contained. The rules are
the SPEC 1.4 contract, not the ``mbcp`` code:

- object keys recursively sorted (byte order of UTF-8 code points)
- no insignificant whitespace (compact separators)
- values preserved verbatim: user strings — including RFC3339
  timestamps with sub-second precision and UTC offsets — are never
  rewritten; non-ASCII characters are emitted as raw UTF-8
  (``ensure_ascii=false`` semantics), never ``\\uXXXX`` escapes
- NaN / Infinity rejected at parse time (not representable in
  canonical JSON)

Anti-drift: tests/test_anchor.py pins byte-equality of
``canonical_bytes`` against ``mbcp.canonical.canonical_bytes`` over a
value corpus and over real L4-attested fixture receipts, so the two
implementations cannot silently diverge.
"""

import hashlib
import json


class NonFiniteConstantError(ValueError):
    """JSON text contained ``NaN``/``Infinity``/``-Infinity``.

    These literals are accepted by ``json.loads`` by default but are not
    canonical JSON (SPEC 1.4) and would crash serialisation later with an
    untyped ``ValueError``. Readers of externally-supplied bytes reject
    them at parse time via :func:`json_loads_strict`.
    """


def _reject_constant(value):
    raise NonFiniteConstantError(
        f"non-finite JSON constant {value!r} is not canonical JSON"
    )


def json_loads_strict(text):
    """Parse JSON text, rejecting NaN/Infinity literals as typed errors.

    Drop-in for ``json.loads`` on externally-supplied bytes (receipts,
    tombstone journals, anchor metadata, pending logs).
    """
    return json.loads(text, parse_constant=_reject_constant)


def canonical_bytes(obj):
    """Serialize ``obj`` to deterministic canonical JSON bytes (SPEC 1.4).

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
