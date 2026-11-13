"""Pure-Python ed25519 (RFC 8032) — vendored reference implementation.

PROVENANCE: this module is the public-domain "slow" affine Python
reference for ed25519 (Bernstein, Duif, Lange, Schwabe, Yang —
ed25519.cr.yp.to), implementing the scheme RFC 8032 specifies in §5.1.
RFC 8032 carries its own Python listing in Appendix A, which implements
the SAME scheme in a different code style (``modp_*`` / ``secret_expand``
/ ``point_mul``); this module is NOT that listing. The conformance gate
is the RFC 8032 §7.1 vectors pinned in tests/test_ed25519.py. It is
vendored because this environment has no ``cryptography``/PyNaCl and no
network access; the MBCP L4 attestation layer (mbcp.attestation) needs a
self-contained ed25519.

Scope is deliberately minimal — the three primitives the profile uses:

- :func:`publickey` — derive the 32-byte public key from a 32-byte seed;
- :func:`signature` — deterministic ed25519 signature (64 bytes);
- :func:`checkvalid` — verify a signature against a public key.

Determinism (SPEC 1.2.6): ed25519 signatures are deterministic — the same
(seed, message) always produces the same signature; there is no nonce
randomness. Same envelope bytes + same key -> same attestation_sig.

Performance is not a design goal here (SPEC 1.2.6 Round B ruling): the
affine-coordinate reference with per-addition inversion is slow but short,
provenance-clean, and easy to audit against the RFC. Do NOT "optimize"
this file without re-pinning the RFC 8032 §7.1 known-answer vectors.

Security notes (honest framing):

- This is a signature scheme, not a trust root: verification proves a
  private key signed the bytes, not WHO that key belongs to. Binding a
  key to an identity needs an out-of-band anchor (SPEC 1.2.6).
- ``checkvalid`` raises on structurally invalid input (wrong lengths,
  off-curve points, non-canonical S) rather than returning False, so
  callers must treat exceptions as verification failure — never as
  validity.
- ``checkvalid`` enforces the RFC 8032 §5.1.7 canonical-scalar check: a
  signature whose ``S`` decodes outside ``[0, L)`` raises instead of
  verifying. Without it, ``S + L`` / ``S + 2L`` malleations of a valid
  signature would ALSO verify (pinned in tests/test_ed25519.py).
- There is NO dom2/context support: only pure ed25519 (RFC 8032 §5.1) is
  implemented, so the §7.2 ``ctx`` variants are out of scope and none of
  those vectors apply to this module.
- Known limitation (recorded, not defended): the verification equation is
  the reference's cofactorless form ``[S]B == R + [k]A``, which RFC 8032
  §5.1.7 explicitly permits ("sufficient, but not required") in place of
  the cofactored ``[8][S]B == [8]R + [8][k]A'``, and ``_decode_point``
  (the reference's ``decodepoint``) accepts small-order and
  non-canonically-encoded points instead of rejecting them. This module
  is therefore NOT hardened against malicious public keys. The L4 gates
  narrow the exposure — the attestation check binds the embedded pubkey
  to its ``key_id`` fingerprint and the accept-list gate (SPEC 1.2.7)
  only admits listed (key_id, pubkey) pairs — but a hostile pubkey still
  reaches :func:`checkvalid` before the accept-list gate runs, so do not
  treat this module as a general-purpose verifier.
"""

import hashlib

# Curve parameters (RFC 8032):
#   edwards25519:  -x^2 + y^2 = 1 + d x^2 y^2  over GF(2^255 - 19)
_b = 256                      # bits per encoded element
_q = 2 ** 255 - 19            # field prime
_l = 2 ** 252 + 27742317777372353535851937790883648493  # group order


def _H(message):
    return hashlib.sha512(message).digest()


def _inv(z):
    """Multiplicative inverse mod q (Fermat's little theorem)."""
    return pow(z, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q - 1) // 4, _q)  # sqrt(-1) mod q


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_BY = 4 * _inv(5) % _q
_Bx = _xrecover(_BY)
_B = [_Bx % _q, _BY % _q]  # the ed25519 base point


def _edwards_add(P, Q):
    """Edwards point addition (affine coordinates, reference form)."""
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % _q, y3 % _q]


def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encode_int(y):
    bits = [(y >> i) & 1 for i in range(_b)]
    return bytes(
        [sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(_b // 8)]
    )


def _encode_point(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(_b - 1)] + [x & 1]
    return bytes(
        [sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(_b // 8)]
    )


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _decode_int(s):
    return sum(2 ** i * _bit(s, i) for i in range(0, _b))


def _decode_point(s):
    y = sum(2 ** i * _bit(s, i) for i in range(0, _b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1):
        x = _q - x
    P = [x, y]
    if not _is_on_curve(P):
        raise ValueError("decoded point is not on the edwards25519 curve")
    return P


def _is_on_curve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _clamp_scalar(h):
    """Derive the signing scalar from the hashed seed (the reference's
    clamp — RFC 8032 §5.1 pruning)."""
    return 2 ** (_b - 2) + sum(
        2 ** i * _bit(h, i) for i in range(3, _b - 2)
    )


def _hint(m):
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * _b))


def publickey(seed):
    """Derive the 32-byte ed25519 public key from a 32-byte seed."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    h = _H(bytes(seed))
    a = _clamp_scalar(h)
    A = _scalarmult(_B, a)
    return _encode_point(A)


def signature(message, seed, public_key):
    """Deterministic ed25519 signature of ``message`` (64 bytes).

    ``seed`` is the 32-byte private seed; ``public_key`` its derived 32-byte
    public key (passed in, per the RFC 8032 reference shape, so callers pin
    the exact key the signature will be checked against).
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be bytes, got {type(message).__name__}")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("ed25519 seed must be 32 bytes")
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    seed = bytes(seed)
    public_key = bytes(public_key)
    h = _H(seed)
    a = _clamp_scalar(h)
    r = _hint(bytes([h[i] for i in range(_b // 8, 2 * _b // 8)]) + bytes(message))
    R = _scalarmult(_B, r)
    S = (r + _hint(_encode_point(R) + public_key + bytes(message)) * a) % _l
    return _encode_point(R) + _encode_int(S)


def checkvalid(sig, message, public_key):
    """Verify ``sig`` over ``message`` against ``public_key``.

    Returns True only on a valid signature. Raises ValueError on
    structurally invalid input (bad lengths, off-curve points, a
    non-canonical ``S``) — callers MUST treat any exception as
    verification failure (fail-closed), never as validity.
    """
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != _b // 4:
        raise ValueError("ed25519 signature must be 64 bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError(f"message must be bytes, got {type(message).__name__}")
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    sig = bytes(sig)
    message = bytes(message)
    public_key = bytes(public_key)
    R = _decode_point(sig[: _b // 8])
    A = _decode_point(public_key)
    S = _decode_int(sig[_b // 8: _b // 4])
    # RFC 8032 §5.1.7: S must decode into [0, L); a signature whose S is
    # out of range is invalid. The reference omits this check, which makes
    # it malleable: S + L and S + 2L verify just as well as S. Rejecting
    # here keeps one valid signature per (key, message).
    if S >= _l:
        raise ValueError(
            "ed25519 signature scalar S is not canonical (S >= L)"
        )
    h = _hint(_encode_point(R) + public_key + message)
    return _scalarmult(_B, S) == _edwards_add(R, _scalarmult(A, h))
