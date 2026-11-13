"""L4 ed25519 attestation: key management, signing, intake authorization.

SPEC 1.2.6 (Round B): every deletion receipt envelope and every propagation
pack carries a deterministic ed25519 signature produced by the ISSUING
service root's per-root keypair. This module owns:

- **Key management**: one ed25519 keypair per service root. The private
  seed lives at ``<root>/.mbcp.key`` (mode 0600, JSON). The public key is
  embedded in every signed artifact next to a short ``key_id`` fingerprint;
  there is no passphrase (SPEC 1.2.6 ruling: 0600 suffices, a passphrase
  would break unattended delete/recover flows) and key rotation semantics
  are deferred (``key_id`` is the reserved rotation anchor).
- **Signing / verification**: the signature binds the canonical bytes of
  the WHOLE artifact envelope (``integrity`` + body) minus the
  ``attestation_sig`` field itself, so it covers the integrity block and
  the body together. ed25519 is deterministic: same envelope + same key
  -> same signature (pinned in tests).
- **Intake authorization** (SPEC 1.2.7): a root accepts propagation packs
  ONLY from sources listed in its accept-list
  ``<root>/.mbcp.authorized_sources.json`` (canonical JSON mapping
  ``key_id`` -> pubkey hex). Absent, empty, or malformed accept-list is
  fail-closed: EVERY incoming pack is rejected with the typed
  :class:`AuthorizationRejectedError` — there is no "accepted-unverified"
  behavioural tier.

Honest threat model (SPEC 1.2.6, verbatim discipline): the private key
lives inside the service root, so a FULL root compromise equals key
compromise — signatures defend against PARTIAL tampering (rewritten
receipt/pack bytes, forged third-party receipts/packs), not against a
total root breach. Third-party verification needs an out-of-band pubkey
anchor (a conformance registry record, or the ``attestation_pubkey`` /
``key_id`` pair exported with the artifact); the signature alone is not a
trust root.

Both dotfiles live at the service-root level, outside every scanner
namespace (``bundles/``, ``receipts/``, the explicit journal paths) —
the same exclusion discipline as ``.mbcp.lock``.
"""

import hashlib
import json
import os
import stat
from pathlib import Path

from . import _ed25519
from ._io import _atomic_write
from .canonical import canonical_bytes, canonical_sha256, json_loads_strict

KEY_FILE_NAME = ".mbcp.key"
AUTHORIZED_SOURCES_FILE_NAME = ".mbcp.authorized_sources.json"

# Round B v0: rotation semantics are deferred (SPEC 1.2.6); key_id is the
# reserved anchor. The id is a short fingerprint of the pubkey — 16 hex
# chars of SHA-256 — deterministic, unique per key except by deliberate
# second-preimage construction (64 bits of work-factor).
KEY_ID_HEX_LENGTH = 16
PUBKEY_HEX_LENGTH = 64
SIGNATURE_HEX_LENGTH = 128


class AttestationError(ValueError):
    """Base class for L4 attestation failures (signing layer)."""


class MissingAttestationError(AttestationError):
    """A signed artifact does not carry the required attestation fields.

    Names the missing field(s) — fail-closed, never a silent skip.
    """


class AttestationVerifyError(AttestationError):
    """An attestation signature does not verify.

    The envelope bytes were tampered with after signing, or the signature
    was produced by a DIFFERENT key than the embedded pubkey claims —
    either way the artifact is rejected, typed.
    """


class InvalidKeypointError(AttestationError):
    """A public key is not a valid ed25519 trust anchor (audit 2, W1).

    Raised when a pubkey decodes to the identity point, a small-order
    (cofactor-subgroup) point, a non-canonically-encoded point
    (``y >= q``), or a point off the curve. Such keys enable
    zero-private-key signature forgeries at the cofactorless verification
    equation (the identity pubkey plus ``(R=B, S=1)`` verifies with no
    secret material at all), so they are rejected typed at every
    trust-anchor layer: key load (:func:`load_keypair`), accept-list
    enrollment (:func:`authorize_source`), and embedded-pubkey
    verification (:func:`attestation_problems`).

    Scope note (Isaac's minimal-diff ruling): this hardening lives one
    layer ABOVE the vendored :mod:`mbcp._ed25519` core, which is left
    untouched — ``checkvalid`` still accepts small-order pubkeys when
    called directly; the L4 gates refuse to treat them as trust anchors.
    """


class KeyMaterialLostError(AttestationError):
    """Key loss detected: ``.mbcp.key`` is missing but the root already
    carries signed attestation history (audit 2, W2).

    ``ensure_keypair`` refuses to silently mint a new identity when the
    key file is gone but the root already holds receipt artifacts and/or
    a propagation journal — silent regeneration would switch the root
    identity mid-history: old receipts verify under the old embedded
    pubkey and new ones under a new key_id, and a third-party verifier
    anchored on the original pubkey silently loses the chain tail.
    Key loss is NOT first use. Recovery is explicit: restore the key
    file, or deliberately call :func:`rotate_keypair` (the escape hatch;
    rotation semantics remain deferred per SPEC 1.2.6).
    """


class AuthorizationRejectedError(AttestationError):
    """Propagation intake rejected by the authorized-source accept-list.

    SPEC 1.2.7 fail-closed: raised when the accept-list is absent, empty
    or malformed (every incoming pack rejected), when the pack's key_id
    is not listed (unknown source), and when the listed pubkey differs
    from the pack's embedded pubkey (key mismatch). Behaviour is binary —
    there is no "accepted-unverified" tier; observability of the verified
    status may only be recorded in intake receipts/records.
    """


class KeyPair:
    """An ed25519 keypair: 32-byte private seed + 32-byte public key."""

    __slots__ = ("seed", "pubkey")

    def __init__(self, seed, pubkey=None):
        seed = bytes(seed)
        if len(seed) != 32:
            raise ValueError("ed25519 seed must be 32 bytes")
        self.seed = seed
        self.pubkey = bytes(pubkey) if pubkey is not None else _ed25519.publickey(seed)
        if len(self.pubkey) != 32:
            raise ValueError("ed25519 public key must be 32 bytes")

    @property
    def key_id(self):
        """Short rotation anchor fingerprint (see module docstring)."""
        return key_id_for_pubkey(self.pubkey)

    @property
    def pubkey_hex(self):
        return self.pubkey.hex()


def key_id_for_pubkey(pubkey):
    """The ``key_id`` fingerprint for a raw 32-byte public key."""
    pubkey = bytes(pubkey)
    if len(pubkey) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    return hashlib.sha256(pubkey).hexdigest()[:KEY_ID_HEX_LENGTH]


def generate_keypair():
    """A fresh random ed25519 keypair (os.urandom seed)."""
    return KeyPair(os.urandom(32))


def validate_keypoint_pubkey(pubkey):
    """Reject pubkeys that are not valid ed25519 trust anchors (W1).

    ``pubkey`` is the raw 32-byte encoding. A valid anchor must decode to
    a prime-order curve point: this rejects the identity encoding
    (``0x01 || 0x00*31``), every small-order point (any ``P`` with
    ``8*P == identity`` — the cofactor subgroup), non-canonical
    encodings (``y >= q``), and off-curve encodings. Uses the vendored
    :mod:`mbcp._ed25519` decode/scalarmult primitives only — the
    vendored sign/verify paths are not modified. Returns the pubkey on
    success; raises :class:`InvalidKeypointError` (typed) otherwise.
    """
    pubkey = bytes(pubkey)
    if len(pubkey) != 32:
        raise InvalidKeypointError(
            f"ed25519 public key must be 32 bytes, got {len(pubkey)}"
        )
    # Canonical encoding: the low 255 little-endian bits are y and must
    # be < q (the vendored _decode_point masks the sign bit but does not
    # perform this check).
    y = int.from_bytes(pubkey, "little") & ((1 << 255) - 1)
    if y >= _ed25519._q:
        raise InvalidKeypointError(
            "non-canonical point encoding (y >= q)"
        )
    try:
        point = _ed25519._decode_point(pubkey)
    except ValueError as err:
        raise InvalidKeypointError(
            f"point is not on the edwards25519 curve: {err}"
        ) from err
    if _ed25519._scalarmult(point, 8) == [0, 1]:
        raise InvalidKeypointError(
            "small-order point (8*P == identity): identity/cofactor-"
            "subgroup pubkeys enable zero-private-key signature forgeries"
        )
    return pubkey


def keypair_from_seed_hex(seed_hex):
    """Rebuild a keypair from a hex-encoded 32-byte seed (fixtures/tests)."""
    return KeyPair(bytes.fromhex(seed_hex))


def save_keypair(root, keypair):
    """Persist ``keypair`` at ``<root>/.mbcp.key`` with mode 0600.

    Written atomically and fsynced (``_atomic_write``), then chmod 0600 —
    the private seed must never be group/other-readable (SPEC 1.2.6).
    """
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = root / KEY_FILE_NAME
    payload = {
        "algo": "ed25519",
        "seed_hex": keypair.seed.hex(),
        "pubkey_hex": keypair.pubkey.hex(),
        "key_id": keypair.key_id,
    }
    _atomic_write(path, canonical_bytes(payload))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def load_keypair(root):
    """Load the root keypair; return None when no key file exists.

    A present-but-malformed key file (unparseable JSON, wrong algo, bad
    lengths, or a pubkey that does not match the seed) raises the typed
    :class:`AttestationError` — a corrupted signing key must fail loud,
    never silently produce unverifiable artifacts.
    """
    path = Path(root) / KEY_FILE_NAME
    if not path.exists():
        return None
    try:
        data = json_loads_strict(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise AttestationError(f"corrupt signing key {path}: {err}") from err
    if not isinstance(data, dict) or data.get("algo") != "ed25519":
        raise AttestationError(f"corrupt signing key {path}: algo must be 'ed25519'")
    try:
        seed = bytes.fromhex(data["seed_hex"])
        pubkey = bytes.fromhex(data["pubkey_hex"])
    except (KeyError, TypeError, ValueError) as err:
        raise AttestationError(f"corrupt signing key {path}: {err}") from err
    # W1 hardening: a key file carrying an identity/small-order/non-
    # canonical pubkey is not a usable trust anchor — fail loud, typed.
    validate_keypoint_pubkey(pubkey)
    keypair = KeyPair(seed, pubkey)
    if _ed25519.publickey(seed) != pubkey:
        raise AttestationError(
            f"corrupt signing key {path}: pubkey does not match the seed"
        )
    if data.get("key_id") != keypair.key_id:
        raise AttestationError(
            f"corrupt signing key {path}: key_id does not match the pubkey"
        )
    return keypair


def _root_has_attestation_history(root):
    """True when the root already carries signed attestation history:
    any receipt artifact in ``receipts/`` and/or a non-empty
    ``propagation.jsonl`` journal (audit 2, W2).

    This is the state that distinguishes KEY LOSS from FIRST USE for
    :func:`ensure_keypair`: a genuinely empty root may mint a first-use
    keypair; a root with history must not silently switch identity.
    """
    root = Path(root)
    receipts_dir = root / "receipts"
    if receipts_dir.is_dir():
        try:
            if any(receipts_dir.iterdir()):
                return True
        except OSError:
            pass  # unreadable dir: the journal check below still decides
    journal = root / "propagation.jsonl"
    try:
        if journal.exists() and journal.stat().st_size > 0:
            return True
    except OSError:
        pass
    return False


def ensure_keypair(root):
    """Load the root keypair, creating it (mode 0600) on FIRST USE.

    Fail-closed on key loss (audit 2, W2; SPEC 1.2.6 hotfix block): when
    the key file is missing but the root already has attestation history
    (any receipt artifact and/or a non-empty propagation journal), this
    raises :class:`KeyMaterialLostError` naming the state — key loss is
    not first use, and silently minting a new identity would leave
    third-party verifiers anchored on the old pubkey silently missing
    the chain tail. Only a genuinely empty root mints. Recovery is
    explicit: restore the key file, or call :func:`rotate_keypair`.
    """
    keypair = load_keypair(root)
    if keypair is None:
        if _root_has_attestation_history(root):
            raise KeyMaterialLostError(
                f"key material lost at {Path(root) / KEY_FILE_NAME}: the "
                f"key file is missing but this root already carries "
                f"attestation history (receipt artifacts and/or a "
                f"propagation journal). Refusing to silently mint a new "
                f"identity (audit W2) — restore the key file, or "
                f"deliberately call rotate_keypair() as the explicit "
                f"'the key is lost' action (rotation semantics remain "
                f"deferred per SPEC 1.2.6)"
            )
        keypair = generate_keypair()
        save_keypair(root, keypair)
    return keypair


def rotate_keypair(root):
    """Explicitly replace the root keypair (audit 2, W2 escape hatch).

    Honest contract — read before calling:

    - This mints a NEW identity and PERMANENTLY discards the old key
      material. There is no re-signing, no supersession link, no
      revocation list: rotation SEMANTICS remain deferred (SPEC 1.2.6;
      ``key_id`` is the reserved anchor, to be defined before G2).
    - Old receipts still verify under their embedded pubkey
      (verification is self-anchored); new artifacts sign under the new
      key_id. A third-party verifier anchored on the old pubkey silently
      loses the tail — that is exactly the loss this API makes
      deliberate instead of silent.
    - This exists ONLY as the explicit "I know the key is lost" action
      that :func:`ensure_keypair` refuses to take implicitly. Callers
      must serialize with writers (hold the root lock) like any other
      root mutation.
    """
    keypair = generate_keypair()
    save_keypair(root, keypair)
    return keypair


def signing_bytes(envelope):
    """Canonical bytes that a signature binds: the whole envelope MINUS
    the ``attestation_sig`` field (SPEC 1.2.6: the sig binds everything
    else, integrity block and body together)."""
    return canonical_bytes(
        {key: value for key, value in envelope.items() if key != "attestation_sig"}
    )


def sign_envelope(envelope, keypair, *, body_field):
    """Return a copy of ``envelope`` with L4 attestation applied.

    Sets ``key_id`` + ``attestation_pubkey`` inside ``envelope[body_field]``
    and the deterministic ed25519 ``attestation_sig`` (hex128) at the
    envelope top level. The envelope's ``integrity.digest`` is recomputed
    over the FINAL body (with the key fields), then the signing input is
    :func:`signing_bytes` of the resulting envelope (everything except
    the sig itself) — so the signature binds the integrity block and the
    complete body together, in that order.
    """
    if not isinstance(envelope, dict) or body_field not in envelope:
        raise AttestationError(f"envelope must carry a {body_field!r} block")
    body = dict(envelope[body_field])
    body["key_id"] = keypair.key_id
    body["attestation_pubkey"] = keypair.pubkey_hex
    signed = dict(envelope)
    signed[body_field] = body
    integrity = signed.get("integrity")
    if isinstance(integrity, dict) and integrity.get("algo") == "sha256":
        # The key fields changed the body — the self-digest must cover the
        # FINAL body or the artifact would fail its own integrity check
        # (and attest bytes that are not what is stored).
        integrity = dict(integrity)
        integrity["digest"] = canonical_sha256(body)
        signed["integrity"] = integrity
    message = signing_bytes(signed)
    sig = _ed25519.signature(message, keypair.seed, keypair.pubkey)
    signed["attestation_sig"] = sig.hex()
    return signed


def attestation_problems(envelope, *, body_field):
    """Verify the L4 attestation of a parsed envelope.

    Returns a list of problem strings (empty = attestation verifies):
    missing fields are named; a key_id/pubkey fingerprint mismatch and a
    signature that does not verify over the embedded pubkey are both
    reported. Any problem is fail-closed for the caller.
    """
    problems = []
    body = envelope.get(body_field)
    if not isinstance(body, dict):
        return [f"envelope has no {body_field!r} block to attest"]
    sig_hex = envelope.get("attestation_sig")
    if not isinstance(sig_hex, str) or len(sig_hex) != SIGNATURE_HEX_LENGTH:
        problems.append(
            f"missing or malformed 'attestation_sig' field "
            f"(expected {SIGNATURE_HEX_LENGTH} lowercase hex chars)"
        )
        return problems  # nothing else can be checked without a sig
    pubkey_hex = body.get("attestation_pubkey")
    if not isinstance(pubkey_hex, str) or len(pubkey_hex) != PUBKEY_HEX_LENGTH:
        problems.append(
            f"missing or malformed 'attestation_pubkey' field in {body_field!r} "
            f"(expected {PUBKEY_HEX_LENGTH} lowercase hex chars)"
        )
        return problems
    key_id = body.get("key_id")
    if not isinstance(key_id, str) or len(key_id) != KEY_ID_HEX_LENGTH:
        problems.append(
            f"missing or malformed 'key_id' field in {body_field!r} "
            f"(expected {KEY_ID_HEX_LENGTH} lowercase hex chars)"
        )
        return problems
    try:
        pubkey = bytes.fromhex(pubkey_hex)
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        problems.append("attestation_sig / attestation_pubkey are not hex")
        return problems
    if key_id != key_id_for_pubkey(pubkey):
        problems.append(
            "key_id does not match the embedded attestation_pubkey "
            "(fingerprint mismatch)"
        )
    # W1 hardening: refuse identity/small-order/non-canonical pubkeys as
    # trust anchors BEFORE the cofactorless verification equation runs —
    # the vendored checkvalid would accept a zero-secret forgery
    # (identity pubkey + (R=B, S=1)) from such a key.
    try:
        validate_keypoint_pubkey(pubkey)
    except InvalidKeypointError as err:
        problems.append(
            f"attestation_pubkey is not a valid trust anchor: {err}"
        )
        return problems
    try:
        valid = _ed25519.checkvalid(sig, signing_bytes(envelope), pubkey)
    except (ValueError, TypeError) as err:
        problems.append(f"attestation signature is malformed: {err}")
        return problems
    if not valid:
        problems.append(
            "attestation signature does not verify against the embedded "
            "pubkey (envelope bytes tampered after signing, or signed by "
            "a different key)"
        )
    return problems


def authorized_sources_path(root):
    return Path(root) / AUTHORIZED_SOURCES_FILE_NAME


def load_authorized_sources(root):
    """The intake accept-list: ``{key_id: pubkey_hex}``.

    Returns None when the file is ABSENT (the caller maps that to
    fail-closed — SPEC 1.2.7: no accept-list means reject every pack).
    A MALFORMED file raises the typed :class:`AuthorizationRejectedError`
    (fail-closed, never an unhandled crash).
    """
    path = authorized_sources_path(root)
    if not path.exists():
        return None
    try:
        data = json_loads_strict(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise AuthorizationRejectedError(
            f"authorized-source accept-list {path} is malformed: {err}"
        ) from err
    if not isinstance(data, dict):
        raise AuthorizationRejectedError(
            f"authorized-source accept-list {path} must be a JSON object "
            f"mapping key_id -> pubkey hex"
        )
    result = {}
    for key_id, pubkey_hex in data.items():
        if (
            not isinstance(key_id, str)
            or len(key_id) != KEY_ID_HEX_LENGTH
            or not isinstance(pubkey_hex, str)
            or len(pubkey_hex) != PUBKEY_HEX_LENGTH
        ):
            raise AuthorizationRejectedError(
                f"authorized-source accept-list {path}: bad entry "
                f"{key_id!r}: key_id must be {KEY_ID_HEX_LENGTH} hex chars "
                f"and pubkey {PUBKEY_HEX_LENGTH} hex chars"
            )
        result[key_id] = pubkey_hex.lower()
    return result


def authorize_source(root, key_id, pubkey_hex):
    """Add (or replace) one authorized source in the accept-list.

    Root config operation (SPEC 1.2.7): multi-root deployments configure
    their accept-lists as a normal conformance requirement. The file is
    canonical JSON, written atomically; it lives outside bundles/journal/
    inventory scans (root-level dotfile).
    """
    if not isinstance(key_id, str) or len(key_id) != KEY_ID_HEX_LENGTH:
        raise ValueError(f"key_id must be {KEY_ID_HEX_LENGTH} hex chars")
    if not isinstance(pubkey_hex, str) or len(pubkey_hex) != PUBKEY_HEX_LENGTH:
        raise ValueError(f"pubkey must be {PUBKEY_HEX_LENGTH} hex chars")
    pubkey_hex = pubkey_hex.lower()
    # W1 hardening: never enroll an identity/small-order/non-canonical
    # pubkey in the accept-list — enrollment is the trust-anchor layer,
    # so a bogus key is refused here typed instead of at intake time.
    pubkey = bytes.fromhex(pubkey_hex)
    validate_keypoint_pubkey(pubkey)
    if key_id != key_id_for_pubkey(pubkey):
        raise ValueError("key_id does not match the given pubkey")
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    existing = load_authorized_sources(root) or {}
    existing[key_id] = pubkey_hex
    _atomic_write(authorized_sources_path(root), canonical_bytes(existing))
    return existing


def deauthorize_source(root, key_id):
    """Remove one authorized source (no-op when absent)."""
    existing = load_authorized_sources(root)
    if not existing or key_id not in existing:
        return existing or {}
    del existing[key_id]
    _atomic_write(authorized_sources_path(root), canonical_bytes(existing))
    return existing


def check_authorization(root, key_id, pubkey_hex):
    """Fail-closed intake authorization gate (SPEC 1.2.7).

    Returns None when the pack's (key_id, pubkey) pair is authorized;
    raises :class:`AuthorizationRejectedError` otherwise. An absent OR
    EMPTY accept-list rejects every pack; a listed key whose pubkey
    differs from the pack's embedded pubkey rejects (key mismatch).
    """
    sources = load_authorized_sources(root)
    if not sources:
        raise AuthorizationRejectedError(
            f"propagation intake is fail-closed (SPEC 1.2.7): no "
            f"authorized-source accept-list at "
            f"{authorized_sources_path(root)} — all incoming packs rejected"
        )
    if key_id not in sources:
        raise AuthorizationRejectedError(
            f"pack key_id {key_id!r} is not in the authorized-source "
            f"accept-list — unknown source, pack rejected"
        )
    if sources[key_id] != pubkey_hex.lower():
        raise AuthorizationRejectedError(
            f"pack key_id {key_id!r} is listed but its embedded pubkey "
            f"does not match the authorized pubkey — key mismatch, pack "
            f"rejected"
        )
    return None
