"""L1 deletion service — tombstone-first bundle deletion with receipts.

Level semantics (SPEC 1.2):

- **L1** (implemented here): the record id is gone from *every* bundle
  under the service root; each bundle keeps a monotonic tombstone so a
  stale copy of any bundle cannot resurrect it, and a receipt artifact
  records what happened. Record ids are global within a service root (the
  tombstone journal and :meth:`L1DeletionService.recover` already treat
  them that way), so ``delete`` removes all same-id copies under the root
  before it will issue a receipt. L1 says nothing about propagation
  outside this root.
- **L2–L4** (not implemented in M2): cross-bundle propagation, verified
  derived-artifact erasure, third-party-verifiable erasure receipt. An L1
  receipt says so explicitly in ``limitations`` and carries
  ``derived_artifacts_verified: false`` — an L1 receipt must never be
  presented as an erasure certificate.

Durability / ordering guarantee (tombstone-first):

1. the tombstone is appended to ``tombstones.jsonl`` and fsynced;
2. the removal evidence (what each copy's digest was) is written durably
   to ``evidence/<sha256(target-id)>.json``;
3. only then are the bundle manifests rewritten (atomically, ``os.replace``);
4. only then is the receipt written.

A crash between (1) and (2) or (2) and (3) leaves a *superset* of
deletions recorded; retrying :meth:`L1DeletionService.delete` finishes the
job from the durable journal + evidence, and
:meth:`L1DeletionService.recover` replays the journal onto every manifest,
so the record can never come back. A crash between (3) and (4) loses only
the receipt, never the deletion — the evidence survives, so the receipt
can be re-issued truthfully. ``delete`` re-reads every manifest before it
returns a receipt; if the target is still present anywhere it raises
:class:`DeletionIncompleteError` instead of claiming success.

On-disk layout of a service root::

    bundles/<bundle-id>.json     # MBCP manifests
    tombstones.jsonl             # append-only tombstone journal (fsynced)
    evidence/<sha256(id)>.json   # per-target removal evidence (digests)
    recovery.jsonl               # recovery log: digest copies removed by recover()
    receipts/<receipt-id>.json   # L1 erasure receipts
    .mbcp.lock                   # root advisory lock file (flock; never data)

Root advisory lock (audit §3, ADV-C2-3): :meth:`L1DeletionService.delete`,
:meth:`L1DeletionService.put_bundle`, :meth:`L1DeletionService.recover`,
propagation export (:func:`mbcp.propagation.export_propagation_pack`) and
propagation intake (:func:`mbcp.propagation.import_propagation_pack`) hold
an exclusive ``fcntl.flock`` on ``.mbcp.lock`` for their whole duration,
so two processes (or threads) sharing one service root cannot interleave
journal/manifest writes — in particular a put_bundle can no longer land
mid-delete (after the deletion-time inventory snapshot, before the
receipt) and an export can no longer read the bundles+journal torn
mid-delete. Acquisition is bounded by a ``lock_timeout`` parameter
(default :data:`DEFAULT_LOCK_TIMEOUT` seconds); a timeout raises the
typed :class:`LockTimeoutError` — never a silent retry. Same-process
nested acquisition is re-entrant (per-thread held count), so a locked
call may internally invoke another locked call; the OS releases the
flock automatically if a holder crashes.

Receipt vs recovery semantics (BACKLOG M2 #4, verify round 2 advisory 2):

``verify_receipt`` uses semantics **(i)**: a receipt verifies ``ok: True``
only if its ``removed_records`` account for EVERY removal of the target
known to the service root — both the delete()-time removals recorded in
``evidence/`` and any digest copies removed later by :meth:`recover`
(recorded in ``recovery.jsonl``). ``recover`` never rewrites or re-issues
receipts: a receipt that under-reports a recovered removal keeps failing
verification with a problem naming the unreported digest, instead of
laundering the removal back into ``ok: True``.

Receipt supersession (SPEC 1.2.2, RFC Q4/Q5) — the healing paths:

``delete()`` has exactly two re-issue triggers:

1. a retry that finds the target already gone, whose latest receipt fails
   verification SOLELY because known removals grew past what that receipt
   names (recovery log / evidence growth). Instead of raising, the retry
   writes a NEW immutable receipt whose ``supersedes`` is the old
   receipt's ``integrity.digest`` and whose ``removed_records`` cover
   every known removal.
2. a fresh-path delete (target present again) whose computed receipt id
   is ALREADY on disk: a copy of the target resurrected in the same
   tombstone generation replays the exact id preimage
   ``{bundle_id, target_id, deleted_at, tombstone_digest}``, so writing
   would ``_atomic_write`` OVER an existing immutable receipt — destroying
   its bytes and breaking every live ``supersedes`` link anchored to its
   digest (advisory A-1). The fresh receipt is routed through supersession
   instead: it supersedes the current CHAIN TAIL for that target (the
   colliding file may itself be a superseded mid-chain receipt), which
   folds ``supersedes`` into the id preimage so the new id is distinct,
   and every earlier file stays byte-intact.

Receipts are never modified in place — the superseded receipt stays on
disk, still verifying ``ok: False`` when checked alone (a superseded
receipt is a stale under-report; only the chain tail can verify ok). Chain
integrity (each ``supersedes`` link resolves to a real, digest-matching,
same-target receipt; no cycles) is a RUNTIME check in ``verify_receipt`` —
JSON Schema has no graph constraints. :class:`DeletionIncompleteError`
stays reserved for genuinely incomplete or inconsistent state (surviving
copies, broken chains, tampered receipts, unreadable journals, or a
receipt-file collision whose chain tail cannot be resolved).
"""

import fcntl
import hashlib
import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path

from . import _schema
from .bundle import make_tombstone, validate_bundle, validate_tombstone
from .canonical import (
    NonFiniteConstantError,
    canonical_bytes,
    canonical_sha256,
    json_loads_strict,
    normalize_id,
    utc_now,
)
from .tombstone import TombstonedIdRejectedError, _merge_tombstones

SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._-]+")

L1_LIMITATIONS = [
    "L1 only: the record id is removed from every bundle under this service "
    "root and tombstones are retained; no propagation beyond this root (L2) "
    "is performed or proven.",
    "Derived artifacts are recorded but NOT verified as erased (L3).",
    "This receipt is not a third-party-verifiable erasure certificate (L4).",
]


class DeletionError(ValueError):
    """Base class for deletion-service failures."""


class UnknownTargetError(DeletionError):
    """Raised when the target id exists nowhere in the bundle."""


class DeletionIncompleteError(DeletionError):
    """Raised when a deletion cannot be truthfully receipted.

    ``delete()`` raises this instead of returning a receipt whenever the
    target is still present in a bundle, or when service state is
    inconsistent (a receipt exists that fails verification for reasons
    OTHER than accounted growth — see SPEC 1.2.2 supersession, which
    heals pure under-reporting by re-issuing, or the target vanished
    without any durable evidence of what was removed).
    """


class ReceiptValidationError(DeletionError):
    """Raised when a receipt artifact is malformed or tampered with."""


class BundleIdCollisionError(DeletionError):
    """Raised when a bundle file name is already used by a DIFFERENT id.

    Adversarial audit §4: ``_safe_id()`` used to let two distinct bundle
    ids (e.g. ``team/a`` and ``team_a``, or any two non-ASCII names) share
    one file, silently dropping one bundle's data with no tombstone, no
    evidence and no receipt. Grammar-valid ids (see schemas/manifest.v0)
    are injective under ``_safe_id``; this guard refuses to overwrite a
    pre-existing file whose stored manifest id differs — loud, not silent.
    """


class LockTimeoutError(DeletionError):
    """Raised when the root advisory lock cannot be acquired in time.

    Audit §3: lock acquisition is bounded (``lock_timeout``, default
    :data:`DEFAULT_LOCK_TIMEOUT` seconds). A caller that cannot get the
    root lock within the bound gets this typed error — never a silent
    retry-forever and never an unbounded block.
    """


LOCK_FILE_NAME = ".mbcp.lock"
DEFAULT_LOCK_TIMEOUT = 10.0


def _norm_id(value):
    """NFC + ASCII case fold for id COMPARISON; pass non-strings through.

    Same defensive pattern as ``tombstone._norm``: hostile on-disk
    artifacts (receipts, recovery log lines) can carry a non-string id,
    and comparison must degrade to the pre-tightening behavior — never
    match, never crash untyped. All id-vs-id comparisons in this module
    route through here (SPEC 1.5 as amended 2026-11-10: storage stays
    verbatim, comparison is NFC + ASCII case-insensitive).
    """
    return normalize_id(value) if isinstance(value, str) else value

# In-process lock table: canonical root path -> {"owner": thread ident or
# None, "fh": open lock-file handle or None, "cond": Condition}.
# fcntl.flock locks are per open-file-description: separate open() fds (even
# within one process) DO exclude each other, while dup'd fds share the lock.
# flock alone therefore cannot express this design's requirements — the
# process-level owner + condition variable exists for RE-ENTRANCY (a
# same-thread nested locked call on a fresh fd would otherwise self-block →
# LockTimeoutError) and cross-thread fairness, not because flock fails to
# exclude. At most one thread per root owns the flock; the rest wait on the
# condition variable.
_ROOT_LOCK_TABLE = {}
_ROOT_LOCK_TABLE_GUARD = threading.Lock()
_ROOT_LOCK_TLS = threading.local()


def _tls_held():
    held = getattr(_ROOT_LOCK_TLS, "held", None)
    if held is None:
        held = {}
        _ROOT_LOCK_TLS.held = held
    return held


class _RootLock:
    """Re-entrant bounded root advisory lock (context manager).

    First acquisition by any thread of this process for a given root
    opens ``<root>/.mbcp.lock`` and takes ``flock(LOCK_EX)`` with a
    bounded spin (``lock_timeout``); a nested acquisition by the SAME
    thread just bumps a per-thread held count (delete()/recover()/
    propagation intake may nest through the service). Another thread —
    here or in another process — waits; past the deadline it gets
    :class:`LockTimeoutError`. The lock file lives at the service-root
    dotfile, outside every scanner namespace (``bundles/``,
    ``receipts/``, the journals are explicit paths).
    """

    def __init__(self, root, timeout):
        self._key = str(Path(root).resolve())
        self._timeout = float(timeout)
        self._entry = None

    def __enter__(self):
        held = _tls_held()
        if held.get(self._key, 0) > 0:
            # Same thread re-entering an already-held root lock.
            held[self._key] += 1
            return self
        deadline = time.monotonic() + self._timeout
        with _ROOT_LOCK_TABLE_GUARD:
            entry = _ROOT_LOCK_TABLE.get(self._key)
            if entry is None:
                entry = {"owner": None, "fh": None, "cond": None}
                _ROOT_LOCK_TABLE[self._key] = entry
            if entry["cond"] is None:
                entry["cond"] = threading.Condition(_ROOT_LOCK_TABLE_GUARD)
        while True:
            with entry["cond"]:
                if entry["owner"] is None:
                    if entry["fh"] is None:
                        lock_path = Path(self._key) / LOCK_FILE_NAME
                        lock_path.parent.mkdir(parents=True, exist_ok=True)
                        entry["fh"] = open(lock_path, "a+b")
                    try:
                        fcntl.flock(entry["fh"].fileno(),
                                    fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        pass  # another PROCESS holds it; wait below
                    else:
                        entry["owner"] = threading.get_ident()
                        held[self._key] = 1
                        return self
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LockTimeoutError(
                        f"could not acquire service-root lock {self._key}/"
                        f"{LOCK_FILE_NAME} within {self._timeout:g}s "
                        "(another writer holds the root; retry or raise "
                        "the lock_timeout)"
                    )
                entry["cond"].wait(timeout=min(0.05, remaining))

    def __exit__(self, exc_type, exc, tb):
        held = _tls_held()
        remaining = held[self._key] - 1
        if remaining > 0:
            held[self._key] = remaining
            return False
        del held[self._key]
        with _ROOT_LOCK_TABLE_GUARD:
            entry = _ROOT_LOCK_TABLE[self._key]
            fcntl.flock(entry["fh"].fileno(), fcntl.LOCK_UN)
            entry["owner"] = None
            entry["cond"].notify()
        return False


_RECEIPT_SCHEMA = None


def _receipt_schema():
    global _RECEIPT_SCHEMA
    if _RECEIPT_SCHEMA is None:
        _RECEIPT_SCHEMA = _schema.load_schema("deletion-receipt.v0")
    return _RECEIPT_SCHEMA


def _atomic_write(path, data):
    """Write ``data`` bytes to ``path`` atomically and durably."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


def _fsync_dir(directory):
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _safe_id(value):
    """Map a bundle id to an on-disk file stem, INJECTIVELY (ADV-C2-3/A-4).

    The old folding (``SAFE_ID_RE.sub("_", ...).strip("_")``) was
    non-injective: ``"abc"`` and ``"abc_"`` — both grammar-valid — folded
    to the same stem, so two distinct ids could share one file and one
    bundle's data was silently dropped (audit §4 probe surface).

    Scheme: ids the folding leaves unchanged pass through verbatim
    (readable, stable names for the common case). An id the folding would
    rewrite keeps its readable folded form PLUS a deterministic
    disambiguator — the first 12 hex of its canonical SHA-256 — so:

    - collisions are typed-guarded, injectivity not claimed: distinct ids
      map to the same name only by deliberate second-preimage construction
      (the mapped name of a rewritten id is itself grammar-valid and
      folding-unchanged, e.g. ``abc_`` vs ``abc--<sha12(abc_)>`` — a real,
      live-verified edge). The safety property is the deterministic pure
      mapping PLUS the typed ``BundleIdCollisionError`` guard that refuses
      a second put onto a held filename, whichever id arrives first;
    - identical ids always map to identical names (pure function of the
      id — determinism preserved);
    - unchanged ids keep their exact legacy filenames.

    The bundle-id grammar (audit §4) restricts ingest to ids the folding
    does not rewrite, so this path is defensive for out-of-band/legacy
    files; the :class:`BundleIdCollisionError` guard in ``put_bundle``
    refuses — typed, never silently — whenever a mapped filename is
    already held by a DIFFERENT id.
    """
    folded = SAFE_ID_RE.sub("_", value).strip("_") or "bundle"
    if folded == value:
        return folded
    return f"{folded}--{canonical_sha256(value)[:12]}"


def inventory_digest(bundle_ids):
    """Canonical SHA-256 over the SORTED bundle-id list (audit §13).

    Order-independent by construction (the input is sorted here): the
    digest binds the SET of bundles that constituted the store, so a
    laundered/resurrected sibling bundle changes the digest even though
    no receipt field naming records would.
    """
    return canonical_sha256(sorted(bundle_ids))


def _validate_receipt(receipt):
    try:
        _schema.validate(receipt, _receipt_schema())
    except _schema.ValidationError as err:
        raise ReceiptValidationError(f"invalid receipt: {err}") from err
    return receipt


def _is_growth_underreport(problems):
    """True when every verification problem names ACCOUNTED GROWTH (SPEC
    1.2.2): the receipt under-reports removals durably recorded in the
    deletion evidence or the recovery log. Any other problem (tampering,
    journal mismatch, broken/circular chain, surviving copies) means
    genuinely inconsistent state and stays fail-closed.
    """
    if not problems:
        return False
    return all(
        problem == "removed_records do not match recorded deletion evidence"
        or problem.startswith("recovery removed digest ")
        for problem in problems
    )


def build_receipt(
    bundle_id,
    tombstone,
    removed_records,
    *,
    issued_at=None,
    supersedes=None,
    inventory=None,
):
    """Build a schema-valid L1 receipt dict (with self-digest).

    ``removed_records`` is a list of record dicts that were removed in this
    deletion; only their id + integrity digest are retained in the receipt.

    ``inventory`` (audit §13) is the list of bundle ids that constituted
    the store root at deletion time; it is recorded (sorted, with a
    canonical digest over the sorted list) in the receipt's ``inventory``
    block so the receipt is bound to the exact store SET, not just to the
    removed records. Service-issued receipts always pass the real
    pre-deletion store set; a bare ``build_receipt`` call without a store
    context defaults to the empty set (schema-valid, and
    ``verify_receipt(check_inventory=True)`` then reports divergence
    against any non-empty live store).

    ``supersedes`` (SPEC 1.2.2) is the ``integrity.digest`` of the receipt
    this receipt supersedes — a re-issued receipt is a FRESH immutable
    artifact; the superseded receipt file is never modified. The link
    value feeds the receipt id preimage so a re-issue never collides with
    the receipt it replaces on disk.

    The id preimage also binds ``tombstone_digest`` (audit §14): two
    receipts for the same target issued in the same second with different
    tombstone generations (e.g. ``derived_artifacts`` grew) must not
    collide on one file.
    """
    issued_at = issued_at or utc_now()
    target_id = tombstone["target_id"]
    tombstone_digest = canonical_sha256(tombstone)
    id_preimage = {
        "bundle_id": bundle_id,
        "target_id": target_id,
        "deleted_at": tombstone["deleted_at"],
        "tombstone_digest": tombstone_digest,
    }
    if supersedes is not None:
        id_preimage["supersedes"] = supersedes
    receipt_id = "rcpt-" + hashlib.sha256(
        canonical_bytes(id_preimage)
    ).hexdigest()[:16]
    bundle_set = sorted(inventory or [])
    body = {
        "id": receipt_id,
        "spec_version": "0.1",
        "level": "L1",
        "issued_at": issued_at,
        "bundle_id": bundle_id,
        "target_id": target_id,
        "reason": tombstone["reason"],
        "tombstone": tombstone,
        "tombstone_digest": tombstone_digest,
        "removed_records": [
            {"id": record["id"], "digest": record["integrity"]["digest"]}
            for record in removed_records
        ],
        "inventory": {
            "bundle_set": bundle_set,
            "inventory_digest": inventory_digest(bundle_set),
        },
        "derived_artifacts": list(tombstone.get("derived_artifacts", [])),
        # L1 cannot prove L3: recorded, not verified. Never flip this in L1.
        "derived_artifacts_verified": False,
        "propagation": {"propagated_to": []},
        "limitations": list(L1_LIMITATIONS),
    }
    if supersedes is not None:
        body["supersedes"] = supersedes
    receipt = {
        "receipt": body,
        "integrity": {"algo": "sha256", "digest": canonical_sha256(body)},
    }
    return _validate_receipt(receipt)


class L1DeletionService:
    """Bundle-local deletion with tombstones + receipts (SPEC 1.2 L1)."""

    def __init__(self, root, *, clock=utc_now):
        self.root = Path(root)
        self.bundles_dir = self.root / "bundles"
        self.journal_path = self.root / "tombstones.jsonl"
        self.evidence_dir = self.root / "evidence"
        self.recovery_path = self.root / "recovery.jsonl"
        self.receipts_dir = self.root / "receipts"
        self._clock = clock
        # A-2 visibility: number of genuinely-unreadable bundle files
        # recover() skipped in its MOST RECENT run (0 before the first
        # run and after any run with no skips). Never silent.
        self.last_recovery_skipped_unreadable = 0

    def _root_lock(self, timeout=DEFAULT_LOCK_TIMEOUT):
        """Bounded re-entrant advisory lock on this service root (audit §3)."""
        return _RootLock(self.root, timeout)

    def bundle_inventory(self):
        """Sorted bundle-id list of every manifest in the store (live state).

        The input to :func:`inventory_digest`; fail-closed like every
        other store scan (a corrupt manifest raises the typed
        :class:`DeletionError`, never a silent partial inventory — a
        partial set would launder a divergence).
        """
        return sorted({bid for bid, _p, _m in self._bundle_manifests()})

    # -- bundles ----------------------------------------------------------
    def put_bundle(self, manifest, *, lock_timeout=DEFAULT_LOCK_TIMEOUT):
        """Validate + atomically persist a manifest; returns its path.

        The whole read-check-write runs under the root advisory lock
        (audit §3, ADV-C2-3): delete() holds the lock for its full
        duration, so a put_bundle racing a delete WAITS instead of
        landing mid-delete — a bundle can no longer appear after the
        deletion-time inventory snapshot but before the receipt is
        written (the born-inventory-divergent receipt hole), and the
        tombstone-journal read below cannot be torn by a concurrent
        delete's journal append. ``lock_timeout`` bounds the wait; a
        timeout raises the typed :class:`LockTimeoutError`.

        Write boundary (SPEC 1.2, audit §6): any record copy whose id is
        already tombstoned in the journal is rejected with the typed
        :class:`TombstonedIdRejectedError` — id-level, regardless of
        digest. The deletion service's own flows never re-put a
        tombstoned id (delete() and recover() rewrite manifests
        directly), so this gate only bites stale producers.

        Audit §4 / §11 gate: hostile-but-parseable manifests (lone
        surrogates, NaN/Infinity, bundle ids outside the grammar) are
        rejected HERE at ingest, loudly and typed — a poison manifest can
        only enter ``bundles/`` by bypassing this API (another producer
        writing files directly), and such legacy files fail typed,
        naming the file, whenever delete()/recover()/get_bundle() touch
        them. Audit §4 collision guard: a pre-existing file for this
        ``_safe_id`` belonging to a DIFFERENT bundle id is never
        overwritten silently.
        """
        with self._root_lock(lock_timeout):
            return self._put_bundle_locked(manifest)

    def _put_bundle_locked(self, manifest):
        """Locked body of :meth:`put_bundle` (runs under the root lock)."""
        validate_bundle(manifest)
        # Write boundary (SPEC 1.2, v0.1 audit §6 tightening, Isaac ruling
        # 2026-11-08): the resurrection backdoor is closed at INGEST, not
        # only at load time. The tombstone kills the whole id, so ANY copy
        # of a journal-tombstoned id is rejected — id-level, regardless of
        # the copy's integrity digest — with the typed error naming the
        # id. Resurrection can then only reach the store out-of-band (a
        # producer writing bundles/ directly), which is exactly the legacy
        # threat model delete()/recover() already heal. Both sides of the
        # comparison are NFC + ASCII case-normalized (SPEC 1.5 as amended
        # 2026-11-10, audit §12) — a case variant of a tombstoned id is
        # the same id.
        tombstoned_ids = {
            normalize_id(t["target_id"]) for t in self.all_tombstones()
        }
        for record in manifest["records"]:
            if normalize_id(record["id"]) in tombstoned_ids:
                raise TombstonedIdRejectedError(
                    f"record id {record['id']!r} is tombstoned in the "
                    "journal; refusing to ingest a copy of a deleted id "
                    "(SPEC 1.2 write boundary, audit §6)"
                )
        bundle_id = manifest["bundle"]["id"]
        path = self.bundles_dir / f"{_safe_id(bundle_id)}.json"
        if path.exists():
            try:
                existing = json_loads_strict(path.read_text(encoding="utf-8"))
                existing_id = existing["bundle"]["id"]
            except (OSError, KeyError, TypeError, ValueError) as err:
                raise DeletionError(
                    f"existing bundle file {path} is unreadable: {err}"
                ) from err
            if existing_id != bundle_id:
                raise BundleIdCollisionError(
                    f"bundle file {path} already holds bundle id "
                    f"{existing_id!r}; refusing to overwrite it with "
                    f"{bundle_id!r} (remove or rename the file deliberately)"
                )
        _atomic_write(path, canonical_bytes(manifest))
        return path

    def bundle_path(self, bundle_id):
        return self.bundles_dir / f"{_safe_id(bundle_id)}.json"

    def get_bundle(self, bundle_id):
        path = self.bundle_path(bundle_id)
        if not path.exists():
            raise DeletionError(f"unknown bundle {bundle_id!r} ({path})")
        try:
            manifest = json_loads_strict(path.read_text(encoding="utf-8"))
        except ValueError as err:
            raise DeletionError(f"corrupt bundle manifest {path}: {err}") from err
        try:
            validate_bundle(manifest)
        except ValueError as err:
            raise DeletionError(f"invalid bundle manifest {path}: {err}") from err
        if manifest["bundle"]["id"] != bundle_id:
            raise DeletionError(
                f"bundle manifest {path} declares id "
                f"{manifest['bundle']['id']!r}, not the requested {bundle_id!r}"
            )
        return manifest

    def _bundle_manifests(self):
        """Every bundle under this service root: ``[(bundle_id, path, manifest)]``.

        Fail-closed (audit §11): an unreadable or invalid manifest raises
        the typed :class:`DeletionError` naming the offending file — never
        a bare UnicodeEncodeError / ValueError from inside the scan, and
        never a silent skip (a skipped manifest could hide a live copy of
        a deletion target). Deletion scan/validate runs BEFORE any
        journal append, so this failure leaves the root untouched.
        """
        if not self.bundles_dir.exists():
            return []
        bundles = []
        for path in sorted(self.bundles_dir.glob("*.json")):
            try:
                manifest = json_loads_strict(path.read_text(encoding="utf-8"))
            except OSError as err:
                # Fail-closed and typed (audit §11): a genuinely unreadable
                # entry (directory-shaped, permissions, vanished mid-scan)
                # is loud here — delete()/verify must never treat a hidden
                # manifest as absent (it could hold a live copy of a
                # deletion target). recover() is the tolerant path.
                raise DeletionError(
                    f"unreadable bundle manifest {path}: {err}"
                ) from err
            except ValueError as err:
                raise DeletionError(
                    f"corrupt bundle manifest {path}: {err}"
                ) from err
            try:
                validate_bundle(manifest)
            except ValueError as err:
                raise DeletionError(
                    f"invalid bundle manifest {path}: {err}"
                ) from err
            bundles.append((manifest["bundle"]["id"], path, manifest))
        return bundles

    # -- tombstone journal ------------------------------------------------
    def journal_tombstones(self):
        """All tombstones in the append-only journal, in write order.

        Decode hygiene (M3 round-2 verify advisory 2, mirrored from
        ``read_propagation_journal``): the journal is read as bytes and
        each line is decoded explicitly — invalid UTF-8 raises the typed
        :class:`DeletionError` with path:lineno, never a bare
        UnicodeDecodeError.
        """
        if not self.journal_path.exists():
            return []
        tombstones = []
        raw = self.journal_path.read_bytes()
        for lineno, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            try:
                text = line.decode("utf-8")
            except UnicodeDecodeError as err:
                raise DeletionError(
                    f"corrupt tombstone journal {self.journal_path}:{lineno}: "
                    f"invalid UTF-8: {err}"
                ) from err
            try:
                tomb = json_loads_strict(text)
            except (json.JSONDecodeError, NonFiniteConstantError) as err:
                raise DeletionError(
                    f"corrupt tombstone journal {self.journal_path}:{lineno}: {err}"
                ) from err
            tombstones.append(validate_tombstone(tomb))
        return tombstones

    def _append_journal(self, tombstone):
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        line = canonical_bytes(tombstone) + b"\n"
        with open(self.journal_path, "ab") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(self.journal_path.parent)

    def all_tombstones(self):
        """Journal tombstones, deduped by target (latest wins, artifacts union).

        Importers must feed these back into every import so a stale export
        cannot resurrect deleted rows.
        """
        return _merge_tombstones(self.journal_tombstones())

    # -- removal evidence --------------------------------------------------
    def evidence_path(self, target_id):
        """Per-target evidence file path (target ids may contain any chars).

        Keyed by the NFC + case-normalized id (SPEC 1.5, amended
        2026-11-10): delete("Rec-1") and delete("rec-1") address the SAME
        evidence — one logical id, one removal ledger — while the ledger
        content keeps the first-seen verbatim id.
        """
        digest = hashlib.sha256(_norm_id(target_id).encode("utf-8")).hexdigest()
        return self.evidence_dir / f"{digest}.json"

    def _read_evidence(self, target_id):
        path = self.evidence_path(target_id)
        if not path.exists():
            return {"target_id": target_id, "removals": []}
        try:
            data = json_loads_strict(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, NonFiniteConstantError) as err:
            raise DeletionError(f"corrupt removal evidence {path}: {err}") from err
        if not isinstance(data, dict) or _norm_id(data.get("target_id")) != _norm_id(target_id):
            raise DeletionError(
                f"removal evidence {path} does not belong to target {target_id!r}"
            )
        removals = data.get("removals")
        if not isinstance(removals, list):
            raise DeletionError(f"corrupt removal evidence {path}: no removals list")
        required = {"bundle_id", "record_id", "digest", "tombstone_digest"}
        for entry in removals:
            if not isinstance(entry, dict) or not required <= set(entry):
                raise DeletionError(f"corrupt removal evidence {path}: bad entry")
        return data

    def _record_evidence(self, target_id, tombstone_digest, copies):
        """Durably record the (bundle, record, digest) copies being removed.

        Written BEFORE any manifest rewrite, so a crash between the manifest
        rewrite and the receipt still leaves enough evidence to re-issue a
        truthful receipt. Idempotent: re-running after a crash merges into
        the existing entry instead of duplicating it.
        """
        data = self._read_evidence(target_id)
        seen = {
            (e["bundle_id"], e["record_id"], e["digest"], e["tombstone_digest"])
            for e in data["removals"]
        }
        for bundle_id, record in copies:
            entry = {
                "bundle_id": bundle_id,
                "record_id": record["id"],
                "digest": record["integrity"]["digest"],
                "tombstone_digest": tombstone_digest,
            }
            key = (
                entry["bundle_id"],
                entry["record_id"],
                entry["digest"],
                entry["tombstone_digest"],
            )
            if key not in seen:
                data["removals"].append(entry)
                seen.add(key)
        data["removals"].sort(
            key=lambda e: (e["bundle_id"], e["record_id"], e["digest"])
        )
        _atomic_write(self.evidence_path(target_id), canonical_bytes(data))
        return data

    def _known_removals(self, target_id):
        """Every removal of ``target_id`` known to this service root.

        TARGET-WIDE union (audit HIGH#1 fix): the delete-time removal
        evidence across ALL tombstone generations PLUS every recovery-log
        entry for the target. Accounting binds the TARGET, never one
        tombstone generation — tombstone digests proliferate (derived
        artifact growth, L2 imports, concurrent deletes) and scoping
        evidence to one generation let an ``ok: True`` receipt omit real,
        evidence-documented removals. A receipt must name this whole set
        or verify ``ok: False``.
        """
        pairs = {
            (entry["record_id"], entry["digest"])
            for entry in self._read_evidence(target_id)["removals"]
        }
        pairs |= {
            (entry["record_id"], entry["digest"])
            for entry in self.recovery_removals(target_id)
        }
        return [
            {"id": record_id, "integrity": {"digest": digest}}
            for record_id, digest in sorted(pairs)
        ]

    # -- recovery log -------------------------------------------------------
    def _record_recovery(self, bundle_id, record):
        """Append a durable recovery log line for one removed record.

        Each line carries the target id, the digest of the copy recover()
        removed, the bundle it was removed from and ``recovered_at``, so the
        removal is retrievable and attributable to recovery — and
        distinguishable from delete()-time removals in ``evidence/``.
        Written BEFORE the manifest rewrite (journal-first): a crash can
        only leave a duplicate or an over-reported recovery, never a
        launched removal. A re-run after a crash may append a duplicate
        line; readers tolerate and dedupe.
        """
        entry = {
            "target_id": record["id"],
            "record_id": record["id"],
            "digest": record["integrity"]["digest"],
            "bundle_id": bundle_id,
            "recovered_at": self._clock(),
        }
        self.recovery_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.recovery_path, "ab") as fh:
            fh.write(canonical_bytes(entry) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(self.recovery_path.parent)

    def _read_recovery(self):
        """All recovery log entries, in write order.

        A service root created before the recovery log existed has no
        ``recovery.jsonl``; that is normal and yields an empty list — the
        service must not crash on pre-existing roots.
        """
        if not self.recovery_path.exists():
            return []
        entries = []
        for lineno, line in enumerate(
            self.recovery_path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                entry = json_loads_strict(line)
            except (json.JSONDecodeError, NonFiniteConstantError) as err:
                raise DeletionError(
                    f"corrupt recovery log {self.recovery_path}:{lineno}: {err}"
                ) from err
            required = {"target_id", "record_id", "digest", "bundle_id", "recovered_at"}
            if not isinstance(entry, dict) or not required <= set(entry):
                raise DeletionError(
                    f"corrupt recovery log {self.recovery_path}:{lineno}: bad entry"
                )
            entries.append(entry)
        return entries

    def recovery_removals(self, target_id=None):
        """Recovery log entries (deduped by bundle/record/digest), optionally
        scoped to one target id."""
        seen = set()
        entries = []
        wanted = _norm_id(target_id) if target_id is not None else None
        for entry in self._read_recovery():
            key = (entry["bundle_id"], entry["record_id"], entry["digest"])
            if key in seen:
                continue
            seen.add(key)
            if wanted is None or _norm_id(entry["target_id"]) == wanted:
                entries.append(entry)
        return entries

    # -- deletion ---------------------------------------------------------
    def delete(
        self,
        bundle_id,
        target_id,
        reason,
        *,
        derived_artifacts=(),
        now=None,
        lock_timeout=DEFAULT_LOCK_TIMEOUT,
    ):
        """Delete ``target_id`` from the service root (L1), returning the receipt.

        Record ids are global within a service root: the tombstone journal
        and :meth:`recover` already apply per target across every manifest,
        so ``delete`` removes *every* same-id copy under ``self.root``
        before it will issue a receipt. The receipt is written only after
        every manifest has been re-read and the target is confirmed absent
        everywhere; otherwise :class:`DeletionIncompleteError` is raised.

        Idempotent: when the target is already gone and a receipt exists
        that still verifies against current state, that receipt is returned
        without writing anything new. If the existing receipt fails
        verification SOLELY because known removals grew past its
        accounting (recovery-log / evidence growth), a fresh receipt is
        re-issued instead, superseding the old one (SPEC 1.2.2) — repeated
        retries without new removals then return that chain tail unchanged.
        A fresh-path delete that computes a receipt id already on disk
        (same-target, same-generation resurrection, advisory A-1) is
        routed through the same supersession machinery rather than
        overwriting the immutable receipt file. Failures from any other
        cause still raise :class:`DeletionIncompleteError`.

        ``derived_artifacts`` from the caller are unioned into the journal
        tombstone; ``reason`` is only used when no tombstone for this target
        exists yet (recovery finishes the original request). When the target
        is already gone everywhere, the existing receipt is returned as-is:
        new ``derived_artifacts`` are not recorded for an already-finished
        deletion (issue a new delete after resuscitation if they matter).

        The whole operation runs under the root advisory lock (audit §3):
        racing writers on one service root cannot interleave
        journal/manifest writes. ``lock_timeout`` bounds the wait for the
        lock; a timeout raises :class:`LockTimeoutError` (typed, never a
        silent retry). The receipt records the pre-deletion store
        inventory (audit §13) — the sorted set of bundle ids present in
        the root at delete time — so the receipt binds to the exact store
        SET, not only to the removed records.
        """
        with self._root_lock(lock_timeout):
            return self._delete_locked(
                bundle_id,
                target_id,
                reason,
                derived_artifacts=derived_artifacts,
                now=now,
            )

    def _delete_locked(
        self,
        bundle_id,
        target_id,
        reason,
        *,
        derived_artifacts=(),
        now=None,
    ):
        """Locked body of :meth:`delete` (runs under the root advisory lock)."""
        # Both ids flow into canonical_bytes (receipt id preimage,
        # evidence path digest); a lone surrogate would crash untyped
        # (audit §11) — reject loudly at the boundary.
        for label, value in (("bundle id", bundle_id), ("target id", target_id)):
            if not isinstance(value, str):
                raise DeletionError(f"{label} must be a string, got {value!r}")
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError as err:
                raise DeletionError(
                    f"{label} {value!r} is not encodable UTF-8: {err}"
                ) from err

        self.get_bundle(bundle_id)  # unknown bundle is an error, not a no-op

        # The whole-root scan/validate runs BEFORE any journal append:
        # every manifest is validated up front, so a hostile or corrupt
        # file fails here with a typed, file-naming error and the durable
        # state is untouched (audit §11: no mid-flight UnicodeEncodeError
        # after tombstone+evidence are durable).
        bundles = self._bundle_manifests()
        # Pre-deletion store inventory (audit §13): the sorted bundle-id
        # set this receipt will be bound to. The scan above ran BEFORE any
        # rewrite, so this is exactly the deletion-time store SET.
        store_inventory = sorted({bid for bid, _p, _m in bundles})
        # SPEC 1.5 (amended 2026-11-10): the target is matched NFC + ASCII
        # case-insensitively — delete("Rec-1") removes a stored "rec-1"
        # copy. The tombstone/receipt keep the CALLER's verbatim id.
        target_key = _norm_id(target_id)
        present = [
            (bid, record)
            for bid, _path, manifest in bundles
            for record in manifest.get("records", [])
            if _norm_id(record["id"]) == target_key
        ]
        journal_entries = [
            t for t in self.journal_tombstones()
            if _norm_id(t["target_id"]) == target_key
        ]

        if not present:
            return self._delete_with_nothing_present(
                bundle_id, target_id, journal_entries, now=now,
                inventory=store_inventory,
            )

        # 1. durable tombstone FIRST — a crash below can only over-delete.
        if journal_entries:
            tombstone = _merge_tombstones(journal_entries)[0]
            artifacts = sorted(
                set(tombstone.get("derived_artifacts", [])) | set(derived_artifacts)
            )
            if artifacts != list(tombstone.get("derived_artifacts", [])):
                tombstone = make_tombstone(
                    target_id,
                    tombstone["reason"],
                    deleted_at=tombstone["deleted_at"],
                    derived_artifacts=artifacts,
                )
        else:
            tombstone = make_tombstone(
                target_id,
                reason,
                deleted_at=now or self._clock(),
                derived_artifacts=derived_artifacts,
            )
        # Audit HIGH#1 (Repro B): the tombstone we embed in the evidence
        # and the receipt MUST be durable in the journal. A MERGED
        # tombstone (union of several generations — e.g. after an L2
        # import brought a second generation) can equal NO journal line;
        # an artifacts-diff condition misses exactly that case. Append
        # unconditionally when no journal line equals it.
        if not any(t == tombstone for t in journal_entries):
            self._append_journal(tombstone)

        # 2. durable evidence of WHAT is removed (the digests), so a retry
        #    after a crash can still issue a receipt that binds to them.
        tombstone_digest = canonical_sha256(tombstone)
        evidence = self._record_evidence(target_id, tombstone_digest, present)

        # 3. rewrite every manifest still carrying the target.
        for _bid, path, manifest in bundles:
            if not any(
                _norm_id(r["id"]) == target_key
                for r in manifest.get("records", [])
            ):
                continue
            manifest["records"] = [
                r
                for r in manifest.get("records", [])
                if _norm_id(r["id"]) != target_key
            ]
            known = {
                _norm_id(t["target_id"]) for t in manifest.get("tombstones", [])
            }
            if target_key not in known:
                manifest["tombstones"] = list(manifest.get("tombstones", [])) + [
                    tombstone
                ]
            validate_bundle(manifest)
            _atomic_write(path, canonical_bytes(manifest))

        # 4. verify actual absence before claiming success.
        survivors = sorted(
            {
                bid
                for bid, _path, manifest in self._bundle_manifests()
                for record in manifest.get("records", [])
                if _norm_id(record["id"]) == target_key
            }
        )
        if survivors:
            raise DeletionIncompleteError(
                f"target {target_id!r} still present in bundle(s) {survivors}; "
                "no receipt issued"
            )

        # 5. receipt last — with TARGET-WIDE accounting: every removal of
        #    this target recorded in evidence (across ALL tombstone
        #    generations) or in the recovery log must be named, and
        #    _write_receipt self-verifies before persisting (audit HIGH#2).
        #    reissue_on_id_collision (advisory A-1): a same-generation
        #    resurrection replays this receipt's exact id preimage; never
        #    overwrite the existing immutable receipt file — supersede the
        #    chain tail instead.
        return self._write_receipt(
            bundle_id,
            tombstone,
            self._known_removals(target_id),
            now=now,
            reissue_on_id_collision=True,
            inventory=store_inventory,
        )

    def _ensure_journal_tombstone(self, tombstone, journal_entries):
        """Make ``tombstone`` durable in the journal (audit HIGH#1 Repro B).

        A merged tombstone can equal NO journal line; a receipt embedding
        an unjournaled tombstone fails its own verification, so every path
        that writes (or re-issues) a receipt appends it first — appended
        unconditionally, never gated on an artifacts diff.
        """
        if not any(t == tombstone for t in journal_entries):
            self._append_journal(tombstone)

    def _delete_with_nothing_present(self, bundle_id, target_id, journal_entries, *, now=None, inventory=None):
        """Handle a delete whose target is already absent from every bundle."""
        if not journal_entries:
            raise UnknownTargetError(
                f"target {target_id!r} not present in bundle {bundle_id!r}"
            )
        tombstone = _merge_tombstones(journal_entries)[0]
        existing = self._latest_receipt(target_id)
        if existing is not None:
            check = self.verify_receipt(existing)
            if check["ok"]:
                return existing
            if _is_growth_underreport(check["problems"]) and (
                self._underreport_due_to_growth(existing)
            ):
                # SPEC 1.2.2 / RFC Q5: the only healing path. The receipt
                # under-reports because known removals grew (recover() log
                # and/or evidence) — re-issue a fresh receipt naming every
                # known removal, superseding the old one, instead of
                # raising. Any other failure stays DeletionIncompleteError.
                self._ensure_journal_tombstone(tombstone, journal_entries)
                return self._reissue_receipt(
                    bundle_id, target_id, existing, tombstone, now=now,
                    inventory=inventory,
                )
            raise DeletionIncompleteError(
                f"existing receipt for {target_id!r} does not verify "
                f"against current state: {check['problems']}"
            )
        # Crash between manifest rewrite and receipt: the evidence written
        # before the rewrite lets us issue an honest receipt now. The
        # accounting is the target-wide union (all generations + recovery).
        self._ensure_journal_tombstone(tombstone, journal_entries)
        removed = self._known_removals(target_id)
        if not removed:
            raise DeletionIncompleteError(
                f"target {target_id!r} is absent but no removal evidence was "
                "recorded; refusing to issue a receipt"
            )
        return self._write_receipt(
            bundle_id, tombstone, removed, now=now, inventory=inventory
        )

    def _underreport_due_to_growth(self, receipt):
        """Precise re-issue predicate (SPEC 1.2.2): the receipt names a
        strict subset of the removals durably recorded for its TARGET —
        the delete-time evidence across all tombstone generations plus the
        recovery log — and invents nothing. Paired with
        :func:`_is_growth_underreport` (which whitelists the failure
        messages), this refuses to re-issue over tampering or broken
        chains — those stay :class:`DeletionIncompleteError`."""
        body = receipt["receipt"]
        recorded = {
            (entry["record_id"], entry["digest"])
            for entry in self._read_evidence(body["target_id"])["removals"]
        }
        claimed = {
            (record["id"], record["digest"]) for record in body["removed_records"]
        }
        recovered = {
            (entry["record_id"], entry["digest"])
            for entry in self.recovery_removals(body["target_id"])
        }
        known = recorded | recovered
        return claimed <= known and known > claimed

    def _reissue_receipt(self, bundle_id, target_id, old_receipt, tombstone, *, now=None, inventory=None):
        """Write a fresh receipt superseding ``old_receipt`` (SPEC 1.2.2).

        The new receipt names EVERY removal known to the service root for
        this target — the target-wide delete-time evidence union plus the
        recovery log — and its ``supersedes`` is the old receipt's
        ``integrity.digest``. The old receipt file is never touched:
        receipts are immutable and supersession is append-only.
        """
        removed = self._known_removals(target_id)
        receipt = build_receipt(
            bundle_id,
            tombstone,
            removed,
            issued_at=now or self._clock(),
            supersedes=old_receipt["integrity"]["digest"],
            inventory=inventory,
        )
        self._self_check(receipt)
        path = self.receipts_dir / f"{receipt['receipt']['id']}.json"
        _atomic_write(path, canonical_bytes(receipt))
        return receipt

    def _self_check(self, receipt):
        """Audit HIGH#2 / BACKLOG M2 #1: NEVER issue a receipt that fails
        its own ``verify_receipt`` — on ANY delete() return path.

        This is the safety net, not the fix: FIX 1 (target-wide
        accounting) makes the underlying inconsistency impossible; this
        makes any residual violation loud (DeletionIncompleteError)
        instead of letting a self-failing receipt reach a caller or disk.
        Runs BEFORE the write, so a failing receipt is never persisted.
        """
        check = self.verify_receipt(receipt)
        if not check["ok"]:
            raise DeletionIncompleteError(
                "refusing to issue a receipt that fails its own "
                f"verification: {check['problems']}"
            )
        return receipt

    def _write_receipt(
        self,
        bundle_id,
        tombstone,
        removed_records,
        *,
        now=None,
        reissue_on_id_collision=False,
        inventory=None,
    ):
        """Write a freshly built receipt, self-checked (audit HIGH#2).

        ``reissue_on_id_collision`` (advisory A-1, fresh-path delete only):
        a copy of the target resurrected in the SAME tombstone generation
        replays this receipt's exact id preimage, so the computed file path
        already exists. Receipts are immutable — ``_atomic_write`` would
        destroy the existing file's bytes AND every live ``supersedes``
        link anchored to its digest (a superseding receipt whose link can
        no longer resolve is a permanently broken chain). Route through
        :meth:`_reissue_receipt` instead: the new receipt supersedes the
        current chain TAIL for this target (the colliding file may itself
        be a superseded mid-chain receipt), the ``supersedes`` value folds
        into the id preimage so the new id is provably distinct, and no
        existing file is touched. If no chain tail can be resolved, the
        state is inconsistent and stays fail-closed
        (:class:`DeletionIncompleteError`).
        """
        receipt = build_receipt(
            bundle_id, tombstone, removed_records, issued_at=now or self._clock(),
            inventory=inventory,
        )
        path = self.receipts_dir / f"{receipt['receipt']['id']}.json"
        if reissue_on_id_collision and path.exists():
            target_id = tombstone["target_id"]
            tail = self._latest_receipt(target_id)
            if tail is None:
                raise DeletionIncompleteError(
                    f"receipt file {path} already exists but no chain-tail "
                    f"receipt for target {target_id!r} can be resolved; "
                    "refusing to overwrite an existing immutable receipt"
                )
            return self._reissue_receipt(
                bundle_id, target_id, tail, tombstone, now=now,
                inventory=inventory,
            )
        self._self_check(receipt)
        _atomic_write(path, canonical_bytes(receipt))
        return receipt

    def receipt_paths(self):
        if not self.receipts_dir.exists():
            return []
        return sorted(self.receipts_dir.glob("*.json"))

    def _latest_receipt(self, target_id, bundle_id=None):
        """Chain-tail receipt for ``target_id`` (SPEC 1.2.2).

        A receipt that has been superseded by another on-disk receipt is a
        stale under-report and is never returned: among this target's
        receipts the only meaningful verification entry point is the chain
        TAIL — the newest receipt no other receipt supersedes. Falls back
        to plain ``(issued_at, id)`` order only if every candidate is
        claimed as superseded (a broken chain then surfaces through
        :meth:`verify_receipt` as :class:`DeletionIncompleteError`).

        Tail disambiguation (advisory A-1, ATK3 mode B): distinct tombstone
        generations produce distinct receipts with NO supersession link
        between them, so a target can have several non-superseded
        candidates at once, and ``(issued_at, id)`` order is not a sound
        tiebreak (equal timestamps pick the lexicographic id, which may
        belong to a stale under-reporting generation). The semantic tail
        is the receipt that CAN verify against current state — verifying
        candidates are preferred, and only among them does ``(issued_at,
        id)`` order apply. Without this, a plain retry would re-issue over
        the stale candidate and mint a SECOND ok tail (multiple-tail
        id-space blowup).
        """
        found = []
        superseded_digests = set()
        for path in self.receipt_paths():
            try:
                receipt = json_loads_strict(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            body = receipt.get("receipt", {})
            link = body.get("supersedes")
            if isinstance(link, str):
                superseded_digests.add(link)
            if _norm_id(body.get("target_id")) != _norm_id(target_id):
                continue
            if bundle_id is not None and body.get("bundle_id") != bundle_id:
                continue
            found.append(receipt)
        if not found:
            return None
        tails = [
            receipt
            for receipt in found
            if receipt["integrity"]["digest"] not in superseded_digests
        ]
        pool = tails or found
        verifying = [r for r in pool if self.verify_receipt(r)["ok"]]
        if verifying:
            pool = verifying
        pool.sort(key=lambda r: (r["receipt"]["issued_at"], r["receipt"]["id"]))
        return pool[-1]

    # -- recovery ---------------------------------------------------------
    def recover(self, *, lock_timeout=DEFAULT_LOCK_TIMEOUT):
        """Replay the journal onto every manifest (crash recovery).

        Returns the list of record ids removed during recovery. This is the
        executable form of the tombstone-first promise: a tombstone is
        durable before the manifest rewrite, so recovery can always finish
        the deletion.

        Every copy removed here is first recorded durably in the recovery
        log (``recovery.jsonl``), before the manifest rewrite — so a removal
        recover() performed can never vanish without evidence, and
        ``verify_receipt`` can hold receipts accountable for it (semantics
        (i), see module docstring). Idempotent: a second ``recover()`` on
        consistent state finds nothing to remove, writes nothing, and
        returns ``[]``.

        A-2 closure (audit, 2026-11-08): per-file error handling is split —
        genuinely UNREADABLE entries (``OSError``: directory-shaped entry,
        permissions, vanished mid-scan) are SKIPPED and counted in
        :attr:`last_recovery_skipped_unreadable` (visible, never silent);
        MALFORMED content (``TypeError``/``ValueError``, including
        :class:`~mbcp.canonical.NonFiniteConstantError` NaN/Infinity
        poison) raises the typed :class:`DeletionError` naming the file —
        never a silent skip, and already-typed errors propagate as-is.
        The whole run holds the root advisory lock (audit §3); nested
        acquisition via propagation intake is re-entrant.
        """
        with self._root_lock(lock_timeout):
            return self._recover_locked()

    def _recover_locked(self):
        """Locked body of :meth:`recover`."""
        self.last_recovery_skipped_unreadable = 0
        journal = _merge_tombstones(self.journal_tombstones())
        if not journal or not self.bundles_dir.exists():
            return []
        targets = {normalize_id(t["target_id"]) for t in journal}
        removed = []
        for path in sorted(self.bundles_dir.glob("*.json")):
            # A-2 split (audit): (OSError, KeyError) = genuinely
            # unreadable/missing -> skip + count, visible via
            # last_recovery_skipped_unreadable. TypeError/ValueError =
            # malformed content -> typed, file-naming, never silent.
            try:
                manifest = json_loads_strict(path.read_text(encoding="utf-8"))
                validate_bundle(manifest)
            except (OSError, KeyError):
                self.last_recovery_skipped_unreadable += 1
                continue
            except (TypeError, ValueError) as err:
                if isinstance(err, DeletionError):
                    raise
                raise DeletionError(
                    f"corrupt bundle manifest {path}: {err}"
                ) from err
            stale = [
                r
                for r in manifest.get("records", [])
                if normalize_id(r["id"]) in targets
            ]
            changed = bool(stale)
            if stale:
                for record in stale:
                    self._record_recovery(manifest["bundle"]["id"], record)
                removed.extend(r["id"] for r in stale)
                manifest["records"] = [
                    r
                    for r in manifest.get("records", [])
                    if normalize_id(r["id"]) not in targets
                ]
            known = {t["target_id"] for t in manifest.get("tombstones", [])}
            for tombstone in journal:
                if tombstone["target_id"] not in known:
                    manifest["tombstones"].append(tombstone)
                    known.add(tombstone["target_id"])
                    changed = True
            if changed:
                validate_bundle(manifest)
                _atomic_write(path, canonical_bytes(manifest))
        return sorted(set(removed))

    # -- verification -----------------------------------------------------
    def _chain_index(self):
        """Parse every on-disk receipt into chain links.

        Returns ``(by_digest, superseding)`` where ``by_digest`` maps each
        artifact's ``integrity.digest`` field to its parsed receipt, and
        ``superseding`` maps a ``supersedes`` link value to the list of
        artifacts claiming it. Unreadable files are skipped — they can
        neither serve as chain links nor be verified themselves.
        """
        by_digest = {}
        superseding = {}
        for path in self.receipt_paths():
            try:
                artifact = json_loads_strict(path.read_text(encoding="utf-8"))
                body = artifact["receipt"]
                digest = artifact["integrity"]["digest"]
            except (OSError, KeyError, TypeError, ValueError):
                continue
            by_digest.setdefault(digest, artifact)
            link = body.get("supersedes")
            if isinstance(link, str):
                superseding.setdefault(link, []).append(artifact)
        return by_digest, superseding

    def verify_receipt(self, receipt, *, check_inventory=False):
        """Check a receipt artifact against durable service state.

        Returns ``{"ok": bool, "problems": [...], "receipt_id": ...}``.
        Checks: schema, self-digest, ``tombstone_digest`` vs the embedded
        tombstone, the embedded tombstone vs the *journal* tombstone (so
        ``deleted_at``, ``reason`` and ``derived_artifacts`` are bound to
        durable evidence rather than to the receipt itself),
        ``removed_records`` vs the recorded removal evidence (per-target
        digests written before the manifest rewrite) UNION the recovery
        log (digests removed later by :meth:`recover` — semantics (i), see
        module docstring: every removal known to the service root must be
        accounted for in ``removed_records``), the receipt's internal
        inventory consistency (``inventory_digest`` recomputed over the
        embedded sorted ``bundle_set``), absence of the target from
        every bundle under the service root, and — for re-issued receipts
        — the supersession chain (SPEC 1.2.2).

        ``check_inventory`` (audit §13, default OFF to preserve the API
        contract): additionally compare the receipt's recorded
        ``bundle_set`` against the store root's CURRENT live bundle-id
        set. A receipt is a HISTORICAL record, so plain verification stays
        ``ok`` after the store set changes (a bundle added or removed
        later does not retroactively falsify the deletion); with
        ``check_inventory=True`` a set divergence fails closed with a
        problem NAMING the divergent bundle ids — the cross-root
        reconciliation hook that detects a laundered/resurrected sibling
        bundle the receipt's record-level evidence cannot see.

        Supersession chain semantics: ``ok: True`` is possible ONLY for the
        chain TAIL. Every ``supersedes`` link must resolve to a real,
        digest-matching, same-target receipt on disk (a link to a missing
        or digest-mismatched receipt is a broken chain); a revisited digest
        during the walk is a circular chain (runtime check by design —
        JSON Schema cannot express graph constraints). A receipt that has
        been superseded verifies ``ok: False`` no matter what its own
        accounting says — superseding never retroactively launders a stale
        receipt, and a non-tail receipt verified alone is an under-report.
        """
        if isinstance(receipt, (str, os.PathLike)):
            try:
                receipt = json_loads_strict(
                    Path(receipt).read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as err:
                return {
                    "ok": False,
                    "problems": [f"receipt unreadable: {err}"],
                    "receipt_id": None,
                }
        problems = []
        try:
            _validate_receipt(receipt)
        except ReceiptValidationError as err:
            return {"ok": False, "problems": [str(err)], "receipt_id": None}

        body = receipt["receipt"]
        receipt_digest = receipt["integrity"]["digest"]
        try:
            body_digest = canonical_sha256(body)
        except UnicodeEncodeError as err:
            # A hostile receipt whose strings carry lone surrogates must
            # fail verification with a problem, never crash untyped
            # (audit §11).
            body_digest = None
            problems.append(f"receipt body is not encodable UTF-8: {err}")
        if body_digest is not None and body_digest != receipt_digest:
            problems.append("receipt digest does not match its body (tampered)")

        # The receipt's own claims must be internally consistent...
        try:
            embedded_digest = canonical_sha256(body["tombstone"])
        except UnicodeEncodeError as err:
            embedded_digest = None
            problems.append(f"receipt tombstone is not encodable UTF-8: {err}")
        if (
            embedded_digest is not None
            and body["tombstone_digest"] != embedded_digest
        ):
            problems.append("tombstone_digest does not match the embedded tombstone")
        if body["reason"] != body["tombstone"]["reason"]:
            problems.append("receipt reason does not match the embedded tombstone")
        if body["derived_artifacts"] != body["tombstone"]["derived_artifacts"]:
            problems.append(
                "receipt derived_artifacts do not match the embedded tombstone"
            )

        # Inventory self-consistency (audit §13): the digest must be the
        # canonical hash of the embedded sorted bundle-id list. Covered
        # for free against whole-body tampering by integrity.digest, but
        # a receipt assembled from mismatched parts fails here, named.
        inventory_set = None
        try:
            inventory_set = list(body["inventory"]["bundle_set"])
            if inventory_digest(inventory_set) != body["inventory"]["inventory_digest"]:
                problems.append(
                    "receipt inventory_digest does not match its bundle_set "
                    "(tampered inventory)"
                )
        except (KeyError, TypeError) as err:
            problems.append(f"receipt inventory block malformed: {err}")
        except UnicodeEncodeError as err:
            problems.append(f"receipt inventory is not encodable UTF-8: {err}")

        # Supersession chain (SPEC 1.2.2): walk every supersedes link from
        # this receipt to the chain origin. The visited check comes FIRST
        # at each step — a revisited digest is a cycle even if the
        # revisiting link's target were inconsistent (a self-consistent
        # cycle is cryptographically infeasible anyway, so this branch is
        # defense against hand-crafted garbage chains).
        by_digest, superseding = self._chain_index()
        visited = {receipt_digest}
        current = body
        while "supersedes" in current:
            link = current["supersedes"]
            if link in visited:
                problems.append(
                    f"circular supersession chain detected at digest {link} "
                    "(supersession chains must be acyclic)"
                )
                break
            visited.add(link)
            linked = by_digest.get(link)
            if linked is None:
                problems.append(
                    f"broken supersession chain: no on-disk receipt has "
                    f"digest {link}"
                )
                break
            linked_body = linked["receipt"]
            try:
                linked_digest = canonical_sha256(linked_body)
            except UnicodeEncodeError:
                linked_digest = None
            if linked_digest != link:
                problems.append(
                    "broken supersession chain: the receipt named by "
                    "supersedes does not match its own digest (tampered link)"
                )
                break
            if linked_body.get("target_id") != body["target_id"]:
                problems.append("supersession chain crosses target ids")
                break
            current = linked_body

        # Tail position: a receipt some other receipt supersedes is a stale
        # under-report and can never be an ok verification entry point.
        successors = [
            artifact
            for artifact in superseding.get(receipt_digest, [])
            if artifact["integrity"]["digest"] != receipt_digest
        ]
        if successors:
            problems.append(
                f"receipt has been superseded by "
                f"{successors[0]['receipt'].get('id')!r}; a superseded receipt "
                "verified alone is a stale under-report — verify the chain "
                "tail instead"
            )

        # ...and must be bound to the durable journal, not merely present in it.
        # All target comparisons are NFC + ASCII case-insensitive (SPEC 1.5,
        # amended 2026-11-10): a receipt naming "Rec-1" verifies against a
        # journal tombstone for "rec-1" of the same logical id.
        target_key = _norm_id(body["target_id"])
        try:
            journal = [
                t
                for t in self.journal_tombstones()
                if _norm_id(t["target_id"]) == target_key
            ]
        except DeletionError as err:
            journal = None
            problems.append(f"tombstone journal unreadable: {err}")
        if journal == []:
            problems.append("no tombstone for target in journal")
        elif journal:
            if not any(body["tombstone"] == tombstone for tombstone in journal):
                problems.append(
                    "receipt tombstone does not match any journal tombstone "
                    "(deleted_at/reason/derived_artifacts)"
                )

        # Semantics (i): ok=True means the receipt accounts for EVERY
        # removal of this target known to the service root. Known removals
        # are TARGET-WIDE (audit HIGH#1): the delete-time evidence across
        # ALL tombstone generations (a target's evidence accumulates over
        # every generation; accounting must not be scoped to the one
        # generation named in the receipt) UNION the recovery log (copies
        # removed later by recover()). Under-report = ok:False.
        try:
            recovered = self._read_recovery()
        except DeletionError as err:
            recovered = None
            problems.append(f"recovery log unreadable: {err}")
        recovered_pairs = set()
        if recovered is not None:
            recovered_pairs = {
                (entry["record_id"], entry["digest"])
                for entry in recovered
                if _norm_id(entry["target_id"]) == target_key
            }
        try:
            evidence = self._read_evidence(body["target_id"])
        except (DeletionError, UnicodeEncodeError) as err:
            # UnicodeEncodeError: a hostile receipt whose target_id carries
            # a lone surrogate must fail verification typed, not crash.
            evidence = None
            problems.append(f"removal evidence unreadable: {err}")
        if evidence is not None:
            recorded = {
                (entry["record_id"], entry["digest"])
                for entry in evidence["removals"]
            }
            claimed = {
                (record["id"], record["digest"])
                for record in body["removed_records"]
            }
            if recorded - claimed or (claimed - recorded) - recovered_pairs:
                problems.append(
                    "removed_records do not match recorded deletion evidence"
                )
        if recovered is not None:
            claimed_pairs = {
                (record["id"], record["digest"])
                for record in body["removed_records"]
            }
            for record_id, digest in sorted(recovered_pairs - claimed_pairs):
                problems.append(
                    f"recovery removed digest {digest} of target {record_id!r} "
                    "that the receipt does not report (receipt under-reports "
                    "known removals)"
                )

        bundle_manifest_path = self.bundle_path(body["bundle_id"])
        if not bundle_manifest_path.exists():
            problems.append("bundle manifest missing")
        else:
            # Audit §4: existence is not identity — the manifest found at
            # the safe path must actually declare this bundle id (a legacy
            # aliased file must not satisfy the check vacuously).
            try:
                manifest = json_loads_strict(
                    bundle_manifest_path.read_text(encoding="utf-8")
                )
                if (
                    not isinstance(manifest, dict)
                    or not isinstance(manifest.get("bundle"), dict)
                    or manifest["bundle"].get("id") != body["bundle_id"]
                ):
                    problems.append(
                        f"bundle manifest {bundle_manifest_path} does not "
                        f"declare bundle id {body['bundle_id']!r}"
                    )
            except (OSError, ValueError) as err:
                problems.append(f"bundle manifest unreadable: {err}")
        try:
            surviving = sorted(
                {
                    bid
                    for bid, _path, manifest in self._bundle_manifests()
                    for record in manifest.get("records", [])
                    if _norm_id(record["id"]) == target_key
                }
            )
        except DeletionError as err:
            surviving = None
            problems.append(f"bundle state unreadable: {err}")
        for bundle_id in surviving or []:
            problems.append(f"target record still present in bundle {bundle_id}")

        # Audit §13 (opt-in, default off to preserve the API contract):
        # cross-root reconciliation. A receipt is a historical record —
        # store-set growth AFTER the deletion does not falsify it — so
        # this runs only when the caller asks, and fails closed naming
        # the divergent bundle ids.
        if check_inventory:
            try:
                live_set = set(self.bundle_inventory())
                recorded_set = set(
                    inventory_set
                    if inventory_set is not None
                    else body["inventory"]["bundle_set"]
                )
            except (DeletionError, KeyError, TypeError, UnicodeEncodeError) as err:
                problems.append(f"store inventory unreadable: {err}")
            else:
                added = sorted(live_set - recorded_set)
                missing = sorted(recorded_set - live_set)
                if added or missing:
                    problems.append(
                        "store inventory diverges from the receipt's "
                        f"deletion-time bundle_set: added bundle ids {added}, "
                        f"missing bundle ids {missing}"
                    )

        return {
            "ok": not problems,
            "problems": problems,
            "receipt_id": body["id"],
        }
