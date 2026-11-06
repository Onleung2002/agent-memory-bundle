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

Receipt vs recovery semantics (BACKLOG M2 #4, verify round 2 advisory 2):

``verify_receipt`` uses semantics **(i)**: a receipt verifies ``ok: True``
only if its ``removed_records`` account for EVERY removal of the target
known to the service root — both the delete()-time removals recorded in
``evidence/`` and any digest copies removed later by :meth:`recover`
(recorded in ``recovery.jsonl``). ``recover`` never rewrites or re-issues
receipts: a receipt that under-reports a recovered removal keeps failing
verification with a problem naming the unreported digest, instead of
laundering the removal back into ``ok: True``.
"""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from . import _schema
from .bundle import make_tombstone, validate_bundle, validate_tombstone
from .canonical import canonical_bytes, canonical_sha256, utc_now
from .tombstone import _merge_tombstones

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
    inconsistent (a receipt exists that no longer verifies, or the target
    vanished without any durable evidence of what was removed).
    """


class ReceiptValidationError(DeletionError):
    """Raised when a receipt artifact is malformed or tampered with."""


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
    return SAFE_ID_RE.sub("_", value).strip("_") or "bundle"


def _validate_receipt(receipt):
    try:
        _schema.validate(receipt, _receipt_schema())
    except _schema.ValidationError as err:
        raise ReceiptValidationError(f"invalid receipt: {err}") from err
    return receipt


def build_receipt(bundle_id, tombstone, removed_records, *, issued_at=None):
    """Build a schema-valid L1 receipt dict (with self-digest).

    ``removed_records`` is a list of record dicts that were removed in this
    deletion; only their id + integrity digest are retained in the receipt.
    """
    issued_at = issued_at or utc_now()
    target_id = tombstone["target_id"]
    receipt_id = "rcpt-" + hashlib.sha256(
        canonical_bytes(
            {
                "bundle_id": bundle_id,
                "target_id": target_id,
                "deleted_at": tombstone["deleted_at"],
            }
        )
    ).hexdigest()[:16]
    body = {
        "id": receipt_id,
        "spec_version": "0.1",
        "level": "L1",
        "issued_at": issued_at,
        "bundle_id": bundle_id,
        "target_id": target_id,
        "reason": tombstone["reason"],
        "tombstone": tombstone,
        "tombstone_digest": canonical_sha256(tombstone),
        "removed_records": [
            {"id": record["id"], "digest": record["integrity"]["digest"]}
            for record in removed_records
        ],
        "derived_artifacts": list(tombstone.get("derived_artifacts", [])),
        # L1 cannot prove L3: recorded, not verified. Never flip this in L1.
        "derived_artifacts_verified": False,
        "propagation": {"propagated_to": []},
        "limitations": list(L1_LIMITATIONS),
    }
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

    # -- bundles ----------------------------------------------------------
    def put_bundle(self, manifest):
        """Validate + atomically persist a manifest; returns its path."""
        validate_bundle(manifest)
        bundle_id = manifest["bundle"]["id"]
        path = self.bundles_dir / f"{_safe_id(bundle_id)}.json"
        _atomic_write(path, canonical_bytes(manifest))
        return path

    def bundle_path(self, bundle_id):
        return self.bundles_dir / f"{_safe_id(bundle_id)}.json"

    def get_bundle(self, bundle_id):
        path = self.bundle_path(bundle_id)
        if not path.exists():
            raise DeletionError(f"unknown bundle {bundle_id!r} ({path})")
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            raise DeletionError(f"corrupt bundle manifest {path}: {err}") from err
        validate_bundle(manifest)
        return manifest

    def _bundle_manifests(self):
        """Every bundle under this service root: ``[(bundle_id, path, manifest)]``."""
        if not self.bundles_dir.exists():
            return []
        bundles = []
        for path in sorted(self.bundles_dir.glob("*.json")):
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as err:
                raise DeletionError(
                    f"corrupt bundle manifest {path}: {err}"
                ) from err
            validate_bundle(manifest)
            bundles.append((manifest["bundle"]["id"], path, manifest))
        return bundles

    # -- tombstone journal ------------------------------------------------
    def journal_tombstones(self):
        """All tombstones in the append-only journal, in write order."""
        if not self.journal_path.exists():
            return []
        tombstones = []
        for lineno, line in enumerate(
            self.journal_path.read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                tomb = json.loads(line)
            except json.JSONDecodeError as err:
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
        """Per-target evidence file path (target ids may contain any chars)."""
        digest = hashlib.sha256(target_id.encode("utf-8")).hexdigest()
        return self.evidence_dir / f"{digest}.json"

    def _read_evidence(self, target_id):
        path = self.evidence_path(target_id)
        if not path.exists():
            return {"target_id": target_id, "removals": []}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            raise DeletionError(f"corrupt removal evidence {path}: {err}") from err
        if not isinstance(data, dict) or data.get("target_id") != target_id:
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

    @staticmethod
    def _removed_from_evidence(evidence, tombstone_digest):
        return [
            {"id": entry["record_id"], "integrity": {"digest": entry["digest"]}}
            for entry in evidence["removals"]
            if entry["tombstone_digest"] == tombstone_digest
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
                entry = json.loads(line)
            except json.JSONDecodeError as err:
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
        for entry in self._read_recovery():
            key = (entry["bundle_id"], entry["record_id"], entry["digest"])
            if key in seen:
                continue
            seen.add(key)
            if target_id is None or entry["target_id"] == target_id:
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
        without writing anything new.

        ``derived_artifacts`` from the caller are unioned into the journal
        tombstone; ``reason`` is only used when no tombstone for this target
        exists yet (recovery finishes the original request). When the target
        is already gone everywhere, the existing receipt is returned as-is:
        new ``derived_artifacts`` are not recorded for an already-finished
        deletion (issue a new delete after resuscitation if they matter).
        """
        self.get_bundle(bundle_id)  # unknown bundle is an error, not a no-op

        bundles = self._bundle_manifests()
        present = [
            (bid, record)
            for bid, _path, manifest in bundles
            for record in manifest.get("records", [])
            if record["id"] == target_id
        ]
        journal_entries = [
            t for t in self.journal_tombstones() if t["target_id"] == target_id
        ]

        if not present:
            return self._delete_with_nothing_present(
                bundle_id, target_id, journal_entries, now=now
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
                self._append_journal(tombstone)
        else:
            tombstone = make_tombstone(
                target_id,
                reason,
                deleted_at=now or self._clock(),
                derived_artifacts=derived_artifacts,
            )
            self._append_journal(tombstone)

        # 2. durable evidence of WHAT is removed (the digests), so a retry
        #    after a crash can still issue a receipt that binds to them.
        tombstone_digest = canonical_sha256(tombstone)
        evidence = self._record_evidence(target_id, tombstone_digest, present)

        # 3. rewrite every manifest still carrying the target.
        for _bid, path, manifest in bundles:
            if not any(r["id"] == target_id for r in manifest.get("records", [])):
                continue
            manifest["records"] = [
                r for r in manifest.get("records", []) if r["id"] != target_id
            ]
            known = {t["target_id"] for t in manifest.get("tombstones", [])}
            if target_id not in known:
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
                if record["id"] == target_id
            }
        )
        if survivors:
            raise DeletionIncompleteError(
                f"target {target_id!r} still present in bundle(s) {survivors}; "
                "no receipt issued"
            )

        # 5. receipt last.
        return self._write_receipt(
            bundle_id,
            tombstone,
            self._removed_from_evidence(evidence, tombstone_digest),
            now=now,
        )

    def _delete_with_nothing_present(self, bundle_id, target_id, journal_entries, *, now=None):
        """Handle a delete whose target is already absent from every bundle."""
        if not journal_entries:
            raise UnknownTargetError(
                f"target {target_id!r} not present in bundle {bundle_id!r}"
            )
        existing = self._latest_receipt(target_id)
        if existing is not None:
            check = self.verify_receipt(existing)
            if not check["ok"]:
                raise DeletionIncompleteError(
                    f"existing receipt for {target_id!r} does not verify "
                    f"against current state: {check['problems']}"
                )
            return existing
        # Crash between manifest rewrite and receipt: the evidence written
        # before the rewrite lets us issue an honest receipt now.
        tombstone = _merge_tombstones(journal_entries)[0]
        tombstone_digest = canonical_sha256(tombstone)
        removed = self._removed_from_evidence(
            self._read_evidence(target_id), tombstone_digest
        )
        if not removed:
            raise DeletionIncompleteError(
                f"target {target_id!r} is absent but no removal evidence was "
                "recorded; refusing to issue a receipt"
            )
        return self._write_receipt(bundle_id, tombstone, removed, now=now)

    def _write_receipt(self, bundle_id, tombstone, removed_records, *, now=None):
        receipt = build_receipt(
            bundle_id, tombstone, removed_records, issued_at=now or self._clock()
        )
        path = self.receipts_dir / f"{receipt['receipt']['id']}.json"
        _atomic_write(path, canonical_bytes(receipt))
        return receipt

    def receipt_paths(self):
        if not self.receipts_dir.exists():
            return []
        return sorted(self.receipts_dir.glob("*.json"))

    def _latest_receipt(self, target_id, bundle_id=None):
        """Latest receipt for ``target_id`` (optionally scoped to a bundle)."""
        found = []
        for path in self.receipt_paths():
            try:
                receipt = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            body = receipt.get("receipt", {})
            if body.get("target_id") != target_id:
                continue
            if bundle_id is not None and body.get("bundle_id") != bundle_id:
                continue
            found.append(receipt)
        if not found:
            return None
        found.sort(key=lambda r: (r["receipt"]["issued_at"], r["receipt"]["id"]))
        return found[-1]

    # -- recovery ---------------------------------------------------------
    def recover(self):
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
        """
        journal = _merge_tombstones(self.journal_tombstones())
        if not journal or not self.bundles_dir.exists():
            return []
        targets = {t["target_id"] for t in journal}
        removed = []
        for path in sorted(self.bundles_dir.glob("*.json")):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            validate_bundle(manifest)
            stale = [r for r in manifest.get("records", []) if r["id"] in targets]
            changed = bool(stale)
            if stale:
                for record in stale:
                    self._record_recovery(manifest["bundle"]["id"], record)
                removed.extend(r["id"] for r in stale)
                manifest["records"] = [
                    r for r in manifest.get("records", []) if r["id"] not in targets
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
    def verify_receipt(self, receipt):
        """Check a receipt artifact against durable service state.

        Returns ``{"ok": bool, "problems": [...], "receipt_id": ...}``.
        Checks: schema, self-digest, ``tombstone_digest`` vs the embedded
        tombstone, the embedded tombstone vs the *journal* tombstone (so
        ``deleted_at``, ``reason`` and ``derived_artifacts`` are bound to
        durable evidence rather than to the receipt itself),
        ``removed_records`` vs the recorded removal evidence (per-target
        digests written before the manifest rewrite) and vs the recovery
        log (digests removed later by :meth:`recover` — semantics (i), see
        module docstring: every removal known to the service root must be
        accounted for in ``removed_records``), and absence of the target
        from every bundle under the service root.
        """
        if isinstance(receipt, (str, os.PathLike)):
            receipt = json.loads(Path(receipt).read_text(encoding="utf-8"))
        problems = []
        try:
            _validate_receipt(receipt)
        except ReceiptValidationError as err:
            return {"ok": False, "problems": [str(err)], "receipt_id": None}

        body = receipt["receipt"]
        if canonical_sha256(body) != receipt["integrity"]["digest"]:
            problems.append("receipt digest does not match its body (tampered)")

        # The receipt's own claims must be internally consistent...
        if body["tombstone_digest"] != canonical_sha256(body["tombstone"]):
            problems.append("tombstone_digest does not match the embedded tombstone")
        if body["reason"] != body["tombstone"]["reason"]:
            problems.append("receipt reason does not match the embedded tombstone")
        if body["derived_artifacts"] != body["tombstone"]["derived_artifacts"]:
            problems.append(
                "receipt derived_artifacts do not match the embedded tombstone"
            )

        # ...and must be bound to the durable journal, not merely present in it.
        try:
            journal = [
                t
                for t in self.journal_tombstones()
                if t["target_id"] == body["target_id"]
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

        # removed_records must match what was durably recorded at delete time.
        try:
            evidence = self._read_evidence(body["target_id"])
        except DeletionError as err:
            evidence = None
            problems.append(f"removal evidence unreadable: {err}")
        if evidence is not None:
            recorded = sorted(
                (entry["record_id"], entry["digest"])
                for entry in evidence["removals"]
                if entry["tombstone_digest"] == body["tombstone_digest"]
            )
            claimed = sorted(
                (record["id"], record["digest"]) for record in body["removed_records"]
            )
            if recorded != claimed:
                problems.append(
                    "removed_records do not match recorded deletion evidence"
                )

        # Semantics (i): ok=True means the receipt accounts for EVERY
        # removal of this target known to the service root. Copies removed
        # later by recover() are recorded in the recovery log; a receipt
        # that does not name them under-reports and must not verify ok.
        try:
            recovered = self._read_recovery()
        except DeletionError as err:
            recovered = None
            problems.append(f"recovery log unreadable: {err}")
        if recovered is not None:
            claimed_pairs = {
                (record["id"], record["digest"])
                for record in body["removed_records"]
            }
            unreported = sorted(
                {
                    (entry["record_id"], entry["digest"])
                    for entry in recovered
                    if entry["target_id"] == body["target_id"]
                    and (entry["record_id"], entry["digest"]) not in claimed_pairs
                }
            )
            for record_id, digest in unreported:
                problems.append(
                    f"recovery removed digest {digest} of target {record_id!r} "
                    "that the receipt does not report (receipt under-reports "
                    "known removals)"
                )

        if not self.bundle_path(body["bundle_id"]).exists():
            problems.append("bundle manifest missing")
        try:
            surviving = sorted(
                {
                    bid
                    for bid, _path, manifest in self._bundle_manifests()
                    for record in manifest.get("records", [])
                    if record["id"] == body["target_id"]
                }
            )
        except DeletionError as err:
            surviving = None
            problems.append(f"bundle state unreadable: {err}")
        for bundle_id in surviving or []:
            problems.append(f"target record still present in bundle {bundle_id}")

        return {
            "ok": not problems,
            "problems": problems,
            "receipt_id": body["id"],
        }
