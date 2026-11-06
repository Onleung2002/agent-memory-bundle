"""L1 deletion service — tombstone-first bundle deletion with receipts.

Level semantics (SPEC 1.2):

- **L1** (implemented here): the record is gone from *this* bundle; the
  bundle keeps a monotonic tombstone so a stale copy of the bundle cannot
  resurrect it, and a receipt artifact records what happened.
- **L2–L4** (not implemented in M2): cross-bundle propagation, verified
  derived-artifact erasure, third-party-verifiable erasure receipt. An L1
  receipt says so explicitly in ``limitations`` and carries
  ``derived_artifacts_verified: false`` — an L1 receipt must never be
  presented as an erasure certificate.

Durability / ordering guarantee (tombstone-first):

1. the tombstone is appended to ``tombstones.jsonl`` and fsynced;
2. only then is the bundle manifest rewritten (atomically, ``os.replace``);
3. only then is the receipt written.

A crash between (1) and (2) leaves a *superset* of deletions recorded;
:meth:`L1DeletionService.recover` replays the journal onto every manifest,
so the record can never come back. A crash between (2) and (3) loses only
the receipt, never the deletion.

On-disk layout of a service root::

    bundles/<bundle-id>.json     # MBCP manifests
    tombstones.jsonl             # append-only tombstone journal (fsynced)
    receipts/<receipt-id>.json   # L1 erasure receipts
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
    "L1 only: the record is removed from this bundle and a tombstone is "
    "retained; no cross-bundle propagation (L2) is performed or proven.",
    "Derived artifacts are recorded but NOT verified as erased (L3).",
    "This receipt is not a third-party-verifiable erasure certificate (L4).",
]


class DeletionError(ValueError):
    """Base class for deletion-service failures."""


class UnknownTargetError(DeletionError):
    """Raised when the target id exists nowhere in the bundle."""


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
        """Delete ``target_id`` from ``bundle_id`` (L1), returning the receipt.

        Idempotent: deleting an already-deleted target returns its latest
        receipt without writing anything new.
        """
        manifest = self.get_bundle(bundle_id)
        known = [t for t in manifest.get("tombstones", []) if t["target_id"] == target_id]
        known += [t for t in self.journal_tombstones() if t["target_id"] == target_id]
        if known:
            existing = self._latest_receipt(target_id, bundle_id)
            if existing is not None:
                return existing
            tombstone = _merge_tombstones(known)[0]
            return self._write_receipt(bundle_id, tombstone, [], now=now)

        matching = [r for r in manifest.get("records", []) if r["id"] == target_id]
        if not matching:
            raise UnknownTargetError(
                f"target {target_id!r} not present in bundle {bundle_id!r}"
            )

        now = now or self._clock()
        tombstone = make_tombstone(
            target_id,
            reason,
            deleted_at=now,
            derived_artifacts=derived_artifacts,
        )

        # 1. durable tombstone FIRST — a crash below can only over-delete.
        self._append_journal(tombstone)

        # 2. rewrite the manifest: record gone, tombstone retained.
        manifest["records"] = [
            r for r in manifest.get("records", []) if r["id"] != target_id
        ]
        manifest["tombstones"] = list(manifest.get("tombstones", [])) + [tombstone]
        validate_bundle(manifest)
        _atomic_write(self.bundle_path(bundle_id), canonical_bytes(manifest))

        # 3. receipt last.
        return self._write_receipt(bundle_id, tombstone, matching, now=now)

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

    def _latest_receipt(self, target_id, bundle_id):
        found = []
        for path in self.receipt_paths():
            try:
                receipt = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            body = receipt.get("receipt", {})
            if body.get("target_id") == target_id and body.get("bundle_id") == bundle_id:
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
        """
        journal = _merge_tombstones(self.journal_tombstones())
        if not journal or not self.bundles_dir.exists():
            return []
        targets = {t["target_id"] for t in journal}
        removed = []
        for path in sorted(self.bundles_dir.glob("*.json")):
            manifest = json.loads(path.read_text(encoding="utf-8"))
            validate_bundle(manifest)
            present = [r["id"] for r in manifest.get("records", []) if r["id"] in targets]
            changed = bool(present)
            if present:
                removed.extend(present)
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
        """Check a receipt artifact against service state.

        Returns ``{"ok": bool, "problems": [...], "receipt_id": ...}``.
        Checks: schema, self-digest, tombstone present in the journal, and
        target absent from the bundle's records.
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

        journal = [t for t in self.journal_tombstones() if t["target_id"] == body["target_id"]]
        if not journal:
            problems.append("no tombstone for target in journal")
        elif not any(
            t["deleted_at"] == body["tombstone"]["deleted_at"] for t in journal
        ):
            problems.append("journal tombstone timestamp does not match receipt")

        bundle_path = self.bundle_path(body["bundle_id"])
        if not bundle_path.exists():
            problems.append("bundle manifest missing")
        else:
            manifest = json.loads(bundle_path.read_text(encoding="utf-8"))
            if any(r["id"] == body["target_id"] for r in manifest.get("records", [])):
                problems.append("target record still present in bundle")

        return {
            "ok": not problems,
            "problems": problems,
            "receipt_id": body["id"],
        }
