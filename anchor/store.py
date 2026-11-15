"""On-disk layout for anchored timestamps under a bundle root.

Layout (all inside the service root, next to the existing evidence
layer — the pre-existing journal / tombstone / evidence structure is
never touched):

    evidence/anchors/<digest>.tsr          RFC3161 token (DER bytes)
    evidence/anchors/<digest>.meta.json    submission metadata
    evidence/anchors/<digest>.<n>.tsr      re-anchor of the same digest
    evidence/anchors/<digest>.<n>.meta.json
    evidence/anchors/trust/<host>/cacert.pem
                                           TSA trust-chain snapshot,
                                           fetched once per endpoint
    evidence/anchors/pending.jsonl         append-only pending events

Immutability (RFC anchor tool 4): files under ``evidence/anchors/`` are
never overwritten or deleted. Re-anchoring the same digest writes the
next free ``.<n>`` suffix; anchors are written with exclusive create.

Pending semantics (RFC anchor tool 6): ``pending.jsonl`` is an
append-only JSONL log of failed submissions, structurally homologous to
the tombstone journal. A digest with a token file on disk is *anchored*;
a digest with only pending events is *pending*. Status display must show
both states honestly — a pending entry is never reported as a success.
"""

import hashlib
import json
import os
import re
from pathlib import Path

from .canonical_replay import canonical_bytes, json_loads_strict

ANCHORS_REL = Path("evidence") / "anchors"
PENDING_NAME = "pending.jsonl"
TRUST_NAME = "trust"

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class AnchorStoreError(Exception):
    """Base error for the anchor store layer."""


class PersistError(AnchorStoreError):
    """Local write failed after a successful submission (RFC 6 row 3).

    Token bytes are not retained anywhere; the TSA is stateless so a
    later re-submission is harmless.
    """


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class AnchorStore:
    """Versioned, immutable anchor file store for one bundle root."""

    def __init__(self, root):
        self.root = Path(root)
        self.anchors_dir = self.root / ANCHORS_REL

    # -- pending log ---------------------------------------------------

    @property
    def pending_path(self):
        return self.anchors_dir / PENDING_NAME

    def append_pending(self, event):
        """Append one canonical-JSON event line (fsynced, exclusive dir)."""
        self.anchors_dir.mkdir(parents=True, exist_ok=True)
        line = canonical_bytes(event) + b"\n"
        with open(self.pending_path, "ab") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        _fsync_dir(self.anchors_dir)

    def pending_events(self):
        """Read back all pending events (tolerates a missing log)."""
        if not self.pending_path.exists():
            return []
        events = []
        with open(self.pending_path, "rb") as fh:
            for raw in fh:
                raw = raw.strip()
                if raw:
                    events.append(json_loads_strict(raw.decode("utf-8")))
        return events

    # -- trust snapshots ------------------------------------------------

    def trust_path(self, endpoint_url):
        """Snapshot path for one TSA endpoint, keyed by URL host."""
        from urllib.parse import urlparse

        host = urlparse(endpoint_url).hostname or "unknown"
        return self.anchors_dir / TRUST_NAME / host / "cacert.pem"

    def has_trust(self, endpoint_url):
        return self.trust_path(endpoint_url).exists()

    def write_trust(self, endpoint_url, pem_bytes):
        """Store a TSA trust-chain snapshot (exclusive create, immutable)."""
        path = self.trust_path(endpoint_url)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(path, "xb") as fh:
                fh.write(pem_bytes)
                fh.flush()
                os.fsync(fh.fileno())
        except FileExistsError:
            pass  # snapshot already stored — never overwrite
        _fsync_dir(path.parent)

    # -- anchor files ----------------------------------------------------

    @staticmethod
    def _check_digest(digest):
        if not _DIGEST_RE.match(digest):
            raise AnchorStoreError(f"malformed sha256 digest {digest!r}")

    def token_paths(self, digest):
        """Existing token files for ``digest`` (base first, then .1, .2...)."""
        self._check_digest(digest)
        if not self.anchors_dir.exists():
            return []
        base = self.anchors_dir / f"{digest}.tsr"
        paths = []
        if base.is_file():
            paths.append(base)
        n = 1
        while True:
            path = self.anchors_dir / f"{digest}.{n}.tsr"
            if not path.is_file():
                break
            paths.append(path)
            n += 1
        return paths

    def next_paths(self, digest):
        """(token_path, meta_path) with the next free version suffix."""
        existing = self.token_paths(digest)
        if not existing:
            return (
                self.anchors_dir / f"{digest}.tsr",
                self.anchors_dir / f"{digest}.meta.json",
            )
        n = len(existing)
        return (
            self.anchors_dir / f"{digest}.{n}.tsr",
            self.anchors_dir / f"{digest}.{n}.meta.json",
        )

    def write_anchor(self, digest, token, meta):
        """Write one token + meta pair, exclusive create, never overwrite.

        Raises :class:`PersistError` on any local write failure. On a
        meta-write failure after the token landed, the token is removed
        again so there is no durable half-anchor (fail-closed: no partial
        state).
        """
        self._check_digest(digest)
        token_path, meta_path = self.next_paths(digest)
        self.anchors_dir.mkdir(parents=True, exist_ok=True)
        try:
            with open(token_path, "xb") as fh:
                fh.write(token)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as err:
            raise PersistError(f"token write failed: {err}") from err
        try:
            with open(meta_path, "xb") as fh:
                fh.write(
                    canonical_bytes(meta) + b"\n"
                )
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as err:
            token_path.unlink(missing_ok=True)
            raise PersistError(f"meta write failed: {err}") from err
        _fsync_dir(self.anchors_dir)

    def latest_anchor(self, digest):
        """(token_path, meta_path) for the newest version, or None."""
        tokens = self.token_paths(digest)
        if not tokens:
            return None
        token_path = tokens[-1]
        if token_path.name == f"{digest}.tsr":
            meta_path = self.anchors_dir / f"{digest}.meta.json"
        else:
            suffix = token_path.name[: -len(".tsr")].rsplit(".", 1)[1]
            meta_path = self.anchors_dir / f"{digest}.{suffix}.meta.json"
        return token_path, meta_path

    # -- metadata --------------------------------------------------------

    @staticmethod
    def sha256_hex(data):
        return hashlib.sha256(data).hexdigest()

    def read_meta(self, meta_path):
        with open(meta_path, "rb") as fh:
            return json_loads_strict(fh.read().decode("utf-8"))


def build_meta(*, digest, kind, endpoint, request_bytes, token_bytes,
               trust_rel_path, submitted_at):
    """Metadata sidecar for one anchor (RFC anchor tool 4 field set)."""
    return {
        "receipt_digest": digest,
        "kind": kind,
        "tsa_endpoint": endpoint,
        "submitted_at": submitted_at,
        "request_sha256": AnchorStore.sha256_hex(request_bytes),
        "token_sha256": AnchorStore.sha256_hex(token_bytes),
        "tsa_trust_chain_snapshot_path": trust_rel_path,
    }
