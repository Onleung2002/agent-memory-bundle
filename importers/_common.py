"""Shared helpers for MBCP importers (pure stdlib).

Importers are a distribution wedge, not conformance evidence (SPEC §4).
Every importer must:

- attach a **sensitivity marker** in ``provenance.sensitivity``;
- default ``consent.exportable = false`` when the source carries no consent
  field (SPEC §4) — importing must not silently grant export rights;
- be deterministic: same input bytes + same import timestamp -> byte-equal
  bundle (records are sorted by id before building).

Tombstone-first is enforced one level down: importers emit a normal MBCP
bundle, and ``mbcp.import_bundle`` applies every tombstone (store + incoming)
before adding anything. ``tombstones`` is a REQUIRED argument at every
importer entry point: omitting it raises TypeError instead of silently
resurrecting deleted records. Pass tombstones from the deletion service
journal in ``build_import_bundle(..., tombstones=service.all_tombstones())``
(SPEC §1.2/§4: re-import must never resurrect deleted records).
"""

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mbcp import build_bundle, import_bundle, make_record, utc_now, validate_record

# Sensitivity vocabulary (provenance.sensitivity) — Isaac ruling 2026-11-06
# (BACKLOG M2 #6): EXACTLY these four values, enforced by the
# bundle-record.v0 schema enum on the build path.
SENSITIVITY_VOCABULARY = ("public", "internal", "sensitive", "secret")

# Protective default for M2 importers. Both chatgpt (user-authored consumer
# export content) and hermes (local agent state, incl. private memories)
# default to "sensitive" — never "public", never an out-of-vocabulary value.
SENSITIVITY_IMPORT_DEFAULT = "sensitive"

# Error raised when the caller omits the required tombstones argument.
TOMBSTONES_REQUIRED = (
    "tombstones is REQUIRED: pass service.all_tombstones() so a re-import "
    "cannot resurrect deleted records (SPEC §1.2/§4)"
)


def require_tombstones(tombstones):
    """Fail fast when the caller omits the required tombstones argument."""
    if tombstones is None:
        raise TypeError(TOMBSTONES_REQUIRED)
    return tombstones


def check_sensitivity_invariant(record):
    """Machine-checkable invariant (BACKLOG M2 #6, Isaac ruling 2026-11-06).

    ``provenance.sensitivity = "secret"`` combined with
    ``consent.exportable = true`` is REJECTED on the build path: a secret
    record must never be marked exportable. Deterministic — pure function of
    the record, raises ValueError on violation. Records with no sensitivity
    field (or any non-secret value) pass.
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
            "combined with consent.exportable=true (Isaac ruling 2026-11-06)"
        )
    return record

_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class ImportFormatError(ValueError):
    """Raised when a source export is not in the expected format."""


def _format_epoch(epoch):
    dt = datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        base += "." + f"{dt.microsecond:06d}".rstrip("0")
    return base + "Z"


def rfc3339(value, *, default=None):
    """Best-effort RFC3339 timestamp from an export value.

    - already-RFC3339 strings are returned **verbatim** (no rewriting);
    - epoch seconds (int/float/numeric string) become UTC RFC3339,
      preserving sub-second precision;
    - anything missing/unparseable falls back to ``default``.
    """
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        if _TS_RE.match(text):
            return text
        try:
            epoch = float(text)
        except ValueError:
            return default
        return _format_epoch(epoch)
    if isinstance(value, (int, float)):
        return _format_epoch(value)
    return default


def read_json(path):
    """Load JSON from ``path``; raise ImportFormatError on failure."""
    path = Path(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as err:
        raise ImportFormatError(f"missing file: {path}") from err
    except json.JSONDecodeError as err:
        raise ImportFormatError(f"invalid JSON in {path}: {err}") from err
    except UnicodeDecodeError as err:
        raise ImportFormatError(f"{path} is not UTF-8: {err}") from err


def content_id(prefix, *parts):
    """Stable, content-addressed record id (same input -> same id)."""
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:16]}"


def build_record(
    record_id,
    kind,
    body,
    owner,
    *,
    created,
    source,
    importer,
    sensitivity,
    kind_priority="standard",
    max_chars=4096,
    on_budget_exceed="skip",
    lifecycle="active",
    imported_at=None,
    extra_provenance=None,
):
    """Build a validated importer record with sensitivity + consent defaults."""
    record = make_record(
        record_id,
        kind,
        body,
        owner,
        source=source,
        created=created,
        lifecycle=lifecycle,
        exportable=False,  # SPEC §4: no consent field in source -> not exportable
        priority=kind_priority,
        max_chars=max_chars,
        on_budget_exceed=on_budget_exceed,
    )
    record["provenance"].update(
        {
            "importer": importer,
            "sensitivity": sensitivity,
            "imported_at": imported_at or created,
        }
    )
    if extra_provenance:
        record["provenance"].update(extra_provenance)
    return check_sensitivity_invariant(validate_record(record))


def dedupe_sorted(records):
    """Deterministic record order with first-wins dedupe by id."""
    seen = set()
    out = []
    for record in sorted(records, key=lambda r: r["id"]):
        if record["id"] in seen:
            continue
        seen.add(record["id"])
        out.append(record)
    return out


def make_bundle(records, bundle_id, *, tombstones=None):
    """Validate and build an MBCP manifest from imported records.

    ``tombstones`` is REQUIRED — omitting it raises TypeError so a re-import
    without the deletion journal can never happen by accident (SPEC §1.2/§4).
    """
    return build_bundle(
        bundle_id,
        records=dedupe_sorted(records),
        tombstones=list(require_tombstones(tombstones)),
    )


def apply_import(store, bundle):
    """Tombstone-first import of an importer bundle into ``store``."""
    return import_bundle(store, bundle)


def now_utc():
    return utc_now()
