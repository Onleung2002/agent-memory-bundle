"""MBCP reference implementation (pure stdlib).

Memory Bundle Conformance Profile — deterministic canonical JSON,
cross-bundle load_policy adjudication, and tombstone-first import.
"""

from .canonical import canonical_bytes, canonical_sha256, utc_now
from .bundle import (
    BudgetExceeded,
    LoadValidationError,
    MergeConflict,
    build_bundle,
    load,
    load_bytes,
    make_record,
    make_tombstone,
    validate_bundle,
    validate_record,
    validate_tombstone,
)
from .tombstone import apply_tombstones, import_bundle

__all__ = [
    "canonical_bytes",
    "canonical_sha256",
    "utc_now",
    "BudgetExceeded",
    "LoadValidationError",
    "MergeConflict",
    "build_bundle",
    "load",
    "load_bytes",
    "make_record",
    "make_tombstone",
    "validate_bundle",
    "validate_record",
    "validate_tombstone",
    "apply_tombstones",
    "import_bundle",
]
