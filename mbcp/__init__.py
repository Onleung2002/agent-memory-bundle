"""MBCP reference implementation (pure stdlib).

Memory Bundle Conformance Profile — deterministic canonical JSON,
cross-bundle load_policy adjudication, and tombstone-first import.
"""

from .canonical import canonical_bytes, canonical_sha256, normalize_id, utc_now
from .bundle import (
    BudgetExceeded,
    LoadValidationError,
    MergeConflict,
    build_bundle,
    check_sensitivity_invariant,
    load,
    load_bytes,
    make_record,
    make_tombstone,
    validate_bundle,
    validate_record,
    validate_tombstone,
)
from .tombstone import (
    TombstonedIdRejectedError,
    apply_tombstones,
    import_bundle,
)
from .deletion import (
    BundleIdCollisionError,
    DeletionError,
    DeletionIncompleteError,
    L1DeletionService,
    ReceiptValidationError,
    UnknownTargetError,
    build_receipt,
)
from .propagation import (
    ACK_LIMITATIONS,
    PackValidationError,
    PropagationError,
    PropagationJournalError,
    export_propagation_pack,
    import_propagation_pack,
    read_propagation_journal,
    record_pending_propagation,
)

__all__ = [
    "canonical_bytes",
    "canonical_sha256",
    "normalize_id",
    "utc_now",
    "BudgetExceeded",
    "LoadValidationError",
    "MergeConflict",
    "build_bundle",
    "check_sensitivity_invariant",
    "load",
    "load_bytes",
    "make_record",
    "make_tombstone",
    "validate_bundle",
    "validate_record",
    "validate_tombstone",
    "apply_tombstones",
    "import_bundle",
    "TombstonedIdRejectedError",
    "DeletionError",
    "DeletionIncompleteError",
    "BundleIdCollisionError",
    "L1DeletionService",
    "ReceiptValidationError",
    "UnknownTargetError",
    "build_receipt",
    "ACK_LIMITATIONS",
    "PackValidationError",
    "PropagationError",
    "PropagationJournalError",
    "export_propagation_pack",
    "import_propagation_pack",
    "read_propagation_journal",
    "record_pending_propagation",
]
