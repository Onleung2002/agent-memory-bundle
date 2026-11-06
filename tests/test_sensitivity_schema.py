"""provenance.sensitivity vocabulary in the schema (BACKLOG M2 #6).

Isaac ruling 2026-11-06: the vocabulary is EXACTLY {public, internal,
sensitive, secret}; the enum lives in schemas/bundle-record.v0.json and is
enforced on the BUILD path (validate_record). The load path stays a tolerant
reader (unknown-field passthrough, SPEC P3). Machine-checkable invariant:
sensitivity="secret" AND consent.exportable=true is rejected on the build
path (importers/_common.py::check_sensitivity_invariant).
"""

from m2_helpers import OWNER

from importers._common import (
    SENSITIVITY_VOCABULARY,
    check_sensitivity_invariant,
)

from mbcp import make_record, validate_record

from syn import FIXED_TS, assert_raises


def _record_with_sensitivity(value):
    record = make_record(
        "rec-sens", "fact", "synthetic sensitivity body", OWNER, created=FIXED_TS
    )
    if value is not None:
        record["provenance"]["sensitivity"] = value
    return record


def test_vocabulary_is_exactly_the_isaac_ruling_set():
    assert set(SENSITIVITY_VOCABULARY) == {"public", "internal", "sensitive", "secret"}


def test_each_vocabulary_value_passes_build_validation():
    for value in SENSITIVITY_VOCABULARY:
        record = _record_with_sensitivity(value)
        if value == "secret":
            # A secret record is valid on the build path only when it is
            # not exportable (M2 #6 invariant, now enforced by
            # mbcp.validate_record itself).
            record["consent"]["exportable"] = False
        validate_record(record)


def test_non_enum_sensitivity_rejected_on_build_path():
    # "personal"/"private" (the old importer vocabulary) are not in the enum.
    for legacy in ("personal", "private"):
        assert_raises(
            ValueError, validate_record, _record_with_sensitivity(legacy)
        )
    assert_raises(ValueError, validate_record, _record_with_sensitivity("confidential"))


def test_record_without_sensitivity_stays_valid():
    # Backward compatible: the field is optional.
    record = _record_with_sensitivity(None)
    validate_record(record)
    assert "sensitivity" not in record["provenance"]


def test_secret_with_exportable_true_is_rejected():
    record = _record_with_sensitivity("secret")
    record["consent"]["exportable"] = True
    assert_raises(ValueError, check_sensitivity_invariant, record)


def test_secret_without_exportable_is_allowed_by_invariant():
    record = _record_with_sensitivity("secret")
    record["consent"]["exportable"] = False
    check_sensitivity_invariant(record)


def test_invariant_rejects_only_secret_exportable_combination():
    # Any non-secret sensitivity may be exportable; the invariant bans the
    # secret+exportable=true pair only.
    for value in ("public", "internal", "sensitive"):
        record = _record_with_sensitivity(value)
        record["consent"]["exportable"] = True
        check_sensitivity_invariant(record)
