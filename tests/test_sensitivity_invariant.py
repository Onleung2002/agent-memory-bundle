"""Build-path sensitivity invariant enforcement in the mbcp layer.

BACKLOG M2 #6 (Isaac ruling 2026-11-06) + verify round 2 advisory 1: the
invariant "provenance.sensitivity='secret' must not be combined with
consent.exportable=true" is enforced ON THE BUILD PATH — mbcp.make_record,
mbcp.validate_record and mbcp.build_bundle all reject such records with a
clear error naming the violated rule. The enum in
schemas/bundle-record.v0.json remains the vocabulary authority.

Load-path tolerance (SPEC 1.5): load() is a tolerant reader and must NOT
reject records already on disk that carry the banned combination; that
tolerance is asserted explicitly here so the load path never silently
becomes a validator.
"""

from m2_helpers import OWNER

from importers._common import (
    SENSITIVITY_VOCABULARY,
    check_sensitivity_invariant as importer_check_sensitivity_invariant,
)

from mbcp import (
    build_bundle,
    check_sensitivity_invariant,
    load,
    make_record,
    validate_record,
)

from syn import FIXED_TS, assert_raises


def _expect_value_error(fn, *args, **kwargs):
    """Run fn expecting ValueError; return the message for assertions."""
    try:
        fn(*args, **kwargs)
    except ValueError as err:
        return str(err)
    raise AssertionError(f"expected ValueError from {fn.__name__}, none raised")


def _secret_exportable_record():
    """Hand-shape the banned combination the way a record already on disk
    might carry it: built legally (secret + exportable=False), then mutated
    to secret + exportable=True, bypassing the build path."""
    record = make_record(
        "rec-secret",
        "fact",
        "synthetic secret body",
        OWNER,
        created=FIXED_TS,
        exportable=False,
        sensitivity="secret",
    )
    record["consent"]["exportable"] = True
    return record


def test_make_record_rejects_secret_exportable():
    message = _expect_value_error(
        make_record,
        "rec-secret",
        "fact",
        "synthetic secret body",
        OWNER,
        created=FIXED_TS,
        sensitivity="secret",  # exportable defaults to True
    )
    assert "secret" in message and "exportable" in message


def test_make_record_accepts_secret_when_not_exportable():
    record = make_record(
        "rec-secret",
        "fact",
        "synthetic secret body",
        OWNER,
        created=FIXED_TS,
        exportable=False,
        sensitivity="secret",
    )
    assert record["provenance"]["sensitivity"] == "secret"
    assert record["consent"]["exportable"] is False


def test_make_record_omits_sensitivity_by_default():
    record = make_record(
        "rec-plain", "fact", "synthetic body", OWNER, created=FIXED_TS
    )
    assert "sensitivity" not in record["provenance"]


def test_validate_record_rejects_secret_exportable():
    message = _expect_value_error(
        validate_record, _secret_exportable_record()
    )
    assert "secret" in message and "exportable" in message


def test_build_bundle_rejects_secret_exportable_record():
    assert_raises(
        ValueError,
        build_bundle,
        "bundle-banned",
        records=[_secret_exportable_record()],
    )


def test_build_bundle_rejects_secret_exportable_kwarg_record():
    # The failure is not an artifact of hand-mutation: a record freshly
    # built with the banned combination cannot enter a bundle either.
    record = make_record(
        "rec-secret",
        "fact",
        "synthetic secret body",
        OWNER,
        created=FIXED_TS,
        exportable=False,
        sensitivity="secret",
    )
    record["consent"]["exportable"] = True
    message = _expect_value_error(
        build_bundle, "bundle-banned", records=[record]
    )
    assert "secret" in message and "exportable" in message


def test_end_to_end_cannot_build_secret_exportable_bundle():
    # Build path, whole way down: neither entry point lets the bundle exist.
    assert_raises(
        ValueError,
        make_record,
        "rec-secret",
        "fact",
        "synthetic secret body",
        OWNER,
        created=FIXED_TS,
        sensitivity="secret",
    )
    assert_raises(ValueError, validate_record, _secret_exportable_record())
    assert_raises(
        ValueError,
        build_bundle,
        "bundle-banned",
        records=[_secret_exportable_record()],
    )


def test_load_path_tolerates_preexisting_secret_exportable_record():
    # SPEC 1.5 tolerant reader: load() must NOT enforce the build-path
    # invariant against records that are already on disk. The manifest is
    # assembled by hand (the build path itself now refuses to build it),
    # standing in for on-disk state written before the invariant moved here.
    record = _secret_exportable_record()
    manifest = {
        "bundle": {"id": "bundle-legacy"},
        "mbcp_version": "0.1",
        "records": [record],
        "tombstones": [],
    }
    loaded = load([manifest])
    assert [r["id"] for r in loaded] == ["rec-secret"]


def test_records_without_sensitivity_are_unaffected():
    # exportable=True stays legal when no sensitivity is declared.
    record = make_record(
        "rec-plain", "fact", "synthetic body", OWNER, created=FIXED_TS
    )
    validate_record(record)
    bundle = build_bundle("bundle-plain", records=[record])
    assert bundle["records"][0]["id"] == "rec-plain"


def test_every_non_secret_vocabulary_value_may_be_exportable():
    for value in ("public", "internal", "sensitive"):
        record = make_record(
            f"rec-{value}",
            "fact",
            "synthetic body",
            OWNER,
            created=FIXED_TS,
            sensitivity=value,
        )
        assert record["consent"]["exportable"] is True
        validate_record(record)


def test_vocabulary_values_match_schema_enum():
    # The schema enum is the authority; the in-code tuple mirrors it.
    assert set(SENSITIVITY_VOCABULARY) == {
        "public",
        "internal",
        "sensitive",
        "secret",
    }


def test_importer_check_delegates_to_mbcp_layer():
    # importers/_common.check_sensitivity_invariant is a thin delegate: the
    # same record fails with the same rule-naming error via both paths.
    record = _secret_exportable_record()
    mbcp_message = _expect_value_error(check_sensitivity_invariant, record)
    importer_message = _expect_value_error(
        importer_check_sensitivity_invariant, record
    )
    assert mbcp_message == importer_message
    # ...and both accept the legal combinations.
    legal = make_record(
        "rec-legal",
        "fact",
        "synthetic body",
        OWNER,
        created=FIXED_TS,
        exportable=False,
        sensitivity="secret",
    )
    check_sensitivity_invariant(legal)
    importer_check_sensitivity_invariant(legal)
