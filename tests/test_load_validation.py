"""SC-SCHEMA-01: load-time validation — unknown fields pass through,
malformed structure/digests raise LoadValidationError (never KeyError)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import (
    LoadValidationError,
    build_bundle,
    load,
    make_tombstone,
    validate_bundle,
    validate_record,
)

from syn import assert_raises, syn_record


def _raw_bundle(records=(), tombstones=()):
    return {
        "bundle": {"id": "bundle-raw"},
        "mbcp_version": "0.1",
        "records": list(records),
        "tombstones": list(tombstones),
    }


def test_sc_schema_01_unknown_fields_pass_through_and_are_retained():
    record = syn_record("rec-u", "body")
    record["x_custom"] = {"anything": True}
    record["scope"]["x_team"] = "blue"
    records = load([_raw_bundle(records=[record])])
    assert records[0]["x_custom"] == {"anything": True}
    assert records[0]["scope"]["x_team"] == "blue"


def test_sc_schema_01_missing_required_field_raises_validation_error():
    record = syn_record("rec-m", "body")
    del record["mbcp"]
    assert_raises(LoadValidationError, load, [_raw_bundle(records=[record])])


def test_sc_schema_01_bad_digest_format_raises_validation_error():
    record = syn_record("rec-d", "body")
    record["integrity"]["digest"] = "not-a-digest"
    assert_raises(LoadValidationError, load, [_raw_bundle(records=[record])])


def test_sc_schema_01_bad_enum_value_raises_validation_error():
    record = syn_record("rec-e", "body")
    record["mbcp"]["load_policy"]["priority"] = "urgent!"
    assert_raises(LoadValidationError, load, [_raw_bundle(records=[record])])


def test_sc_schema_01_malformed_manifest_raises_validation_error():
    assert_raises(LoadValidationError, load, [{"records": []}])
    assert_raises(
        LoadValidationError,
        load,
        [{"bundle": {"id": "b"}, "records": {"not": "a list"}, "tombstones": []}],
    )
    assert_raises(LoadValidationError, load, ["not a manifest"])


def test_build_bundle_emits_all_four_manifest_keys():
    # SPEC 1.5 build-path manifest: bundle, mbcp_version, records,
    # tombstones — emitted even when both lists are empty.
    manifest = build_bundle("bundle-keys")
    assert set(manifest) == {"bundle", "mbcp_version", "records", "tombstones"}
    assert manifest["records"] == []
    assert manifest["tombstones"] == []
    validate_bundle(manifest)  # build path accepts its own output


def test_build_path_requires_records_and_tombstones_keys():
    # SPEC 1.5: missing key is a build-path error (strict schema).
    # _schema.ValidationError is a ValueError; assert the shared base.
    manifest = _raw_bundle()
    del manifest["records"]
    assert_raises(ValueError, validate_bundle, manifest)
    manifest = _raw_bundle()
    del manifest["tombstones"]
    assert_raises(ValueError, validate_bundle, manifest)
    manifest = _raw_bundle()
    del manifest["records"]
    del manifest["tombstones"]
    assert_raises(ValueError, validate_bundle, manifest)


def test_load_path_tolerates_missing_records_and_tombstones_keys():
    # SPEC 1.5 asymmetry, load side: missing keys are treated as empty
    # lists — tolerant reader, NO error.
    record = syn_record("rec-tol", "body")
    manifest = _raw_bundle(records=[record])
    del manifest["tombstones"]
    assert [r["id"] for r in load([manifest])] == ["rec-tol"]
    manifest = _raw_bundle()
    del manifest["records"]
    assert load([manifest]) == []
    manifest = _raw_bundle()
    del manifest["records"]
    del manifest["tombstones"]
    assert load([manifest]) == []


def _raw_tombstone(**overrides):
    tombstone = {
        "target_id": "rec-x",
        "deleted_at": "2026-06-01T00:00:00Z",
        "reason": "erased",
        "derived_artifacts": [],
    }
    tombstone.update(overrides)
    return tombstone


def test_sc_schema_01_tombstone_unparseable_deleted_at_raises():
    # A-15 (SPEC 1.2): deleted_at must parse as RFC3339 with timezone info
    tombstone = _raw_tombstone(deleted_at="not-a-timestamp")
    assert_raises(LoadValidationError, load, [_raw_bundle(tombstones=[tombstone])])


def test_sc_schema_01_tombstone_naive_deleted_at_raises():
    # A-15 (SPEC 1.2): a timestamp WITHOUT a timezone offset is rejected
    tombstone = _raw_tombstone(deleted_at="2026-06-01T00:00:00")
    assert_raises(LoadValidationError, load, [_raw_bundle(tombstones=[tombstone])])


def test_sc_schema_01_tombstone_valid_offset_timestamps_pass():
    for ts in (
        "2026-06-01T00:00:00Z",
        "2026-06-01T08:00:00+08:00",
        "2026-06-01T10:20:30.5-05:30",
    ):
        tombstone = _raw_tombstone(deleted_at=ts)
        assert load([_raw_bundle(tombstones=[tombstone])]) == []


def test_sc_schema_01_build_path_rejects_bad_deleted_at():
    # A-15: the build path rejects naive/unparseable deleted_at too. The
    # schema's own format=date-time check fires first (ValidationError, a
    # ValueError); assert the shared ValueError base.
    assert_raises(
        ValueError, make_tombstone, "rec-x", "erased",
        deleted_at="not-a-timestamp",
    )
    assert_raises(
        ValueError, make_tombstone, "rec-x", "erased",
        deleted_at="2026-06-01T00:00:00",
    )


def test_sc_schema_01_build_path_accepts_offset_timestamps():
    for ts in ("2026-06-01T00:00:00Z", "2026-06-01T08:00:00+08:00"):
        tombstone = make_tombstone("rec-x", "erased", deleted_at=ts)
        assert tombstone["deleted_at"] == ts


# ---------------------------------------------------------------------------
# max_chars floor (SPEC 1.5, v0.1 audit §8, M4 round C1): 0 or negative
# max_chars is rejected on BOTH paths — a hostile record can no longer
# zero out an entire priority class.
# ---------------------------------------------------------------------------


def test_max_chars_zero_or_negative_rejected_on_load():
    for bad in (0, -1, -4096):
        # tamper a valid record: the build path would refuse max_chars<1,
        # so construct the hostile producer manifest by hand
        record = syn_record("rec-budget", "body")
        record["mbcp"]["load_policy"]["max_chars"] = bad
        assert_raises(
            LoadValidationError, load, [_raw_bundle(records=[record])]
        ), bad


def test_max_chars_zero_or_negative_rejected_on_build():
    from mbcp import _schema

    for bad in (0, -1):
        record = syn_record("rec-budget", "body")
        record["mbcp"]["load_policy"]["max_chars"] = bad
        assert_raises(_schema.ValidationError, validate_record, record), bad
        assert_raises(
            _schema.ValidationError,
            build_bundle,
            "bundle-budget",
            records=[record],
        ), bad


def test_max_chars_one_is_the_new_floor():
    record = syn_record("rec-min", "x", max_chars=1)
    manifest = _raw_bundle(records=[record])
    (loaded,) = load([manifest])
    assert loaded["id"] == "rec-min"


# ---------------------------------------------------------------------------
# Record-id grammar (SPEC 1.5, v0.1 audit §12, M4 round C1): record ids
# carry the id grammar on both paths. JUDGMENT CALL (Round C1): the
# enforced class is ^[A-Za-z0-9._:-]{1,128}$ — the SPEC class plus ':' —
# because the shipped chatgpt importer's ids are "chatgpt:<...>" and
# importers/ is outside this batch's change set. CJK/space/slash and all
# other non-ASCII characters are rejected on both paths.
# ---------------------------------------------------------------------------


def test_record_id_grammar_rejected_on_load():
    for bad in ("team/a", "team a", "café", "記憶", "..", "a..b", "a" * 129, ""):
        record = syn_record("placeholder", "body")
        record["id"] = bad
        assert_raises(
            LoadValidationError, load, [_raw_bundle(records=[record])]
        ), bad


def test_record_id_grammar_rejected_on_build():
    from mbcp import _schema

    for bad in ("team/a", "team a", "café", "記憶", "..", "a..b", "a" * 129, ""):
        record = syn_record("placeholder", "body")
        record["id"] = bad
        assert_raises(_schema.ValidationError, validate_record, record), bad
        assert_raises(
            _schema.ValidationError,
            build_bundle,
            "bundle-idg",
            records=[record],
        ), bad


def test_record_id_grammar_valid_ids_both_paths():
    from mbcp import _schema

    for good in ("a", "A-Z_a.z-0", "x" * 128, "chatgpt:conv-alpha"):
        record = syn_record(good, "body")
        validate_record(record)
        manifest = build_bundle("bundle-idg", records=[record])
        validate_bundle(manifest)
        (loaded,) = load([_raw_bundle(records=[record])])
        assert loaded["id"] == good
