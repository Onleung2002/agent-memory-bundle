"""SC-SCHEMA-01: load-time validation — unknown fields pass through,
malformed structure/digests raise LoadValidationError (never KeyError)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import LoadValidationError, load

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
