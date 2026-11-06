"""Hermes profile importer: entry splitting, ids, sessions, defaults."""

import tempfile
from pathlib import Path

from m2_helpers import HERMES_PROFILE, IMPORTED_AT, OWNER, copy_profile

from importers import hermes
from mbcp import canonical_bytes, import_bundle, validate_record

from syn import assert_raises


def _records(**kwargs):
    kwargs.setdefault("owner", OWNER)
    kwargs.setdefault("imported_at", IMPORTED_AT)
    kwargs.setdefault("default_created", IMPORTED_AT)
    return hermes.parse_profile(HERMES_PROFILE, **kwargs)


def test_split_memory_entries_on_section_delimiter():
    entries = hermes.split_memory_entries("alpha\n§\nbeta\n§\n\ngamma\n")
    assert entries == ["alpha", "beta", "gamma"], entries


def test_split_memory_entries_without_delimiter_is_one_entry():
    assert hermes.split_memory_entries("single entry\n") == ["single entry"]


def test_parse_profile_dedupes_identical_entries():
    records = _records()
    # fixture: 8 raw entries (one duplicate) -> 7 records
    assert len(records) == 7, [r["id"] for r in records]
    ids = [r["id"] for r in records]
    assert len(ids) == len(set(ids))


def test_user_md_maps_to_critical_preference_records():
    prefs = [r for r in _records() if r["kind"] == "preference"]
    assert len(prefs) == 2
    for record in prefs:
        policy = record["mbcp"]["load_policy"]
        assert policy["priority"] == "critical"
        assert record["provenance"]["file"] == "memories/USER.md"


def test_memory_md_maps_to_standard_fact_records():
    facts = [r for r in _records() if r["kind"] == "fact"]
    assert len(facts) == 3
    for record in facts:
        assert record["mbcp"]["load_policy"]["priority"] == "standard"
        assert record["provenance"]["file"] == "memories/MEMORY.md"


def test_memory_ids_are_content_addressed_and_stable_across_relocation():
    with tempfile.TemporaryDirectory() as tmp:
        relocated = copy_profile(Path(tmp) / "different-directory-name")
        moved = hermes.parse_profile(
            relocated,
            owner=OWNER,
            imported_at=IMPORTED_AT,
            default_created=IMPORTED_AT,
        )
    assert [r["id"] for r in moved] == [r["id"] for r in _records()]


def test_profile_without_consent_is_not_exportable_and_private():
    for record in _records():
        assert record["consent"] == {"exportable": False}
        assert record["provenance"]["sensitivity"] == "private"
        assert record["provenance"]["importer"] == "hermes"


def test_multiline_memory_entry_body_preserved():
    bodies = [r["body"] for r in _records() if r["kind"] == "preference"]
    multiline = [body for body in bodies if "\n" in body]
    assert len(multiline) == 1
    assert "Second synthetic line in the same entry." in multiline[0]


def test_json_session_parsed_and_scaffolding_dropped():
    sessions = [r for r in _records() if r["id"] == "hermes-sess:sess-001"]
    assert len(sessions) == 1
    body = sessions[0]["body"]
    assert "Synthetic session question" in body
    assert "Synthetic session answer." in body
    assert "Second synthetic block." in body
    assert "scaffolding" not in body
    assert "tool output" not in body
    assert body.startswith("user: ")


def test_jsonl_session_uses_first_message_timestamp():
    sessions = [r for r in _records() if r["id"] == "hermes-sess:sess-002"]
    assert len(sessions) == 1
    assert sessions[0]["time"]["created"] == "2026-02-03T04:05:06Z"


def test_include_sessions_false_drops_conversations():
    records = _records(include_sessions=False)
    assert all(r["kind"] != "conversation" for r in records)
    assert len(records) == 5


def test_built_bundle_is_schema_valid_and_sorted():
    bundle = hermes.build_import_bundle(
        HERMES_PROFILE,
        owner=OWNER,
        imported_at=IMPORTED_AT,
        default_created=IMPORTED_AT,
    )
    ids = [record["id"] for record in bundle["records"]]
    assert ids == sorted(ids)
    for record in bundle["records"]:
        validate_record(record)


def test_parse_profile_is_deterministic_bytes():
    first = hermes.build_import_bundle(
        HERMES_PROFILE, owner=OWNER, imported_at=IMPORTED_AT
    )
    second = hermes.build_import_bundle(
        HERMES_PROFILE, owner=OWNER, imported_at=IMPORTED_AT
    )
    assert canonical_bytes(first) == canonical_bytes(second)


def test_malformed_session_json_raises_import_format_error():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "broken-profile"
        (root / "sessions").mkdir(parents=True)
        (root / "memories").mkdir()
        (root / "sessions" / "bad.json").write_text("{not json", encoding="utf-8")
        assert_raises(
            hermes.ImportFormatError, hermes.parse_profile, root, owner=OWNER
        )


def test_non_profile_directory_raises_import_format_error():
    with tempfile.TemporaryDirectory() as tmp:
        assert_raises(
            hermes.ImportFormatError, hermes.parse_profile, tmp, owner=OWNER
        )


def test_import_profile_is_tombstone_first():
    bundle = hermes.build_import_bundle(
        HERMES_PROFILE,
        owner=OWNER,
        imported_at=IMPORTED_AT,
        default_created=IMPORTED_AT,
    )
    target = bundle["records"][0]["id"]
    bundle["tombstones"] = [
        {
            "target_id": target,
            "deleted_at": IMPORTED_AT,
            "reason": "synthetic erasure",
            "derived_artifacts": ["emb:" + target],
        }
    ]
    merged = import_bundle({"records": [], "tombstones": []}, bundle)
    assert target not in [r["id"] for r in merged["records"]]
    assert target in [t["target_id"] for t in merged["tombstones"]]
