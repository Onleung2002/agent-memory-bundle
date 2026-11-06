"""ChatGPT export importer: format parsing, defaults, determinism."""

import json
import tempfile
from pathlib import Path

from m2_helpers import CHATGPT_EXPORT, IMPORTED_AT, OWNER

from importers import chatgpt
from mbcp import canonical_bytes, import_bundle, validate_record

from syn import assert_raises


def _records(**kwargs):
    kwargs.setdefault("owner", OWNER)
    kwargs.setdefault("imported_at", IMPORTED_AT)
    return chatgpt.parse_export(CHATGPT_EXPORT, **kwargs)


def test_parse_export_skips_empty_and_system_only_conversations():
    ids = [record["id"] for record in _records()]
    assert ids == ["chatgpt:conv-alpha", "chatgpt:conv-beta"], ids


def test_current_branch_preferred_over_newer_off_branch_message():
    by_id = {record["id"]: record for record in _records()}
    body = by_id["chatgpt:conv-alpha"]["body"]
    assert "Synthetic answer alpha" in body
    assert "OFF-BRANCH" not in body


def test_transcript_is_role_prefixed():
    body = {r["id"]: r for r in _records()}["chatgpt:conv-alpha"]["body"]
    assert body == "user: Synthetic question alpha\n\nassistant: Synthetic answer alpha"


def test_mapping_order_does_not_change_transcript():
    data = json.loads(
        (CHATGPT_EXPORT / "conversations.json").read_text(encoding="utf-8")
    )
    with tempfile.TemporaryDirectory() as tmp:
        reordered = []
        for conversation in data:
            clone = dict(conversation)
            clone["mapping"] = dict(reversed(list(conversation["mapping"].items())))
            reordered.append(clone)
        export = Path(tmp) / "conversations.json"
        export.write_text(json.dumps(reordered), encoding="utf-8")
        shuffled = chatgpt.parse_export(
            export, owner=OWNER, imported_at=IMPORTED_AT
        )
    original = _records()
    assert [r["body"] for r in shuffled] == [r["body"] for r in original]


def test_parse_export_is_deterministic_bytes():
    first = chatgpt.build_import_bundle(
        CHATGPT_EXPORT, owner=OWNER, imported_at=IMPORTED_AT
    )
    second = chatgpt.build_import_bundle(
        CHATGPT_EXPORT, owner=OWNER, imported_at=IMPORTED_AT
    )
    assert canonical_bytes(first) == canonical_bytes(second)


def test_multimodal_part_renders_image_pointer():
    body = {r["id"]: r for r in _records()}["chatgpt:conv-beta"]["body"]
    assert "[image:file-synthetic-001]" in body


def test_epoch_timestamps_preserve_subsecond_precision():
    by_id = {r["id"]: r for r in _records()}
    time_ = by_id["chatgpt:conv-alpha"]["time"]
    assert time_["created"] == "2025-01-01T00:00:00.25Z", time_
    assert time_["updated"] == "2025-01-01T00:06:39.75Z", time_


def test_whole_second_epoch_formats_without_fraction():
    by_id = {r["id"]: r for r in _records()}
    assert by_id["chatgpt:conv-beta"]["time"]["created"] == "2025-01-02T00:00:00Z"


def test_export_without_consent_field_is_not_exportable():
    # SPEC §4: no consent column in a ChatGPT export -> exportable false.
    for record in _records():
        assert record["consent"] == {"exportable": False}


def test_importer_marks_sensitivity_personal():
    for record in _records():
        assert record["provenance"]["sensitivity"] == "personal"
        assert record["provenance"]["importer"] == "chatgpt"
        assert record["provenance"]["source"] == "chatgpt-export"


def test_archived_conversation_maps_to_archived_lifecycle():
    by_id = {r["id"]: r for r in _records()}
    assert by_id["chatgpt:conv-beta"]["lifecycle"] == "archived"
    assert by_id["chatgpt:conv-alpha"]["lifecycle"] == "active"


def test_conversation_records_are_opportunistic_and_bounded():
    for record in _records():
        policy = record["mbcp"]["load_policy"]
        assert policy["priority"] == "opportunistic"
        assert policy["max_chars"] == 8000
        assert policy["on_budget_exceed"] == "truncate_last"


def test_built_bundle_is_schema_valid_and_id_sorted():
    bundle = chatgpt.build_import_bundle(
        CHATGPT_EXPORT, owner=OWNER, imported_at=IMPORTED_AT
    )
    ids = [record["id"] for record in bundle["records"]]
    assert ids == sorted(ids)
    for record in bundle["records"]:
        validate_record(record)


def test_find_conversations_accepts_directory_or_file():
    from_file = chatgpt.find_conversations(CHATGPT_EXPORT / "conversations.json")
    from_dir = chatgpt.find_conversations(CHATGPT_EXPORT)
    assert from_file == from_dir


def test_missing_directory_export_raises_import_format_error():
    with tempfile.TemporaryDirectory() as tmp:
        assert_raises(
            chatgpt.ImportFormatError, chatgpt.parse_export, tmp, owner=OWNER
        )


def test_non_array_export_raises_import_format_error():
    with tempfile.TemporaryDirectory() as tmp:
        export = Path(tmp) / "conversations.json"
        export.write_text('{"conversations": []}', encoding="utf-8")
        assert_raises(
            chatgpt.ImportFormatError, chatgpt.parse_export, tmp, owner=OWNER
        )


def test_import_export_is_tombstone_first():
    # Deletion wins even though the stale export still contains the record.
    bundle = chatgpt.build_import_bundle(
        CHATGPT_EXPORT,
        owner=OWNER,
        imported_at=IMPORTED_AT,
        tombstones=[
            {
                "target_id": "chatgpt:conv-alpha",
                "deleted_at": IMPORTED_AT,
                "reason": "synthetic erasure",
                "derived_artifacts": [],
            }
        ],
    )
    merged = import_bundle({"records": [], "tombstones": []}, bundle)
    ids = [record["id"] for record in merged["records"]]
    assert ids == ["chatgpt:conv-beta"], ids
