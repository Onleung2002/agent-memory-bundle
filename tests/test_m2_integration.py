"""M2 integration: importer -> bundle -> L1 deletion -> load.

These tests exercise the seam between components, not each unit in
isolation: the point is that a deletion performed through the L1 service
survives a *re-import of the stale export*.
"""

import tempfile
from pathlib import Path

from m2_helpers import (
    CHATGPT_EXPORT,
    DELETED_AT,
    HERMES_PROFILE,
    IMPORTED_AT,
    OWNER,
)

from importers import chatgpt, hermes
from mbcp import L1DeletionService, import_bundle, load


def _chatgpt_bundle(*, tombstones):
    return chatgpt.build_import_bundle(
        CHATGPT_EXPORT,
        owner=OWNER,
        imported_at=IMPORTED_AT,
        tombstones=tombstones,
    )


def _hermes_bundle(*, tombstones):
    return hermes.build_import_bundle(
        HERMES_PROFILE,
        owner=OWNER,
        imported_at=IMPORTED_AT,
        default_created=IMPORTED_AT,
        tombstones=tombstones,
    )


def test_chatgpt_export_delete_receipt_load_pipeline():
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(Path(tmp) / "svc", clock=lambda: DELETED_AT)
        service.put_bundle(_chatgpt_bundle(tombstones=[]))

        receipt = service.delete(
            "chatgpt-export",
            "chatgpt:conv-alpha",
            "synthetic erasure request",
            derived_artifacts=["chunk:conv-alpha:0"],
        )

        assert service.verify_receipt(receipt)["ok"] is True
        ids = [r["id"] for r in load([service.get_bundle("chatgpt-export")])]
        assert ids == ["chatgpt:conv-beta"], ids
        assert receipt["receipt"]["removed_records"][0]["id"] == "chatgpt:conv-alpha"


def test_hermes_profile_delete_receipt_load_pipeline():
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(Path(tmp) / "svc", clock=lambda: DELETED_AT)
        bundle = _hermes_bundle(tombstones=[])
        service.put_bundle(bundle)
        target = next(r["id"] for r in bundle["records"] if r["kind"] == "preference")

        receipt = service.delete("hermes-profile", target, "synthetic erasure request")

        assert service.verify_receipt(receipt)["ok"] is True
        ids = [r["id"] for r in load([service.get_bundle("hermes-profile")])]
        assert target not in ids
        assert len(ids) == len(bundle["records"]) - 1


def test_stale_chatgpt_reimport_cannot_resurrect_deleted_record():
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(Path(tmp) / "svc", clock=lambda: DELETED_AT)
        service.put_bundle(_chatgpt_bundle(tombstones=[]))
        service.delete("chatgpt-export", "chatgpt:conv-alpha", "synthetic erasure")

        store = import_bundle({"records": [], "tombstones": []}, _chatgpt_bundle(tombstones=[]))
        assert "chatgpt:conv-alpha" in [r["id"] for r in store["records"]]

        # re-import the STALE export, carrying the service's tombstones
        stale = _chatgpt_bundle(tombstones=service.all_tombstones())
        merged = import_bundle(store, stale)

        ids = [r["id"] for r in merged["records"]]
        assert ids == ["chatgpt:conv-beta"], ids
        assert "chatgpt:conv-alpha" in [t["target_id"] for t in merged["tombstones"]]


def test_importer_without_tombstones_resurrects_hermes_entry():
    # Contract test: importers are stateless parsers. Deleting a memory entry
    # then re-importing the *same profile* without the service journal WILL
    # bring it back — the caller must pass service.all_tombstones().
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(Path(tmp) / "svc", clock=lambda: DELETED_AT)
        bundle = _hermes_bundle(tombstones=[])
        service.put_bundle(bundle)
        target = bundle["records"][0]["id"]
        service.delete("hermes-profile", target, "synthetic erasure")

        naive = import_bundle({"records": [], "tombstones": []}, _hermes_bundle(tombstones=[]))
        assert target in [r["id"] for r in naive["records"]]

        guarded = import_bundle(
            {"records": [], "tombstones": []},
            _hermes_bundle(tombstones=service.all_tombstones()),
        )
        assert target not in [r["id"] for r in guarded["records"]]


def test_hermes_content_addressed_id_survives_entry_reordering():
    # Move a deleted entry to the end of MEMORY.md: the content id is stable,
    # so the tombstone still matches and the entry stays deleted.
    with tempfile.TemporaryDirectory() as tmp:
        profile = Path(tmp) / "profile"
        import shutil

        shutil.copytree(HERMES_PROFILE, profile)
        memory = profile / "memories" / "MEMORY.md"
        entries = [
            entry.strip()
            for entry in memory.read_text(encoding="utf-8").split("§")
            if entry.strip()
        ]
        reversed_text = "\n§\n".join(reversed(entries))
        memory.write_text(reversed_text, encoding="utf-8")

        service = L1DeletionService(Path(tmp) / "svc", clock=lambda: DELETED_AT)
        original = hermes.build_import_bundle(
            HERMES_PROFILE,
            owner=OWNER,
            imported_at=IMPORTED_AT,
            default_created=IMPORTED_AT,
            tombstones=[],
        )
        service.put_bundle(original)
        target = next(r["id"] for r in original["records"] if r["kind"] == "fact")
        service.delete("hermes-profile", target, "synthetic erasure")

        reordered = hermes.build_import_bundle(
            profile,
            owner=OWNER,
            imported_at=IMPORTED_AT,
            default_created=IMPORTED_AT,
            tombstones=service.all_tombstones(),
        )
        merged = import_bundle({"records": [], "tombstones": []}, reordered)
        assert target not in [r["id"] for r in merged["records"]]


def test_load_across_both_bundles_after_one_deletion():
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(Path(tmp) / "svc", clock=lambda: DELETED_AT)
        service.put_bundle(_chatgpt_bundle(tombstones=[]))
        service.put_bundle(_hermes_bundle(tombstones=[]))
        service.delete("chatgpt-export", "chatgpt:conv-alpha", "synthetic erasure")

        loaded = load(
            [
                service.get_bundle("chatgpt-export"),
                service.get_bundle("hermes-profile"),
            ]
        )
        ids = {r["id"] for r in loaded}
        assert "chatgpt:conv-alpha" not in ids
        assert "chatgpt:conv-beta" in ids
        assert any(r["kind"] == "preference" for r in loaded)
        assert any(r["kind"] == "fact" for r in loaded)


def test_receipt_verifies_after_service_restart():
    with tempfile.TemporaryDirectory() as tmp:
        first = L1DeletionService(Path(tmp) / "svc", clock=lambda: DELETED_AT)
        first.put_bundle(_chatgpt_bundle(tombstones=[]))
        receipt = first.delete(
            "chatgpt-export", "chatgpt:conv-alpha", "synthetic erasure request"
        )

        restarted = L1DeletionService(Path(tmp) / "svc")
        result = restarted.verify_receipt(receipt)
        assert result["ok"] is True, result
