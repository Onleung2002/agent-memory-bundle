#!/usr/bin/env python3
"""SC-SUITE-01: versioned conformance scenarios, public API only.

Executes every tests/scenarios/*.yaml against the public MBCP API
(`mbcp.load`, `mbcp.import_bundle`, `mbcp.canonical_bytes`) — no white-box
imports — and checks the deterministic expected outcome.

Scenario files are YAML 1.2 documents in JSON syntax (JSON is a subset of
YAML 1.2), so the runner stays pure-stdlib. Format:

    {
      "id": "DEL-01",
      "spec_version": "0.1",
      "title": "...",
      "op": "load" | "import",          # default "load"
      "input": {"bundles": [...]},      # load
      "input": {"store": {...}, "bundle": {...}},   # import
      "expect": {
        "error": null | "ExceptionName",
        "record_ids": [...],            # exact ordered ids (both ops)
        "bodies": {"id": "..."},        # exact body per id (load)
        "digests_valid": true,          # every digest matches its body (load)
        "digests": {"id": "hex..."},    # explicit expected digest per id (load)
        "truncated": ["id"],            # ids marked integrity.truncated (load)
        "tombstones": [{...}],          # import
        "compare": ["k", ...]           # tombstone keys to compare (import,
                                        # SPEC 3 A-05: declared keys only)
      }
    }

    {
      "id": "PRP-01",
      "title": "cross-root propagation removes a stale destination copy",
      "op": "propagate",
      "input": {
        "source_bundles": [...],   # manifests put_bundle'd into the source root
        "dest_bundles": [...],     # manifests put_bundle'd into the dest root
        "delete": [{"bundle_id": "...", "target_id": "...", "reason": "..."}],
        "export_targets": [...],   # optional target_id filter for the pack
        "tamper": "first-tombstone-reason"  # optional forgery injection
      },
      "expect": {
        "error": "PackValidationError",   # optional: import must fail this way
        "dest_record_ids": [...],  # load() of dest manifests after import
        "journal_status": "acked"  # optional: last propagation.jsonl status
      }
    }

    {
      "id": "DEL-07",
      "title": "receipt supersession: under-report retry re-issues a chain tail",
      "op": "supersede",
      "input": {
        "bundles": [...],       # manifests put_bundle'd into a fresh root
        "delete": {"bundle_id": "...", "target_id": "...", "reason": "..."},
        "resurrect": [...]      # manifests put AFTER the delete (novel
                                # digest), then recover() grows the log
      },
      "expect": {
        "first_receipt_ok": false,      # original receipt under-reports
        "tail_ok": true,                # re-issued chain tail verifies ok
        "old_receipt_ok": false,        # superseded receipt stays ok:false
        "final_receipt_count": 2        # no-growth retries add nothing
      }
    }

The supersede op builds one real service root in a temp dir with a fixed
clock, runs the supersession story delete -> resurrect -> recover ->
retry through the public API, and checks the chain semantics end to end.

The propagate op builds two real service roots in a temp dir (a pure-data
scenario cannot express two roots), runs the deletes on the source, exports
a propagation pack, imports it into the destination, then re-reads the
destination manifests and load()s them — all through the public API.
"""

import hashlib
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from mbcp import (  # public API only
    L1DeletionService,
    canonical_bytes,
    export_propagation_pack,
    import_bundle,
    import_propagation_pack,
    load,
    read_propagation_journal,
)

SCENARIO_DIR = REPO_ROOT / "tests" / "scenarios"


def _body_digest(body):
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _check_load(scenario, expect):
    failures = []
    try:
        records = load(scenario["input"]["bundles"])
    except Exception as err:  # noqa: BLE001
        if expect.get("error") == type(err).__name__:
            return []
        return [f"unexpected {type(err).__name__}: {err}"]
    if expect.get("error"):
        return [f"expected error {expect['error']}, none raised"]

    ids = [r["id"] for r in records]
    if "record_ids" in expect and ids != expect["record_ids"]:
        failures.append(f"record_ids: want {expect['record_ids']}, got {ids}")

    by_id = {r["id"]: r for r in records}
    for rid, body in expect.get("bodies", {}).items():
        got = by_id.get(rid, {}).get("body")
        if got != body:
            failures.append(f"body[{rid}]: want {body!r}, got {got!r}")

    if expect.get("digests_valid"):
        for r in records:
            if _body_digest(r["body"]) != r["integrity"]["digest"]:
                failures.append(f"{r['id']}: digest does not match body")

    # explicit per-id expected digests (raw-UTF8 canonical bytes, SPEC 1.4)
    for rid, want_hex in expect.get("digests", {}).items():
        got_hex = by_id.get(rid, {}).get("integrity", {}).get("digest")
        if got_hex != want_hex:
            failures.append(f"digest[{rid}]: want {want_hex}, got {got_hex}")

    if "truncated" in expect:
        want = set(expect["truncated"])
        for r in records:
            marked = bool(r["integrity"].get("truncated", False))
            if marked != (r["id"] in want):
                failures.append(
                    f"{r['id']}: truncated mark {marked}, want {r['id'] in want}"
                )
    return failures


def _check_import(scenario, expect):
    failures = []
    try:
        merged = import_bundle(scenario["input"]["store"], scenario["input"]["bundle"])
    except Exception as err:  # noqa: BLE001
        if expect.get("error") == type(err).__name__:
            return []
        return [f"unexpected {type(err).__name__}: {err}"]
    if expect.get("error"):
        return [f"expected error {expect['error']}, none raised"]

    if "record_ids" in expect:
        ids = [r["id"] for r in merged["records"]]
        if ids != expect["record_ids"]:
            failures.append(f"record_ids: want {expect['record_ids']}, got {ids}")

    if "tombstones" in expect:
        # SPEC 3 (A-05): tombstones compare ONLY on the keys declared in
        # the scenario's explicit "compare" list — no implicit subset match.
        compare = expect.get("compare")
        if not compare:
            failures.append(
                "tombstones: scenario must declare an explicit compare key list"
            )
        else:
            def _project(t, side):
                proj = {}
                for k in compare:
                    if k not in t:
                        failures.append(
                            f"tombstones: {side} tombstone missing "
                            f"compare key {k!r}"
                        )
                        continue
                    proj[k] = t[k]
                if "derived_artifacts" in proj:
                    proj["derived_artifacts"] = sorted(proj["derived_artifacts"])
                return proj

            got = [_project(t, "got") for t in merged["tombstones"]]
            want = [_project(e, "expected") for e in expect["tombstones"]]
            if got != want:
                failures.append(f"tombstones: want {want}, got {got}")
    return failures


def _check_propagate(scenario, expect):
    """Cross-root story: source deletes -> export pack -> dest imports.

    Two real service roots in a temp dir (a pure-data scenario cannot hold
    two roots); everything runs through the public API with a fixed clock
    so the run is deterministic.
    """
    failures = []
    fixed_now = "2026-11-06T00:00:00Z"
    with tempfile.TemporaryDirectory() as tmp:
        source = L1DeletionService(
            Path(tmp) / "source", clock=lambda: fixed_now
        )
        dest = L1DeletionService(Path(tmp) / "dest", clock=lambda: fixed_now)
        for manifest in scenario["input"].get("source_bundles", []):
            source.put_bundle(manifest)
        dest_ids = []
        for manifest in scenario["input"].get("dest_bundles", []):
            dest.put_bundle(manifest)
            dest_ids.append(manifest["bundle"]["id"])

        try:
            for deletion in scenario["input"].get("delete", []):
                source.delete(
                    deletion["bundle_id"],
                    deletion["target_id"],
                    deletion["reason"],
                )
            pack = export_propagation_pack(
                source,
                scenario["input"].get("export_targets") or None,
                source_root="root-source-scenario",
                now=fixed_now,
            )
            if scenario["input"].get("tamper") == "first-tombstone-reason":
                pack["pack"]["tombstones"][0]["reason"] += " (tampered)"
            import_propagation_pack(dest.root, pack, now=fixed_now)
        except Exception as err:  # noqa: BLE001
            if expect.get("error") != type(err).__name__:
                return [f"unexpected {type(err).__name__}: {err}"]
        else:
            if expect.get("error"):
                return [f"expected error {expect['error']}, none raised"]

        if "dest_record_ids" in expect:
            try:
                records = load([dest.get_bundle(bid) for bid in dest_ids])
            except Exception as err:  # noqa: BLE001
                return [f"dest load failed: {type(err).__name__}: {err}"]
            ids = [r["id"] for r in records]
            if ids != expect["dest_record_ids"]:
                failures.append(
                    f"dest_record_ids: want {expect['dest_record_ids']}, got {ids}"
                )

        if "journal_status" in expect:
            entries = read_propagation_journal(dest.root)
            got = entries[-1]["status"] if entries else None
            if got != expect["journal_status"]:
                failures.append(
                    f"journal_status: want {expect['journal_status']!r}, got {got!r}"
                )
    return failures


def _put_resurrect_bundle(service, manifest):
    """Land a resurrection manifest OUT-OF-BAND (write bundles/ directly).

    Since M4 round C1 (SPEC 1.2 write boundary, audit §6), put_bundle
    rejects any copy of a journal-tombstoned id — which is exactly what a
    supersede/regen "resurrect" bundle carries. The scenario stories model
    a producer bypassing the write boundary (the documented legacy/attack
    channel that delete()/recover() heal), so the runner lands these
    manifests through that same channel, byte-identical to put_bundle's
    write (canonical bytes at bundle_path).
    """
    path = service.bundle_path(manifest["bundle"]["id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(manifest))


def _check_supersede(scenario, expect):
    """Receipt supersession story (SPEC 1.2.2): delete -> recovery growth
    makes the first receipt under-report -> delete() retry re-issues a
    superseding chain-tail receipt covering every known removal, and the
    superseded receipt stays ok:false forever.

    One real service root in a temp dir with a fixed clock, public API
    only — a pure-data scenario cannot express recovery-driven growth.
    """
    failures = []
    fixed_now = "2026-11-06T00:00:00Z"
    inp = scenario["input"]
    deletion = inp["delete"]
    args = (deletion["bundle_id"], deletion["target_id"], deletion["reason"])
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(
            Path(tmp) / "root", clock=lambda: fixed_now
        )
        for manifest in inp.get("bundles", []):
            service.put_bundle(manifest)
        first = service.delete(*args)
        for manifest in inp.get("resurrect", []):
            # UPDATED-PIN (M4 round C1): resurrection bypasses the write
            # boundary, exactly like the legacy/attack producer it models.
            _put_resurrect_bundle(service, manifest)
        if inp.get("recover"):
            service.recover()

        if "first_receipt_ok" in expect:
            check = service.verify_receipt(first)
            if check["ok"] != expect["first_receipt_ok"]:
                failures.append(
                    f"first receipt ok={check['ok']}, want "
                    f"{expect['first_receipt_ok']}: {check['problems']}"
                )

        retried = service.delete(*args)
        if expect.get("supersedes"):
            link = retried["receipt"].get("supersedes")
            if link != first["integrity"]["digest"]:
                failures.append(
                    f"re-issued receipt supersedes {link!r}, want "
                    f"{first['integrity']['digest']!r}"
                )
        if "tail_ok" in expect:
            check = service.verify_receipt(retried)
            if check["ok"] != expect["tail_ok"]:
                failures.append(
                    f"chain tail ok={check['ok']}, want "
                    f"{expect['tail_ok']}: {check['problems']}"
                )
        if "old_receipt_ok" in expect:
            check = service.verify_receipt(first)
            if check["ok"] != expect["old_receipt_ok"]:
                failures.append(
                    f"superseded receipt ok={check['ok']}, want "
                    f"{expect['old_receipt_ok']} (whitewash)"
                )

        # a no-growth retry must return the chain tail and write nothing
        again = service.delete(*args)
        if "final_receipt_count" in expect:
            count = len(service.receipt_paths())
            if count != expect["final_receipt_count"]:
                failures.append(
                    f"receipt count {count}, want "
                    f"{expect['final_receipt_count']}"
                )
        if again != retried:
            failures.append("no-growth retry returned a different receipt")
    return failures


def _check_regen(scenario, expect):
    """Two tombstone generations for one target (adversarial audit HIGH#1,
    Repro A): delete -> the target resurrects with a DIFFERENT digest ->
    re-delete naming a new derived artifact splits the tombstone
    generation. The second receipt must account the UNION of real removals
    across BOTH generations (never the stale copy alone), verify ok, and
    leave the first receipt's file on disk (its digest differs now that
    the receipt id preimage binds the tombstone digest).
    """
    failures = []
    fixed_now = "2026-11-06T00:00:00Z"
    inp = scenario["input"]
    deletion = inp["delete"]
    args = (deletion["bundle_id"], deletion["target_id"], deletion["reason"])
    with tempfile.TemporaryDirectory() as tmp:
        service = L1DeletionService(
            Path(tmp) / "root", clock=lambda: fixed_now
        )
        for manifest in inp.get("bundles", []):
            service.put_bundle(manifest)
        first = service.delete(*args)
        first_digest = first["receipt"]["removed_records"][0]["digest"]
        for manifest in inp.get("resurrect", []):
            # UPDATED-PIN (M4 round C1): resurrection bypasses the write
            # boundary, exactly like the legacy/attack producer it models.
            _put_resurrect_bundle(service, manifest)
        second = service.delete(
            *args, derived_artifacts=inp.get("new_artifacts", [])
        )

        if "receipt_ok" in expect:
            check = service.verify_receipt(second)
            if check["ok"] != expect["receipt_ok"]:
                failures.append(
                    f"second receipt ok={check['ok']}, want "
                    f"{expect['receipt_ok']}: {check['problems']}"
                )
        claimed = sorted(
            r["digest"] for r in second["receipt"]["removed_records"]
        )
        if "removed_digests" in expect and claimed != expect["removed_digests"]:
            failures.append(
                f"removed_digests: want {expect['removed_digests']}, got {claimed}"
            )
        if expect.get("names_first_removal") and first_digest not in claimed:
            failures.append(
                "second receipt dropped the first deletion's digest "
                "(union accounting broken)"
            )
        if "journal_generations" in expect:
            count = len(service.journal_tombstones())
            if count != expect["journal_generations"]:
                failures.append(
                    f"journal generations {count}, want "
                    f"{expect['journal_generations']}"
                )
        if "receipt_files" in expect:
            count = len(service.receipt_paths())
            if count != expect["receipt_files"]:
                failures.append(
                    f"receipt files {count}, want {expect['receipt_files']}"
                )
    return failures


def main():
    files = sorted(SCENARIO_DIR.glob("*.yaml"))
    if not files:
        print(f"no scenarios found in {SCENARIO_DIR}", file=sys.stderr)
        return 1
    passed = failed = 0
    for path in files:
        scenario = json.loads(path.read_text(encoding="utf-8"))
        op = scenario.get("op", "load")
        checker = {
            "import": _check_import,
            "propagate": _check_propagate,
            "supersede": _check_supersede,
            "regen": _check_regen,
        }.get(op, _check_load)
        failures = checker(scenario, scenario.get("expect", {}))
        if failures:
            failed += 1
            print(f"FAIL {scenario['id']} ({path.name})")
            for line in failures:
                print(f"  - {line}")
        else:
            passed += 1
            print(f"PASS {scenario['id']} ({path.name})")
    print(f"\n{passed} passed, {failed} failed ({len(files)} scenarios)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
