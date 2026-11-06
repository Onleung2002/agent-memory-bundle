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
        "truncated": ["id"],            # ids marked integrity.truncated (load)
        "tombstones": [{"target_id", "reason", "derived_artifacts"}]  # import
      }
    }
"""

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from mbcp import canonical_bytes, import_bundle, load  # public API only

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
        got = [
            {
                "target_id": t["target_id"],
                "reason": t["reason"],
                "derived_artifacts": sorted(t["derived_artifacts"]),
            }
            for t in merged["tombstones"]
        ]
        want = [
            {**e, "derived_artifacts": sorted(e["derived_artifacts"])}
            for e in expect["tombstones"]
        ]
        if got != want:
            failures.append(f"tombstones: want {want}, got {got}")
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
        checker = _check_import if op == "import" else _check_load
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
