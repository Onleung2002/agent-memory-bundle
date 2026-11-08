#!/usr/bin/env python3
"""Generate a conformance registry record (docs/registry/<slug>-<commit[:12]>.json).

Pure stdlib. Nothing in the record is hand-filled:

  spec.spec_commit         <- git rev-parse HEAD
  spec.record_generated_at <- git log -1 --format=%cI (RFC3339, tz-aware)
  suite.*                  <- actually running tools/run_tests.py and
                              tools/run_scenarios.py and parsing their
                              summary lines; generation REFUSES to proceed
                              unless both suites are fully green (fail_set
                              would be non-empty, and a red suite must never
                              enter the registry).

Everything attestation-related comes from CLI flags (see --help). Writes the
machine-readable JSON plus a human-readable markdown rendering next to it.

Usage (home record, run from repo root):

  python3 tools/make_registry_record.py \
      --impl-slug mbcp --name "mbcp" --version 0.1.0 --producer home \
      --repo-url https://github.com/Onleung2002/agent-memory-bundle \
      --kind verifier-attested \
      --verifier "GLM independent verification session" \
      --method "independent adversarial audit + mutation-verified verification rounds, replayed against the public suite" \
      --evidence-ref "docs/AUDIT_2026-11-08.md + docs/MILESTONE_M3.md §5a"

The record is validated against schemas/conformance-record.v0.json before
writing; the anti-drift pin in tests/test_registry.py re-checks every record
in docs/registry/ on every test run.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_DIR = REPO_ROOT / "docs" / "registry"
SCHEMA_NAME = "conformance-record.v0"

SUMMARY_RE = re.compile(r"^(\d+) passed, (\d+) failed", re.MULTILINE)

HONEST_LIMITATION = (
    "digest-chain integrity only; third-party-verifiable attestation "
    "arrives with L4 signing (roadmap); this record is a Conformance "
    "Report, not a legal opinion"
)


def git(*args):
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def run_suite(tool, label):
    """Run one acceptance tool and return (passed, total). Refuse on red."""
    print(f"running {tool} ...", file=sys.stderr)
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / tool)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    out = result.stdout
    matches = SUMMARY_RE.findall(out)
    if not matches:
        raise SystemExit(
            f"{tool}: no 'N passed, M failed' summary line found — "
            f"refusing to generate a record from unparseable output "
            f"(exit {result.returncode})\n{out[-2000:]}"
        )
    passed, failed = (int(n) for n in matches[-1])
    total = passed + failed
    if failed or result.returncode != 0:
        raise SystemExit(
            f"{tool}: suite is RED ({passed}/{total} {label}) — a record "
            f"must only ever describe a fully green run; fix the suite first"
        )
    print(f"  {label}: {passed}/{total} green", file=sys.stderr)
    return passed, total


def build_record(args, unit_passed, unit_total, scenarios_passed, scenarios_total):
    limitations = list(args.limitation)
    if HONEST_LIMITATION not in limitations:
        # mandatory framing line: auto-appended so no invocation can forget it
        limitations.append(HONEST_LIMITATION)
    record = {
        "implementation": {
            "name": args.name,
            "version": args.version,
            "producer": args.producer,
        },
        "spec": {
            "spec_version": "0.1",
            "spec_commit": git("rev-parse", "HEAD"),
            "record_generated_at": git("log", "-1", "--format=%cI"),
        },
        "suite": {
            "unit_passed": unit_passed,
            "unit_total": unit_total,
            "scenarios_passed": scenarios_passed,
            "scenarios_total": scenarios_total,
            "runner": "tools/run_scenarios.py",
            "inventory_tool": "python3 tools/test_inventory.py",
            "fail_set": [],
        },
        "attestation": {
            "kind": args.kind,
            "method": args.method,
        },
        "limitations": limitations,
        "external_benchmark": [],
    }
    if args.repo_url:
        record["implementation"]["repo_url"] = args.repo_url
    if args.verifier:
        record["attestation"]["verifier"] = args.verifier
    if args.evidence_ref:
        record["attestation"]["evidence_ref"] = args.evidence_ref
    if args.notes:
        record["notes"] = args.notes
    return record


def check_against_schema(record):
    """Validate with the repo's minimal validator (stdlib-only house tool)."""
    sys.path.insert(0, str(REPO_ROOT))
    from mbcp._schema import ValidationError, load_schema, validate

    try:
        validate(record, load_schema(SCHEMA_NAME))
    except ValidationError as err:
        raise SystemExit(f"record fails schemas/{SCHEMA_NAME}.json: {err}")


def render_markdown(record, slug, short):
    impl = record["implementation"]
    spec = record["spec"]
    suite = record["suite"]
    att = record["attestation"]
    lines = [
        f"# Conformance Report — {impl['name']} {impl['version']}",
        "",
        f"- implementation: `{impl['name']}` {impl['version']} (producer: {impl['producer']})",
        f"- spec: MBCP v{spec['spec_version']} @ `{spec['spec_commit'][:12]}`",
        f"- record generated at: {spec['record_generated_at']} (git commit date, auto-filled)",
        f"- suite: {suite['unit_passed']}/{suite['unit_total']} unit + "
        f"{suite['scenarios_passed']}/{suite['scenarios_total']} scenarios, "
        f"fail_set {suite['fail_set']}",
        f"- attestation: **{att['kind']}** — {att['method']}",
    ]
    if att.get("verifier"):
        lines.append(f"  - verifier: {att['verifier']}")
    if att.get("evidence_ref"):
        lines.append(f"  - evidence: {att['evidence_ref']}")
    lines.append("- limitations:")
    lines.extend(f"  - {item}" for item in record["limitations"])
    lines.append(
        f"- external_benchmark: {len(record['external_benchmark'])} entr"
        f"{'y' if len(record['external_benchmark']) == 1 else 'ies'}"
    )
    if record.get("notes"):
        lines.append(f"- notes: {record['notes']}")
    lines.append("")
    # machine-readable twin: this file is a rendering of
    # <slug>-<short>.json in this directory; the JSON is authoritative.
    lines.append(f"Machine-readable twin: [`{slug}-{short}.json`]({slug}-{short}.json)")
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--impl-slug", required=True,
                        help="filename slug, e.g. 'mbcp' -> docs/registry/mbcp-<commit[:12]>.json")
    parser.add_argument("--name", required=True)
    parser.add_argument("--version", required=True,
                        help="implementation's own semver (GOVERNANCE principle 3)")
    parser.add_argument("--producer", required=True, choices=["home", "external"])
    parser.add_argument("--repo-url")
    parser.add_argument("--kind", required=True,
                        choices=["self-declaration", "verifier-attested"])
    parser.add_argument("--verifier")
    parser.add_argument("--method", required=True)
    parser.add_argument("--evidence-ref")
    parser.add_argument("--limitation", action="append", default=[],
                        help="limitation line; repeatable. The honest-framing "
                             "sentence is mandatory and added verbatim if absent.")
    parser.add_argument("--notes")
    args = parser.parse_args(argv)

    unit_passed, unit_total = run_suite("run_tests.py", "unit")
    scen_passed, scen_total = run_suite("run_scenarios.py", "scenarios")

    record = build_record(args, unit_passed, unit_total, scen_passed, scen_total)
    check_against_schema(record)

    short = record["spec"]["spec_commit"][:12]
    REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REGISTRY_DIR / f"{args.impl_slug}-{short}.json"
    md_path = REGISTRY_DIR / f"{args.impl_slug}-{short}.md"
    json_path.write_text(
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    md_path.write_text(render_markdown(record, args.impl_slug, short), encoding="utf-8")
    print(f"wrote {json_path.relative_to(REPO_ROOT)}")
    print(f"wrote {md_path.relative_to(REPO_ROOT)}")
    print(json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
