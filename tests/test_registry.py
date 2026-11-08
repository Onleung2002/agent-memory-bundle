"""SC-REG-01: conformance-registry anti-drift pins.

Every record file in docs/registry/ must (a) validate against
schemas/conformance-record.v0.json, (b) carry the honest-framing limitation
sentence verbatim (the terminology-law enforcement point), (c) follow the
filename convention <slug>-<spec_commit[:12]>, and (d) report suite numbers
that match the actual suite AT the commit the record cites, counted with the
same rule as tools/test_count_guard.sh. A fabricated number must fail.

Design decision (documented in docs/REGISTRY.md "Anti-drift pin" section):
the count check is coupled to the record's own spec_commit, not to live
HEAD. A committed file can never cite its own commit hash (self-reference),
so a HEAD-coupled check would be dead code after every regeneration commit;
checking against the cited commit's tree instead keeps every historical
record verifiable forever. A commit not resolvable in this repo (an external
implementation citing its own repository) is validated schema-only.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mbcp._schema import ValidationError, load_schema, validate

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_DIR = REPO_ROOT / "docs" / "registry"

HONEST_LIMITATION = (
    "digest-chain integrity only; third-party-verifiable attestation "
    "arrives with L4 signing (roadmap); this record is a Conformance "
    "Report, not a legal opinion"
)


def _records():
    assert REGISTRY_DIR.is_dir(), "docs/registry/ must exist"
    records = sorted(REGISTRY_DIR.glob("*.json"))
    assert records, "registry must contain at least one record"
    return records


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _git(*args, check=True):
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=REPO_ROOT
    )
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result


def _commit_resolvable(commit):
    return _git("rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}",
                check=False).returncode == 0


def _counts_at(ref):
    """(unit_total, scenario_total) at <ref> using the guard's counting rule:
    test-function definition lines in tests/test_*.py plus scenario yaml
    files. The marker is assembled indirectly so this file's own line count
    matches its number of executable tests (the inventory rule greps for
    the raw marker string)."""
    marker = "def " + "test_"  # test-function definition marker
    grep = _git("grep", "-c", marker, ref, "--", "tests/test_*.py",
                check=False)
    unit = sum(int(line.rsplit(":", 1)[1]) for line in grep.stdout.splitlines())
    tree = _git("ls-tree", "-r", "--name-only", ref, "--", "tests/scenarios")
    scenarios = sum(
        1 for name in tree.stdout.splitlines() if name.endswith((".yaml", ".yml"))
    )
    return unit, scenarios


def _suite_problems(record):
    """[] if the record's suite numbers match the tree at spec_commit."""
    suite = record["suite"]
    problems = []
    if not _commit_resolvable(record["spec"]["spec_commit"]):
        return problems  # external repo's commit: schema-only, see module doc
    unit_total, scen_total = _counts_at(record["spec"]["spec_commit"])
    if suite["unit_total"] != unit_total:
        problems.append(f"unit_total {suite['unit_total']} != {unit_total} "
                        f"at {record['spec']['spec_commit'][:12]}")
    if suite["scenarios_total"] != scen_total:
        problems.append(f"scenarios_total {suite['scenarios_total']} != "
                        f"{scen_total} at {record['spec']['spec_commit'][:12]}")
    # the generator only writes fully green runs, so a committed record must
    # claim exactly that — a red-suite record can never enter the registry
    if suite["unit_passed"] != suite["unit_total"]:
        problems.append("unit_passed != unit_total")
    if suite["scenarios_passed"] != suite["scenarios_total"]:
        problems.append("scenarios_passed != scenarios_total")
    if suite["fail_set"] != []:
        problems.append("fail_set must be empty for a green run")
    return problems


def test_sc_reg_01_every_record_validates_against_schema():
    schema = load_schema("conformance-record.v0")
    for path in _records():
        try:
            validate(_load(path), schema)
        except ValidationError as err:
            raise AssertionError(f"{path.name}: {err}")


def test_sc_reg_02_every_record_carries_honest_framing_limitation():
    for path in _records():
        record = _load(path)
        assert HONEST_LIMITATION in record["limitations"], (
            f"{path.name}: missing the mandatory honest-framing sentence"
        )


def test_sc_reg_03_filename_suffix_matches_spec_commit():
    for path in _records():
        record = _load(path)
        assert path.stem.rsplit("-", 1)[1] == record["spec"]["spec_commit"][:12], (
            f"{path.name}: filename suffix must equal spec_commit[:12]"
        )


def test_sc_reg_04_suite_numbers_match_counts_at_spec_commit():
    for path in _records():
        problems = _suite_problems(_load(path))
        assert not problems, f"{path.name}: " + "; ".join(problems)


def test_sc_reg_05_fabricated_suite_number_fails():
    # mutation pin: bump a number and prove the check fires (the gate is
    # exercised, not assumed — same discipline as test_ci_guard's self-test)
    record = _load(_records()[0])
    if not _commit_resolvable(record["spec"]["spec_commit"]):
        return  # nothing head-resolvable to fabricate against here
    record["suite"]["unit_total"] += 1
    assert _suite_problems(record), "fabricated unit_total was not caught"
