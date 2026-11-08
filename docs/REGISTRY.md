# MBCP Conformance Registry

The registry records conformance reports for implementations of the MBCP
spec (v0.1, see [SPEC.md](../SPEC.md)). Each record in `docs/registry/` is a
machine-readable JSON file validated against
[`schemas/conformance-record.v0.json`](../schemas/conformance-record.v0.json),
plus a human-readable `.md` rendering of the same content.

## Rules

**Terminology law (Isaac ruling; GOVERNANCE.md principle 2).** The following
paragraph is quoted verbatim as the rule itself — it is the only place this
vocabulary may appear anywhere in the registry, its schema, its tooling, or
its tests:

> TERMINOLOGY LAW (Isaac ruling; GOVERNANCE.md principle 2): before any
> accreditation exists, output is called **Conformance Report / Evidence
> Pack**. The words "certificate / certified / certification" are FORBIDDEN
> in every artifact you touch (schema, docs, code strings, test names).
> Upgrade path wording: "self-declaration -> verifier-attested". Zero
> certified-words anywhere.

Every record must carry this limitation sentence verbatim (enforced by
`tests/test_registry.py`):

> digest-chain integrity only; third-party-verifiable attestation arrives
> with L4 signing (roadmap); this record is a Conformance Report, not a
> legal opinion.

A record never claims or implies any accredited status. The upgrade path is:
a record enters as **self-declaration** and may be upgraded to
**verifier-attested** after an independent verification session replays the
implementation's report and confirms it.

## Record format

A record describes one implementation against one spec commit:

- `implementation`: name, version (the implementation's own semver, not the
  spec's), optional repo_url, and `producer` (`home` | `external`).
- `spec`: `spec_version` (always `"0.1"` in this schema generation),
  `spec_commit` (full git hash the suite numbers were produced against) and
  `record_generated_at` (RFC3339, timezone-aware). Both metadata fields are
  **auto-filled from git by `tools/make_registry_record.py`** — hand-filling
  them is the drift entry point and is not allowed.
- `suite`: unit/scenario pass and total counts, the runner and inventory
  tool identifiers, and `fail_set`. Counts come from actually running
  `tools/run_tests.py` and `tools/run_scenarios.py`; the generator refuses
  to write a record unless both suites are fully green, so `fail_set` is
  always empty in a committed record.
- `attestation`: `kind` (`self-declaration` | `verifier-attested`),
  `method`, optional `verifier` and `evidence_ref`.
- `limitations`: required, at least one entry, must include the
  honest-framing sentence above.
- `external_benchmark`: reserved array for future cross-referencing of
  independent benchmarks; entries carry `name`, `scope`, and `relationship`
  (`independent` | `cross-reference-candidate`). Empty in v0.1; no real
  product may be named until an entry is actually accepted.
- `notes`: optional free text.

## How external implementations submit

Per [CONTRIBUTING.md](../CONTRIBUTING.md): implement against `SPEC.md` and
`tests/scenarios/*.yaml` **without reading the `mbcp/` source** (ambiguities
you hit are spec-fuzzing — file an issue), then produce an implementation
report: per-scenario pass/fail plus your diagnosis of every failure (your
bug or spec ambiguity). Open a PR adding a record file produced with
`tools/make_registry_record.py`, with `--producer external` and
`--kind self-declaration`. The maintainers replay your report; after an
independent verification session confirms it, the record is upgraded to
`verifier-attested` with the verifier and evidence named.

## Anti-drift pin

`tests/test_registry.py` validates every record file against the schema,
pins the honest-framing sentence, pins the filename convention
(`<slug>-<spec_commit[:12]>.json`), and cross-checks each record's suite
numbers against the actual suite counts **at the commit the record cites**
(using the same counting rule as `tools/test_count_guard.sh`), plus an
explicit mutation pin proving a fabricated number fails.

Design decision — commit coupling: the check is coupled to the record's own
`spec_commit`, not to live `HEAD`. A committed file can never cite its own
commit hash (self-reference), so a HEAD-coupled check would be dead code
immediately after every regeneration commit. Checking against the cited
commit's tree keeps every historical record verifiable forever, and lets the
suite grow in later commits without invalidating older records. A
`spec_commit` that does not resolve in this repository (an external
implementation citing its own repo) is validated schema-only. A fabricated
or stale number in any record whose commit resolves here fails CI.

## Records

### mbcp 0.1.0 (home) — Conformance Report

| field | value |
|---|---|
| implementation | `mbcp` 0.1.0, producer `home` — [repo](https://github.com/Onleung2002/agent-memory-bundle) |
| spec | MBCP v0.1 @ `7297422b03760494511df29d949bbc3e37cbc203` (`7297422b0376`) |
| record generated at | 2026-11-08T14:53:56Z (git commit date, auto-filled) |
| suite | 224/224 unit + 19/19 scenarios via `tools/run_tests.py` + `tools/run_scenarios.py`, `fail_set` [] |
| attestation | **verifier-attested** — verifier: GLM independent verification session |
| method | independent adversarial audit + mutation-verified verification rounds, replayed against tools/run_tests.py and tools/run_scenarios.py |
| evidence | [docs/AUDIT_2026-11-08.md](AUDIT_2026-11-08.md) + [docs/MILESTONE_M3.md](MILESTONE_M3.md) §5a |
| limitations | digest-chain integrity only; third-party-verifiable attestation arrives with L4 signing (roadmap); this record is a Conformance Report, not a legal opinion |
| external_benchmark | [] (reserved) |
| notes | First registry record: the home reference implementation after the M3 hotfix round (audit HIGH#1/HIGH#2 fixed, ATK1-3 pinned, A-5 parse-gate pins), GLM-verified. |

Machine-readable: [`registry/mbcp-7297422b0376.json`](registry/mbcp-7297422b0376.json)
· rendering: [`registry/mbcp-7297422b0376.md`](registry/mbcp-7297422b0376.md)
