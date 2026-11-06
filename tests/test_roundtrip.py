"""Round-trip determinism: bundle -> canonical bytes -> identical SHA-256.

Covers SPEC 1.1 requirement: same inputs -> byte-deterministic output,
in-process and across two separate interpreter runs (hash randomization
included).
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import canonical_bytes, canonical_sha256, validate_bundle

from syn import syn_bundle_a, syn_bundle_b

REPO_ROOT = Path(__file__).resolve().parent.parent

_SUBPROCESS_SNIPPET = (
    "import sys;"
    f"sys.path.insert(0, {str(REPO_ROOT)!r});"
    f"sys.path.insert(0, {str(REPO_ROOT / 'tests')!r});"
    "from syn import syn_bundle_a, syn_bundle_b;"
    "from mbcp import canonical_sha256;"
    "print(canonical_sha256([syn_bundle_a(), syn_bundle_b()]))"
)


def test_canonical_bytes_identical_twice_in_process():
    bundle = syn_bundle_a()
    first = canonical_bytes(bundle)
    second = canonical_bytes(bundle)
    assert first == second
    assert canonical_sha256(bundle) == canonical_sha256(bundle)


def test_canonical_form_sorted_and_compact():
    blob = canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}})
    assert blob == b'{"a":{"c":3,"d":2},"b":1}'


def test_timestamp_preserved_verbatim_including_subseconds():
    # SC-CANON-01: canonicalization normalizes STRUCTURE only; values —
    # including sub-second timestamp precision — are preserved verbatim.
    blob = canonical_bytes({"t": "2026-11-05T10:20:30.987654+02:30"})
    assert blob == b'{"t":"2026-11-05T10:20:30.987654+02:30"}'


def test_manifest_validates_against_schema():
    validate_bundle(syn_bundle_a())
    validate_bundle(syn_bundle_b())


def test_sha256_identical_across_two_runs():
    expected = canonical_sha256([syn_bundle_a(), syn_bundle_b()])
    for _ in range(2):
        out = subprocess.run(
            [sys.executable, "-c", _SUBPROCESS_SNIPPET],
            capture_output=True,
            text=True,
            check=True,
        )
        assert out.stdout.strip() == expected
