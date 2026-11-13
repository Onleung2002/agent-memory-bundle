"""Shared synthetic fixtures — never real profile data (PII discipline).

All bodies/owners/ids are machine-generated placeholders.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mbcp import (
    build_bundle,
    canonical_bytes,
    keypair_from_seed_hex,
    make_record,
    make_tombstone,
)

FIXED_TS = "2026-11-05T08:00:00Z"
OWNER = "user-synthetic-01"

# Deterministic ed25519 fixture keypair (M4 Round B): hand-built receipt
# fixtures must be L4-signed to pass the schema/attestation gates, and a
# FIXED seed keeps the fixtures reproducible. This is a published test
# vector key — never a real profile key.
SYN_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"


def syn_keypair():
    """The shared deterministic fixture keypair (RFC 8032 TEST 1 seed)."""
    return keypair_from_seed_hex(SYN_SEED_HEX)


def syn_record(record_id, body, **kwargs):
    kwargs.setdefault("created", FIXED_TS)
    kwargs.setdefault("source", "synthetic-fixture")
    return make_record(record_id, "fact", body, OWNER, **kwargs)


def syn_bundle_a():
    return build_bundle(
        "bundle-alpha",
        records=[
            syn_record("rec-001", "synthetic body alpha one", priority="critical"),
            syn_record("rec-002", "synthetic body alpha two", priority="standard"),
            syn_record("rec-003", "synthetic body alpha three", priority="opportunistic"),
        ],
        tombstones=[
            make_tombstone(
                "rec-000",
                "synthetic erasure request",
                deleted_at=FIXED_TS,
                derived_artifacts=["chunk:rec-000:0", "emb:rec-000"],
            )
        ],
    )


def syn_bundle_b():
    return build_bundle(
        "bundle-beta",
        records=[
            syn_record("rec-101", "synthetic body beta one", priority="standard"),
            syn_record("rec-102", "synthetic body beta two", priority="critical"),
        ],
    )


def write_bundle_direct(service, manifest):
    """Simulate the out-of-band producer: write a manifest STRAIGHT into
    ``bundles/``, bypassing ``L1DeletionService.put_bundle``.

    Since M4 round C1 (SPEC 1.2 write boundary, audit §6), put_bundle
    rejects any copy of a journal-tombstoned id, so test fixtures that
    resurrect a deleted record must land through the same channel the
    real attack/legacy path uses — another producer writing files
    directly. Byte-identical to what put_bundle would have written
    (canonical bytes), so downstream validation is unaffected.
    """
    path = service.bundle_path(manifest["bundle"]["id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(manifest))
    return path


def assert_raises(exc_type, fn, *args, **kwargs):
    """Minimal pytest.raises stand-in so tests run under the vendored
    stdlib runner as well as under pytest."""
    try:
        fn(*args, **kwargs)
    except exc_type:
        return
    except Exception as err:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(err).__name__}: {err}"
        )
    raise AssertionError(f"expected {exc_type.__name__}, no exception raised")
