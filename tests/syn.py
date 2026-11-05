"""Shared synthetic fixtures — never real profile data (PII discipline).

All bodies/owners/ids are machine-generated placeholders.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mbcp import build_bundle, make_record, make_tombstone

FIXED_TS = "2026-11-05T08:00:00Z"
OWNER = "user-synthetic-01"


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
