"""Regression pins for the strict-parse gate (json_loads_strict).

Backlog A-5: the parse gate (NaN/Infinity rejection via parse_constant) was
previously unobservable by the suite -- defense-in-depth elsewhere masked it,
so defusing ``parse_constant`` kept the full suite green while a NaN literal
inside a schema-legal position of an on-disk artifact flowed silently into
receipt accounting. Each pin here poisons a real on-disk artifact at a
parse-gate-relevant position and asserts a TYPED outcome at the boundary
(raised DeletionError / PropagationError, or an ok:False verify result whose
problems name the corruption -- the documented fail-closed shapes).

Known residual (A-2, backlog): ``recover()`` wraps its own scans in a broad
``except (OSError, KeyError, TypeError, ValueError): continue`` and therefore
silently skips a NaN-poisoned recovery line; the typed gate still fires at
``_read_recovery``/``recovery_removals`` and downstream at delete/verify.
That skip is tracked under A-2 and intentionally NOT asserted as typed here.

Controller-authored test-only micro-commit (Isaac ruling 2026-11-08).
"""
import json
from pathlib import Path

from syn import assert_raises, syn_record

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mbcp import build_bundle
from mbcp.canonical import NonFiniteConstantError, json_loads_strict
from mbcp.deletion import DeletionError, L1DeletionService
from mbcp.propagation import PropagationError, export_propagation_pack, import_propagation_pack


def _inject_nan(obj, key="zz_extra"):
    """Insert a raw NaN literal (json.dumps cannot emit it)."""
    raw = json.dumps(obj)
    assert raw.endswith("}")
    return raw[:-1] + f', "{key}": NaN}}'


def _svc():
    svc = L1DeletionService(Path(__import__("tempfile").mkdtemp()))
    svc.put_bundle(build_bundle(
        "b1", records=[syn_record("r1", "synthetic body one")]))
    return svc


def _lines(path):
    return path.read_text(encoding="utf-8").strip().split("\n")


# --- Gate unit pins ---------------------------------------------------------

def test_parse_gate_rejects_nan_infinity_typed():
    for literal in ("NaN", "Infinity", "-Infinity"):
        assert_raises(NonFiniteConstantError, json_loads_strict, f"[{literal}]")


def test_parse_gate_stdlib_contrast_documents_gap():
    # documents the gap the gate closes: stdlib json.loads is permissive
    assert isinstance(json.loads("[NaN]")[0], float)


# --- Boundary pins: NaN at a parse-gate-relevant position on disk -----------

def test_nan_literal_in_removal_evidence_fails_verify_typed():
    svc = _svc()
    receipt = svc.delete("b1", "r1", "user request")
    ev_path = svc.evidence_path("r1")
    ev_path.write_text(
        _inject_nan(json.loads(ev_path.read_text(encoding="utf-8"))),
        encoding="utf-8")
    # verify_receipt catches reader errors into problems (fail-closed shape)
    result = svc.verify_receipt(
        svc.root / "receipts" / f"{receipt['receipt']['id']}.json")
    assert result["ok"] is False
    assert any("non-finite" in p for p in result["problems"]), result["problems"]
    # the gate also fires directly at the reader boundary
    assert_raises(DeletionError, svc._read_evidence, "r1")


def test_nan_literal_in_recovery_log_fails_reader_typed():
    svc = _svc()
    svc.delete("b1", "r1", "user request")
    # create a recovery entry: resurrect a stale copy, then recover it
    svc.put_bundle(build_bundle("b2", records=[syn_record("r1", "STALE")]))
    svc.recover()
    assert svc.recovery_path.exists()
    lines = _lines(svc.recovery_path)
    lines[0] = _inject_nan(json.loads(lines[0]))
    svc.recovery_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # the typed gate fires at the reader boundary
    assert_raises(DeletionError, svc.recovery_removals)
    # downstream stays fail-closed: delete() refuses to heal on an unreadable log
    assert_raises(Exception, svc.delete, "b1", "r1", "retry")
    # NOTE: recover() itself silently skips the poisoned line (A-2, backlog)


def test_nan_literal_in_tombstone_journal_rejected_typed():
    svc = _svc()
    svc.delete("b1", "r1", "user request")  # ensures the journal file exists
    jpath = svc.journal_path
    lines = _lines(jpath)
    lines[0] = _inject_nan(json.loads(lines[0]))
    jpath.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert_raises(DeletionError, svc.all_tombstones)


def test_nan_literal_in_receipt_file_rejected_typed():
    svc = _svc()
    receipt = svc.delete("b1", "r1", "user request")
    rpath = svc.root / "receipts" / f"{receipt['receipt']['id']}.json"
    rpath.write_text(
        _inject_nan(json.loads(rpath.read_text(encoding="utf-8"))),
        encoding="utf-8")
    result = svc.verify_receipt(rpath)
    assert result["ok"] is False
    assert any("non-finite" in p for p in result["problems"]), result["problems"]


def test_nan_literal_in_bundle_manifest_rejected_typed_not_crash():
    svc = _svc()
    bpath = svc.bundles_dir / "b1.json"
    bpath.write_text(
        _inject_nan(json.loads(bpath.read_text(encoding="utf-8"))),
        encoding="utf-8")
    assert_raises(DeletionError, svc.delete, "b1", "r1", "another request")
    # recover() currently SKIPS unreadable manifests silently (broad
    # `except (OSError, KeyError, TypeError, ValueError): continue`) -- the
    # A-2 silent-skip pattern, tracked in backlog; pinned here as documented
    # current behavior (availability, fail-closed downstream at delete/verify)
    svc.recover()  # must not crash; typed enforcement lives at delete/verify


def test_nan_literal_in_propagation_ack_rejected_typed():
    svc = _svc()
    svc.delete("b1", "r1", "user request")
    pack = export_propagation_pack(svc)
    import_propagation_pack(svc, pack)
    apath = sorted((svc.root / "propagation" / "acks").glob("*.json"))[0]
    apath.write_text(
        _inject_nan(json.loads(apath.read_text(encoding="utf-8"))),
        encoding="utf-8")
    # no-op re-import reads the ack back: NaN-poisoned bytes must not be served
    assert_raises(PropagationError, import_propagation_pack, svc, pack)
