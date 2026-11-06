"""SC-CANON-01: canonicalization preserves values verbatim (structure only)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mbcp import canonical_bytes


def test_sc_canon_01_user_strings_preserved_verbatim():
    obj = {
        "msg": "  Keep   Me \n Exactly — 唔准改  ",
        "ts": "2026-11-05T10:20:30.123456+02:30",
    }
    assert json.loads(canonical_bytes(obj)) == obj


def test_sc_canon_01_subsecond_timestamp_precision_preserved():
    obj = {"t": "2026-11-05T10:20:30.987654+02:30"}
    parsed = json.loads(canonical_bytes(obj))
    assert parsed["t"] == "2026-11-05T10:20:30.987654+02:30"


def test_sc_canon_01_parse_back_equality_samples():
    samples = [
        {"a": 1, "b": [1, 2, {"c": "x"}], "d": None, "e": True},
        {"ts1": "2026-01-01T00:00:00Z", "ts2": "2026-01-01T00:00:00.5+08:00"},
        {"nested": {"deep": {"unicode": "记忆 — 記憶", "num": 3.25}}},
        {"empty": "", "list": [], "obj": {}},
    ]
    for obj in samples:
        assert json.loads(canonical_bytes(obj)) == obj


def test_sc_canon_01_structure_normalized_but_not_values():
    # key order is normalized; values are byte-identical after parse-back
    a = canonical_bytes({"b": "2026-11-05T10:20:30.9+02:30", "a": 1})
    b = canonical_bytes({"a": 1, "b": "2026-11-05T10:20:30.9+02:30"})
    assert a == b
    assert json.loads(a)["b"] == "2026-11-05T10:20:30.9+02:30"
