"""SC-ANCHOR-01: banned-word grep pin over the anchor tool tree (RFC 7.3).

The anchor tool must never make capability claims beyond "third-party
timestamped evidence". These needles are the RFC 7.3 list, assembled
indirectly (house pattern, as in test_registry's terminology pin) so this
file never carries the raw banned roots either:

- ``certified`` — independent root: does NOT contain ``certificat-``
- ``certificat-`` — covers certificate / certification
- ``tamper-proof`` / ``tamperproof`` — independent word forms
- ``guarantee`` — covers guaranteed
- ``forgery-proof``

The pin covers every file under ``anchor/`` (code, docstrings, README,
meta.json field names). RFC3161 protocol internals (X.509 trust-chain
files) are called "TSA trust chain" in this tree per the RFC's
terminology rule; runtime DER bytes from a TSA are not repo content and
are out of scope for this pin.

The fire check (SC-ANCHOR-02) injects a real banned word into a COPY of
the tree and proves the scanner trips — the pin is exercised, not
assumed.
"""

import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ANCHOR_DIR = REPO_ROOT / "anchor"

# Indirect assembly — never write the raw roots in this file.
NEEDLES = (
    "certi" + "fied",
    "certi" + "ficat",
    "tamper" + "-proof",
    "tamper" + "proof",
    "guaran" + "tee",
    "forgery" + "-proof",
)


def scan_tree(root):
    """Return [(path, lineno, needle)] for every banned-root hit."""
    hits = []
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: not a claims-bearing file
        for lineno, line in enumerate(text.splitlines(), 1):
            for needle in NEEDLES:
                if needle in line:
                    hits.append((path, lineno, needle))
    return hits


def test_sc_anchor_01_banned_roots_pin_anchor_tree_clean():
    hits = scan_tree(ANCHOR_DIR)
    assert hits == [], (
        "banned capability-claim roots in anchor tree: "
        + "; ".join(f"{p}:{n}: {needle!r}" for p, n, needle in hits)
    )


def test_sc_anchor_02_pin_fires_on_injected_violation():
    # exercise the pin: a tree copy carrying one real banned word per
    # needle family must trip the scanner (a pin that cannot fire is
    # decoration).
    injections = {
        NEEDLES[0]: "this receipt was certi" + "fied by the tool",
        NEEDLES[1]: "a certi" + "ficate is issued",
        NEEDLES[2]: "described as tamper" + "-proof storage",
        NEEDLES[3]: "described as tamper" + "proof storage",
        NEEDLES[4]: "we guaran" + "tee deletion",
        NEEDLES[5]: "a forgery" + "-proof receipt",
    }
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "anchor"
        shutil.copytree(ANCHOR_DIR, copy)
        for idx, (needle, sentence) in enumerate(injections.items()):
            target = copy / f"injected_{idx}.md"
            target.write_text(f"# doc\n{sentence}\n", encoding="utf-8")
            hits = scan_tree(copy)
            assert hits, f"pin did not fire on injected {needle!r}"
            assert any(needle == hit[2] for hit in hits), (
                f"pin fired but on the wrong needle for {needle!r}: {hits}"
            )
            target.unlink()
        assert scan_tree(copy) == [], "pin stayed lit after cleanup"
