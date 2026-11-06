"""Shared helpers for M2 importer / deletion tests.

Synthetic fixtures only — never real profile content (PII discipline).
"""

import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
for path in (str(REPO_ROOT), str(REPO_ROOT / "tests")):
    if path not in sys.path:
        sys.path.insert(0, path)

FIXTURES = REPO_ROOT / "fixtures"
CHATGPT_EXPORT = FIXTURES / "chatgpt" / "mini_export"
HERMES_PROFILE = FIXTURES / "hermes_profile_demo"
OWNER = "user-synthetic-01"
IMPORTED_AT = "2026-11-06T00:00:00Z"
DELETED_AT = "2026-11-06T01:00:00Z"


def copy_profile(destination):
    """Copy the synthetic Hermes profile to ``destination`` (a path)."""
    destination = Path(destination)
    shutil.copytree(HERMES_PROFILE, destination)
    return destination
