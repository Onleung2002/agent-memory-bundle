#!/usr/bin/env python3
"""Minimal stdlib test runner for MBCP.

pytest is preferred when available; otherwise this runner discovers
tests/test_*.py and executes every zero-argument test_* function.
Tests are written to be compatible with both.
"""

import importlib.util
import inspect
import pathlib
import sys
import traceback

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    try:
        import pytest  # noqa: F401
    except ImportError:
        pytest = None

    if pytest is not None:
        return pytest.main([str(REPO_ROOT / "tests"), "-q"])

    sys.path.insert(0, str(REPO_ROOT))
    sys.path.insert(0, str(REPO_ROOT / "tests"))

    passed = failed = 0
    failures = []
    files = sorted((REPO_ROOT / "tests").glob("test_*.py"))
    for path in files:
        try:
            module = _load_module(path)
        except Exception:  # noqa: BLE001
            failed += 1
            failures.append((f"{path.stem} (import)", traceback.format_exc()))
            print(f"FAIL {path.stem} (import)")
            continue
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            fn = getattr(module, name)
            if not callable(fn):
                continue
            if inspect.signature(fn).parameters:
                print(f"SKIP {path.stem}::{name} (fixtures need pytest)")
                continue
            try:
                fn()
                passed += 1
                print(f"PASS {path.stem}::{name}")
            except Exception:  # noqa: BLE001
                failed += 1
                failures.append((f"{path.stem}::{name}", traceback.format_exc()))
                print(f"FAIL {path.stem}::{name}")

    print(f"\n{passed} passed, {failed} failed ({len(files)} test files)")
    for label, tb in failures:
        print(f"\n--- {label}\n{tb}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
