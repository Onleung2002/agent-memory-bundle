#!/usr/bin/env bash
# Test-count guard (SC-CI-01/02).
#
# Counts ALL tests at two git refs:
#   - unit tests:   `def test_` functions in tests/test_*.py
#   - scenarios:    tests/scenarios/*.yaml files
# Fails (exit 1) if the total decreased between <before-ref> and <after-ref>
# without a spec revision. Test deletions must fail CI.
#
# Usage:
#   tools/test_count_guard.sh <before-ref> <after-ref>
#   tools/test_count_guard.sh --self-test
#
# --self-test builds a doctored tree (files listed in
# fixtures/deliberate_violation/deleted_files.txt are removed) and proves
# the guard actually fails on it — the gate is exercised, not assumed.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT"

count_tests() {
  local ref="$1"
  local unit scenarios
  # git grep -c prints "<ref>:<path>:<count>" per file; exit 1 on no match,
  # so guard the pipeline (never `grep -c ... || echo 0` — that prints "0"
  # AND "0", corrupting the arithmetic).
  unit=$( { git grep -c 'def test_' "$ref" -- 'tests/test_*.py' 2>/dev/null || true; } \
          | awk -F: '{s += $NF} END {print s + 0}')
  scenarios=$(git ls-tree -r --name-only "$ref" -- tests/scenarios \
          | { grep -cE '\.ya?ml$' || true; })
  echo $((unit + scenarios))
}

self_test() {
  local tmp wt bad list
  list="$REPO_ROOT/fixtures/deliberate_violation/deleted_files.txt"
  tmp=$(mktemp -d)
  trap "git worktree remove --force '$tmp/wt' >/dev/null 2>&1 || true; rm -rf '$tmp'" EXIT
  git worktree add -q --detach "$tmp/wt" HEAD
  while IFS= read -r f; do
    [ -n "$f" ] && rm -f "$tmp/wt/$f"
  done < "$list"
  git -C "$tmp/wt" add -A
  git -C "$tmp/wt" -c user.email=guard@ci.invalid -c user.name=guard \
    commit -qm "deliberate violation: test deletion (guard self-test)"
  bad=$(git -C "$tmp/wt" rev-parse HEAD)
  if "$0" HEAD "$bad" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: guard did NOT fail on a tree with deleted tests" >&2
    exit 1
  fi
  echo "SELF-TEST OK: guard caught the deliberate test deletion"
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit 0
fi

if [ $# -ne 2 ]; then
  echo "usage: $0 <before-ref> <after-ref> | --self-test" >&2
  exit 2
fi

before=$(count_tests "$1")
after=$(count_tests "$2")
echo "test count: before=$before after=$after"
if [ "$after" -lt "$before" ]; then
  echo "::error::test count decreased ($before -> $after) without spec revision — test-deletion regression" >&2
  exit 1
fi
