# Deliberate-violation fixture (SC-CI-02)
#
# `tools/test_count_guard.sh --self-test` builds a doctored git worktree in
# which every file listed in `deleted_files.txt` is removed, commits it, and
# asserts the test-count guard FAILS on that tree. This proves the gate can
# fail — a guard that never fails is skipped/neutral CI theatre.
#
# The CI step "Test-count guard self-check" runs this every build; the unit
# test tests/test_ci_guard.py runs it locally.
