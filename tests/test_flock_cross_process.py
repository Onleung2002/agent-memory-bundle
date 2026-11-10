"""Cross-process flock exclusion pin (ADV-C3-4, controller-authored).

SPEC 1.2.3 claims cross-process advisory locking on the service root; the
suite must carry that evidence, not only thread-level tests. Two REAL OS
processes: the parent holds the root lock, the child attempts put_bundle
with a short lock_timeout and must receive the typed LockTimeoutError; after
the parent releases, the same child operation must succeed.

Barrier/Event based — no sleep-based timing anywhere.
"""
import multiprocessing
import os
import queue as queue_mod
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from syn import syn_record  # noqa: E402
from mbcp.deletion import L1DeletionService, LockTimeoutError  # noqa: E402


def _child(root, start_ev, released_ev, q):
    """Runs in a separate OS process: two timed attempts against the root."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from mbcp.deletion import L1DeletionService, LockTimeoutError
    svc = L1DeletionService(root)
    manifest = {"bundle": {"id": "child-b"}, "mbcp_version": "0.1",
                "records": [syn_record("r1", "x")], "tombstones": []}
    start_ev.wait(timeout=30)
    try:
        svc.put_bundle(manifest, lock_timeout=0.4)
        q.put(("attempt1", "no-lock"))
    except LockTimeoutError as e:
        assert str(root) in str(e), "LockTimeoutError must name the root"
        q.put(("attempt1", "timeout-typed"))
    released_ev.wait(timeout=30)
    try:
        svc.put_bundle(manifest, lock_timeout=5.0)
        q.put(("attempt2", "ok"))
    except LockTimeoutError:
        q.put(("attempt2", "timeout-again"))


def test_cross_process_flock_exclusion_and_release():
    root = tempfile.mkdtemp()
    start_ev = multiprocessing.Event()
    released_ev = multiprocessing.Event()
    q = multiprocessing.Queue()
    proc = multiprocessing.Process(target=_child, args=(root, start_ev, released_ev, q))
    proc.start()
    try:
        svc = L1DeletionService(root)
        # Phase 1: parent holds the lock -> child's put must time out typed.
        with svc._root_lock(timeout=5.0):
            start_ev.set()
            tag1, outcome1 = q.get(timeout=30)
            assert (tag1, outcome1) == ("attempt1", "timeout-typed"), (tag1, outcome1)
            # No residue: the child must not have written during phase 1.
            bundles_dir = os.path.join(root, "bundles")
            bundles = os.listdir(bundles_dir) if os.path.isdir(bundles_dir) else []
            assert bundles == [], f"child wrote while lock was held: {bundles}"
            # Phase 2: parent releases -> the same child op must succeed.
            released_ev.set()
        tag2, outcome2 = q.get(timeout=30)
        assert (tag2, outcome2) == ("attempt2", "ok"), (tag2, outcome2)
    finally:
        released_ev.set()
        proc.join(timeout=30)
        assert proc.exitcode == 0, f"child exited {proc.exitcode}"
