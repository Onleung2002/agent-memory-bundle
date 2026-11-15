"""RFC-B deployment-layer tests: hermes self-host dispatcher.

These tests build fake Hermes profile trees under a temp dir and drive the
dispatcher end-to-end against real MBCP service roots — no mbcp/ code is
touched and no real /opt/data/profiles data is used. Every test is a
zero-argument function so the stdlib runner (tools/run_tests.py) executes
it without pytest; the @with_tmp decorator supplies the temp directory.
"""

import functools
import inspect
import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "deploy"))

import hermes_dispatcher as hd  # noqa: E402
import mbcp  # noqa: E402

DAY1 = "2026-11-15T03:00:00Z"
DAY2 = "2026-11-16T03:00:00Z"


def with_tmp(fn):
    """Inject a fresh TemporaryDirectory Path (stdlib-runner compatible).

    ``__signature__`` is reset to zero parameters: ``functools.wraps`` would
    otherwise propagate the inner ``tmp_path`` parameter through
    ``__wrapped__`` and the stdlib runner would skip every test as
    "fixtures need pytest" — fake coverage we refuse to ship.
    """

    @functools.wraps(fn)
    def wrapper():
        with tempfile.TemporaryDirectory() as td:
            return fn(Path(td))

    wrapper.__signature__ = inspect.Signature()
    return wrapper


def _write_profile(root_dir, name, memory_text, *, user_text=None, memories=True):
    base = root_dir / name
    if memories:
        mem = base / "memories"
        mem.mkdir(parents=True, exist_ok=True)
        (mem / "MEMORY.md").write_text(memory_text, encoding="utf-8")
        if user_text is not None:
            (mem / "USER.md").write_text(user_text, encoding="utf-8")
    return base


def _cfg(root_dir, **over):
    cfg = {
        "profiles_root": str(root_dir),
        "memories_dir": "memories",
        "memory_filename": "MEMORY.md",
        "root_subdir": "memory/mbcp_root",
        "log_subdir": "memory/dispatcher",
        "owner": "hermes",
        "secret_tier_profiles": ["job_applicator"],
        "notify_cmd": None,
        "max_entry_chars": 4096,
        "lock_timeout_seconds": 10.0,
    }
    cfg.update(over)
    return cfg


def _write_config(tmp_path, cfg):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def _root(cfg, profile):
    return Path(cfg["profiles_root"]) / profile / cfg["root_subdir"]


def _live_ids(root):
    service = mbcp.L1DeletionService(root)
    return set(hd._live_records(service))


def _runs(cfg, profile):
    path = Path(cfg["profiles_root"]) / profile / cfg["log_subdir"] / "runs.jsonl"
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _bundle_records(root, bundle_id):
    service = mbcp.L1DeletionService(root)
    return service.get_bundle(bundle_id)["records"]


# -- config -----------------------------------------------------------------


@with_tmp
def test_config_loads_valid_file(tmp_path):
    cfg_path = _write_config(tmp_path, _cfg(tmp_path))
    cfg = hd.load_config(cfg_path)
    assert cfg["profiles_root"] == str(tmp_path)
    assert cfg["secret_tier_profiles"] == ["job_applicator"]


@with_tmp
def test_config_missing_required_key_is_typed(tmp_path):
    cfg = _cfg(tmp_path)
    del cfg["root_subdir"]
    try:
        hd.load_config(_write_config(tmp_path, cfg))
    except hd.ConfigError:
        pass
    else:
        raise AssertionError("ConfigError not raised")


@with_tmp
def test_config_bad_profiles_root_is_typed(tmp_path):
    cfg = _cfg(tmp_path / "does-not-exist")
    try:
        hd.load_config(_write_config(tmp_path, cfg))
    except hd.ConfigError:
        pass
    else:
        raise AssertionError("ConfigError not raised")


@with_tmp
def test_config_invalid_json_is_typed(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("{not json", encoding="utf-8")
    try:
        hd.load_config(path)
    except hd.ConfigError:
        pass
    else:
        raise AssertionError("ConfigError not raised")


# -- enumeration ------------------------------------------------------------


@with_tmp
def test_iter_profiles_only_dirs_with_memory_md(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    _write_profile(tmp_path, "beta", "fact two\n", memories=False)
    (tmp_path / "not_a_profile.md").write_text("x", encoding="utf-8")
    names = [p.name for p in hd.iter_profiles(_cfg(tmp_path))]
    assert names == ["alpha"]


# -- first run / data boundary ------------------------------------------------


@with_tmp
def test_first_run_builds_full_bundle(tmp_path):
    _write_profile(tmp_path, "alpha", "first fact\n§\nsecond fact\n")
    cfg = _cfg(tmp_path)
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 0
    (rec,) = [r for r in records if r["profile"] == "alpha"]
    assert rec["status"] == "ok" and rec["added"] == 2 and rec["tombstoned"] == 0
    bundle_id = rec["bundle_id"]
    assert bundle_id == "hermes-alpha-20261115"
    bodies = sorted(r["body"] for r in _bundle_records(_root(cfg, "alpha"), bundle_id))
    assert bodies == ["first fact", "second fact"]
    for record in _bundle_records(_root(cfg, "alpha"), bundle_id):
        assert record["id"].startswith("rec:hermes:alpha:")
        assert len(record["id"].rsplit(":", 1)[1]) == 12
        assert record["provenance"]["source"] == "hermes:alpha"
        assert record["consent"]["exportable"] is True
        assert "sensitivity" not in record["provenance"]  # standard tier = marker absent


@with_tmp
def test_user_md_is_never_bundled(tmp_path):
    _write_profile(tmp_path, "alpha", "memory fact\n",
                   user_text="private user preference\n§\nmore pii\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    bundle_id = _runs(cfg, "alpha")[0]["bundle_id"]
    bodies = [r["body"] for r in _bundle_records(_root(cfg, "alpha"), bundle_id)]
    assert bodies == ["memory fact"]


@with_tmp
def test_secret_tier_profile_marks_secret_and_unexportable(tmp_path):
    _write_profile(tmp_path, "job_applicator", "job hunting fact\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    bundle_id = _runs(cfg, "job_applicator")[0]["bundle_id"]
    (record,) = _bundle_records(_root(cfg, "job_applicator"), bundle_id)
    assert record["provenance"]["sensitivity"] == "secret"
    assert record["consent"]["exportable"] is False


@with_tmp
def test_identical_duplicate_entries_collapse_to_one_record(tmp_path):
    _write_profile(tmp_path, "alpha", "same fact\n§\nsame fact\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    bundle_id = _runs(cfg, "alpha")[0]["bundle_id"]
    assert len(_bundle_records(_root(cfg, "alpha"), bundle_id)) == 1


# -- incremental behaviour ----------------------------------------------------


@with_tmp
def test_second_run_with_no_changes_is_ok_noop(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    records, code = hd.run_all(cfg, now=DAY2)
    assert code == 0
    (rec,) = records
    assert rec["status"] == "ok" and rec["bundle_id"] is None
    assert rec["detail"] == "no changes since last run"
    # no day-2 bundle was written
    assert not (_root(cfg, "alpha") / "bundles" / "hermes-alpha-20261116.json").exists()


@with_tmp
def test_new_entry_next_day_goes_into_incremental_bundle(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    _write_profile(tmp_path, "alpha", "fact one\n§\nfact two\n")
    records, code = hd.run_all(cfg, now=DAY2)
    assert code == 0
    (rec,) = records
    assert rec["added"] == 1 and rec["tombstoned"] == 0
    bundle = _bundle_records(_root(cfg, "alpha"), "hermes-alpha-20261116")
    assert [r["body"] for r in bundle] == ["fact two"]


@with_tmp
def test_modified_entry_tombstones_old_id_and_adds_new(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n§\nfact two\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    old_ids = _live_ids(_root(cfg, "alpha"))
    _write_profile(tmp_path, "alpha", "fact one edited\n§\nfact two\n")
    records, code = hd.run_all(cfg, now=DAY2)
    assert code == 0
    assert records[0]["tombstoned"] == 1 and records[0]["receipts"] == 1
    new_live = _live_ids(_root(cfg, "alpha"))
    assert len(new_live) == len(old_ids)  # one out, one in
    assert len(old_ids - new_live) == 1
    assert len(new_live - old_ids) == 1
    gone = next(iter(old_ids - new_live))
    service = mbcp.L1DeletionService(_root(cfg, "alpha"))
    # RFC §4 semantics: new record in the day-2 bundle, old id removed by a
    # real delete (journal tombstone + receipt) — never a bare manifest tombstone
    bundle = service.get_bundle("hermes-alpha-20261116")
    assert bundle["tombstones"] == []
    assert [r["body"] for r in bundle["records"]] == ["fact one edited"]
    journal_targets = [t["target_id"] for t in service.all_tombstones()]
    assert journal_targets == [gone]
    assert list(service.receipt_paths())  # a real receipt was issued


@with_tmp
def test_removed_entry_is_tombstoned(tmp_path):
    _write_profile(tmp_path, "alpha", "keep\n§\ndrop me\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    _write_profile(tmp_path, "alpha", "keep\n")
    records, code = hd.run_all(cfg, now=DAY2)
    assert code == 0
    assert records[0]["tombstoned"] == 1 and records[0]["receipts"] == 1
    live = _live_ids(_root(cfg, "alpha"))
    assert len(live) == 1
    service = mbcp.L1DeletionService(_root(cfg, "alpha"))
    journal_targets = [t["target_id"] for t in service.all_tombstones()]
    assert len(journal_targets) == 1


# -- fail-closed paths ---------------------------------------------------------


@with_tmp
def test_reappeared_tombstoned_id_fails_closed(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    _write_profile(tmp_path, "alpha", "fact one edited\n")
    hd.run_all(cfg, now=DAY2)  # tombstones the original id
    _write_profile(tmp_path, "alpha", "fact one\n")  # identical content back
    records, code = hd.run_all(cfg, now="2026-11-17T03:00:00Z")
    assert code == 1
    (rec,) = records
    assert rec["status"] == "failed"
    assert "tombstoned" in rec["detail"]
    # no day-3 bundle was written
    assert not (_root(cfg, "alpha") / "bundles" / "hermes-alpha-20261117.json").exists()


@with_tmp
def test_oversized_entry_fails_closed_instead_of_silent_skip(tmp_path):
    _write_profile(tmp_path, "alpha", "short\n§\n" + "x" * 100 + "\n")
    cfg = _cfg(tmp_path, max_entry_chars=50)
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 1
    (rec,) = records
    assert rec["status"] == "failed"
    assert "max_entry_chars" in rec["detail"]
    assert not (_root(cfg, "alpha") / "bundles").exists()


@with_tmp
def test_non_utf8_memory_fails_closed(tmp_path):
    base = _write_profile(tmp_path, "alpha", "")
    (base / "memories" / "MEMORY.md").write_bytes(b"\xff\xfe invalid")
    cfg = _cfg(tmp_path)
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 1
    assert records[0]["status"] == "failed"


@with_tmp
def test_run_all_continues_after_one_profile_fails(tmp_path):
    _write_profile(tmp_path, "alpha", "good fact\n")
    _write_profile(tmp_path, "beta", "x" * 100 + "\n")
    cfg = _cfg(tmp_path, max_entry_chars=50)
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 1
    by_name = {r["profile"]: r for r in records}
    assert by_name["alpha"]["status"] == "ok"
    assert by_name["beta"]["status"] == "failed"
    # both profiles got exactly one definite run record
    assert len(_runs(cfg, "alpha")) == 1
    assert len(_runs(cfg, "beta")) == 1


@with_tmp
def test_same_day_rerun_is_idempotent(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    bundle_file = _root(cfg, "alpha") / "bundles" / "hermes-alpha-20261115.json"
    before = bundle_file.read_bytes()
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 0
    assert records[0]["status"] == "ok"
    assert bundle_file.read_bytes() == before  # untouched


@with_tmp
def test_same_day_conflict_refuses_overwrite(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    bundle_file = _root(cfg, "alpha") / "bundles" / "hermes-alpha-20261115.json"
    before = bundle_file.read_bytes()
    _write_profile(tmp_path, "alpha", "fact one\n§\nlate addition\n")
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 1
    (rec,) = records
    assert rec["status"] == "failed"
    assert "refusing to overwrite" in rec["detail"]
    assert bundle_file.read_bytes() == before  # no retry-overwrite


# -- notification ---------------------------------------------------------------


def _notify_script(tmp_path):
    log = tmp_path / "notify.log"
    script = tmp_path / "notify.sh"
    script.write_text(f'#!/bin/sh\nprintf "%s\\n" "$1" >> "{log}"\n', encoding="utf-8")
    script.chmod(0o755)
    return script, log


@with_tmp
def test_notify_invoked_on_failure_only(tmp_path):
    script, log = _notify_script(tmp_path)
    _write_profile(tmp_path, "alpha", "x" * 100 + "\n")
    _write_profile(tmp_path, "beta", "fine\n")
    cfg = _cfg(tmp_path, max_entry_chars=50, notify_cmd=str(script))
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 1
    messages = log.read_text(encoding="utf-8").splitlines()
    assert len(messages) == 1  # only the failed profile notified
    assert "bundle build failed" in messages[0]
    assert "alpha" in messages[0]


@with_tmp
def test_successful_run_does_not_notify(tmp_path):
    script, log = _notify_script(tmp_path)
    _write_profile(tmp_path, "alpha", "fine\n")
    cfg = _cfg(tmp_path, notify_cmd=str(script))
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 0
    assert not log.exists()


@with_tmp
def test_notify_failure_does_not_mask_profile_result(tmp_path):
    _write_profile(tmp_path, "alpha", "x" * 100 + "\n")
    cfg = _cfg(tmp_path, max_entry_chars=50, notify_cmd="/bin/false")
    records, code = hd.run_all(cfg, now=DAY1)
    assert code == 1
    (rec,) = records
    assert rec["status"] == "failed"  # the real failure stands
    assert rec["notify"]["sent"] is False


# -- status ----------------------------------------------------------------------


@with_tmp
def test_status_expect_date_ok_and_missing(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    assert hd.status(cfg, expect_date="2026-11-15") == 0
    assert hd.status(cfg, expect_date="2026-11-16") == 1


@with_tmp
def test_status_flags_profile_without_runs(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    _write_profile(tmp_path, "beta", "fact two\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    # wipe beta's log to simulate a cron miss
    (Path(cfg["profiles_root"]) / "beta" / cfg["log_subdir"] / "runs.jsonl").unlink()
    assert hd.status(cfg, expect_date="2026-11-15") == 1


# -- delete ------------------------------------------------------------------------


@with_tmp
def test_delete_by_unique_substring_returns_verified_receipt(tmp_path):
    _write_profile(tmp_path, "alpha", "keep this fact\n§\nremove that fact\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    record = hd.delete_entry(cfg, "alpha", "remove that", "user-requested redaction")
    assert record["status"] == "ok" and record["receipt_ok"] is True
    live = _live_ids(_root(cfg, "alpha"))
    assert len(live) == 1
    runs = _runs(cfg, "alpha")
    assert runs[-1]["event"] == "delete" and runs[-1]["status"] == "ok"


@with_tmp
def test_delete_by_record_id(tmp_path):
    _write_profile(tmp_path, "alpha", "only fact\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    (rid,) = _live_ids(_root(cfg, "alpha"))
    record = hd.delete_entry(cfg, "alpha", rid, "test")
    assert record["status"] == "ok" and record["target_id"] == rid
    assert _live_ids(_root(cfg, "alpha")) == set()


@with_tmp
def test_delete_ambiguous_substring_is_typed(tmp_path):
    _write_profile(tmp_path, "alpha", "shared prefix one\n§\nshared prefix two\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    try:
        hd.delete_entry(cfg, "alpha", "shared prefix", "test")
    except hd.DispatcherError:
        pass
    else:
        raise AssertionError("DispatcherError not raised")


@with_tmp
def test_delete_no_match_is_typed(tmp_path):
    _write_profile(tmp_path, "alpha", "fact one\n")
    cfg = _cfg(tmp_path)
    hd.run_all(cfg, now=DAY1)
    try:
        hd.delete_entry(cfg, "alpha", "not present anywhere", "test")
    except hd.DispatcherError:
        pass
    else:
        raise AssertionError("DispatcherError not raised")


# -- CLI ----------------------------------------------------------------------------


@with_tmp
def test_cli_run_exit_codes(tmp_path):
    _write_profile(tmp_path, "alpha", "fine\n")
    _write_profile(tmp_path, "beta", "x" * 100 + "\n")
    cfg_path = _write_config(tmp_path, _cfg(tmp_path, max_entry_chars=50))
    assert hd.main(["run", "--config", str(cfg_path), "--now", DAY1]) == 1
    _write_profile(tmp_path, "beta", "fine now\n")
    assert hd.main(["run", "--config", str(cfg_path), "--now", DAY2]) == 0


@with_tmp
def test_cli_bad_config_exit_1(tmp_path):
    assert hd.main(["run", "--config", str(tmp_path / "missing.json")]) == 1
