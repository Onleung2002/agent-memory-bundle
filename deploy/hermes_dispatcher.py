"""Hermes self-host dispatcher — deployment layer for RFC: Hermes Self-Host.

This is NOT part of the ``mbcp/`` library (RFC scope guard: the deployment
uses the library as-is and modifies nothing under ``mbcp/``). It is the
daily cron entry point that packages every Hermes profile's
``memories/MEMORY.md`` into per-profile MBCP service roots:

- one profile = one service root (``<profile>/memory/mbcp_root/``, B-Q2);
- one incremental bundle per profile per day — only records new or modified
  since the previous run, never a full snapshot (RFC §5);
- data boundary: ``MEMORY.md`` only — no chat transcripts, no USER.md
  (B-Q3), no PII beyond what the agent already wrote into MEMORY.md;
- every record carries ``provenance.source = "hermes:<profile>"`` (RFC §3);
- sensitivity tiering is deployment config, not library code (B-Q1, RFC §6):
  profiles listed in ``secret_tier_profiles`` get
  ``sensitivity="secret"`` + ``exportable=False`` (the library's build-path
  invariant rejects secret+exportable with ValueError); every other profile
  gets no sensitivity marker and ``exportable=True``.
- fail-closed (RFC §7): any build/validation/lock failure produces a typed
  per-profile failure record, nothing is half-written, the run continues
  with the remaining profiles, and a notification command (if configured)
  is invoked. Every profile gets exactly one definite "ok"/"failed" record
  per run — no silent grey zone.

Scope decisions (approved RFC text only; nothing invented):

- **Profile enumeration** scans ``profiles_root`` for directories holding
  ``memories/MEMORY.md`` (B-Q1: 磁碟全部 profile; job_applicator and
  translator are picked up automatically the day they appear — the secret
  tier is a config rule, not a per-profile hardcode). The config file is
  the single source of deployment rules (paths, tiers, notify); the
  enumeration itself is filesystem reality, the only list that cannot
  drift out of the code.
- **RFC §6's ``standard`` tier label has no library representation**: the
  sensitivity vocabulary is exactly {public, internal, sensitive, secret}
  and "standard" fails schema validation. Deployment mapping: standard
  tier = sensitivity marker ABSENT (schema: "records without the field
  stay valid"). Flagged in the worker report.
- **Modify/remove detection** is content-addressed: each MEMORY.md entry
  becomes an id from ``sha256("<profile>\n<entry>")[:12]``. Per approved
  RFC §4 semantics, an edited entry = ``put_bundle`` of the new record plus
  ``L1DeletionService.delete`` of the old id — the delete journalizes the
  tombstone (a tombstone inside a bundle manifest never reaches the
  journal and would be invisible to the write boundary and to
  ``all_tombstones()``) and issues a real receipt. The dispatcher cannot
  distinguish "edited" from "deleted from MEMORY.md" (both are a
  disappeared id); both get the journal tombstone + receipt, with a reason
  string saying the entry vanished from MEMORY.md.
- **Diff state is derived from the MBCP root itself** (bundle inventory +
  tombstone journal); the dispatcher keeps no separate state file.
- **Reappearing tombstoned id** (identical content re-added after a
  tombstone) would be rejected by the library's write boundary; the
  dispatcher detects it BEFORE put and fails the profile closed, because
  silently dropping a live fact would be a grey zone.
- **Same-day re-run**: the bundle id is ``hermes-<profile>-<YYYYMMDD>``.
  If that bundle already exists with identical canonical bytes the run is
  "ok (already present)"; with different bytes it is a failure (no
  retry-overwrite, RFC §7). A no-change day writes no bundle — the run
  record IS the definite outcome, so the §7.1 cron-miss watcher checks run
  records via ``status --expect-date``, not manifest existence.

Usage (cron):

    python3 deploy/hermes_dispatcher.py run    --config deploy/hermes_dispatcher.config.json
    python3 deploy/hermes_dispatcher.py status --config deploy/hermes_dispatcher.config.json --expect-date $(date +%F)
    python3 deploy/hermes_dispatcher.py delete --config deploy/hermes_dispatcher.config.json \
        --profile <profile> --target <record-id-or-unique-body-substring> --reason "<why>"
"""

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import mbcp
from importers.hermes import split_memory_entries  # one shared §-splitting rule

RECORD_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# tombstone reason for ids that vanished from MEMORY.md (edit or removal —
# indistinguishable at content level; see module docstring)
REASON_VANISHED = "entry no longer present in MEMORY.md (modified or removed)"

REQUIRED_CONFIG_KEYS = (
    "profiles_root",
    "root_subdir",
    "log_subdir",
    "owner",
    "secret_tier_profiles",
)

DEFAULTS = {
    "memories_dir": "memories",
    "memory_filename": "MEMORY.md",
    "notify_cmd": None,
    "max_entry_chars": 4096,
    "lock_timeout_seconds": 10.0,
}


class DispatcherError(Exception):
    """Typed deployment-layer error (fail-closed; never raised bare)."""


class ConfigError(DispatcherError):
    """Invalid or missing dispatcher config."""


def load_config(path):
    """Load and validate the dispatcher config (single source of rules)."""
    cfg_path = Path(path)
    try:
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
    except OSError as err:
        raise ConfigError(f"cannot read config {cfg_path}: {err}") from err
    except json.JSONDecodeError as err:
        raise ConfigError(f"config {cfg_path} is not valid JSON: {err}") from err
    if not isinstance(raw, dict):
        raise ConfigError(f"config {cfg_path} must be a JSON object")
    missing = [k for k in REQUIRED_CONFIG_KEYS if k not in raw]
    if missing:
        raise ConfigError(f"config {cfg_path} missing required keys: {missing}")
    cfg = dict(DEFAULTS)
    cfg.update(raw)
    if not isinstance(cfg["profiles_root"], str):
        raise ConfigError("profiles_root must be a string")
    if not Path(cfg["profiles_root"]).is_dir():
        raise ConfigError(f"profiles_root {cfg['profiles_root']!r} is not a directory")
    if not isinstance(cfg["secret_tier_profiles"], list) or not all(
        isinstance(n, str) for n in cfg["secret_tier_profiles"]
    ):
        raise ConfigError("secret_tier_profiles must be a list of profile names")
    if not isinstance(cfg["max_entry_chars"], int) or cfg["max_entry_chars"] < 1:
        raise ConfigError("max_entry_chars must be a positive integer")
    return cfg


def iter_profiles(cfg):
    """Enumerate profile dirs under profiles_root that hold a MEMORY.md.

    Sorted for deterministic run order. Directories without
    ``<memories_dir>/<memory_filename>`` are not profiles of this
    deployment (B-Q1: 磁碟全部 = every profile that actually has memory).
    """
    root = Path(cfg["profiles_root"])
    profiles = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        memory = child / cfg["memories_dir"] / cfg["memory_filename"]
        if memory.is_file():
            profiles.append(child)
    return profiles


def profile_paths(cfg, profile_name):
    """Resolve the per-profile MBCP root, log dir and run-record path."""
    base = Path(cfg["profiles_root"]) / profile_name
    root = base / cfg["root_subdir"]
    log_dir = base / cfg["log_subdir"]
    return root, log_dir, log_dir / "runs.jsonl"


def _append_run_record(cfg, profile_name, record):
    """Append one canonical JSONL run record (never inside the MBCP root)."""
    _root, log_dir, runs_path = profile_paths(cfg, profile_name)
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        with runs_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    except OSError as err:
        # Logging must never crash the run; the error is surfaced on stderr.
        print(f"dispatcher: WARNING cannot write run record for {profile_name}: {err}",
              file=sys.stderr)


def _notify(cfg, message):
    """Invoke the configured notification command; never masks the result."""
    cmd = cfg.get("notify_cmd")
    if not cmd:
        return {"sent": False, "detail": "notify_cmd not configured"}
    try:
        proc = subprocess.run(
            shlex.split(cmd) + [message],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as err:
        return {"sent": False, "detail": f"notify failed: {err}"}
    return {
        "sent": proc.returncode == 0,
        "detail": (proc.stderr or proc.stdout or "").strip()[:200],
    }


def content_record_id(profile, entry):
    """Content-addressed record id (RFC §4: profile + content hash)."""
    digest = hashlib.sha256(f"{profile}\n{entry}".encode("utf-8")).hexdigest()
    return f"rec:hermes:{profile}:{digest[:12]}"


def _check_id_grammars(profile):
    if not RECORD_ID_RE.match(f"rec:hermes:{profile}:{'x' * 12}"):
        raise DispatcherError(
            f"profile name {profile!r} does not fit the record id grammar"
        )
    if not BUNDLE_ID_RE.match(f"hermes-{profile}-20260101"):
        raise DispatcherError(
            f"profile name {profile!r} does not fit the bundle id grammar"
        )


def _read_entries(cfg, profile_name):
    """Read and split the profile's MEMORY.md into non-empty entries."""
    memory = (
        Path(cfg["profiles_root"])
        / profile_name
        / cfg["memories_dir"]
        / cfg["memory_filename"]
    )
    if not memory.is_file():
        raise DispatcherError(
            f"no {cfg['memories_dir']}/{cfg['memory_filename']} under profile dir"
        )
    try:
        text = memory.read_text(encoding="utf-8")
    except UnicodeDecodeError as err:
        raise DispatcherError(f"{memory} is not UTF-8: {err}") from err
    except OSError as err:
        raise DispatcherError(f"cannot read {memory}: {err}") from err
    entries = split_memory_entries(text)
    for entry in entries:
        if len(entry) > cfg["max_entry_chars"]:
            raise DispatcherError(
                f"entry of {len(entry)} chars exceeds max_entry_chars="
                f"{cfg['max_entry_chars']} (on_budget_exceed=skip would "
                "silently drop it — refusing, fail-closed)"
            )
    # identical entries collapse to one record (same content id)
    return list(dict.fromkeys(entries))


def _live_records(service):
    """Map record id -> containing bundle id for every LIVE record copy.

    Journal tombstones kill an id across the whole root (older bundles
    keep their copies on disk — MBCP is append-only), so tombstoned ids
    are excluded here; load-time/recover() semantics apply the same filter.
    """
    tombstoned = {
        mbcp.normalize_id(t["target_id"]) for t in service.all_tombstones()
    }
    live = {}
    for bundle_id in service.bundle_inventory():
        manifest = service.get_bundle(bundle_id)
        for record in manifest.get("records", []):
            if mbcp.normalize_id(record["id"]) in tombstoned:
                continue
            live.setdefault(record["id"], bundle_id)
    return live


def _make_bundle_id(profile, day):
    return f"hermes-{profile}-{day}"


def run_profile(cfg, profile_name, *, now=None, notify=True):
    """Run one profile's daily incremental bundle. Returns its run record.

    Fail-closed: any error becomes a ``status="failed"`` record; nothing is
    written to the MBCP root on failure. ``status="ok"`` with ``bundle_id``
    null means "no changes today" — a definite outcome, not a grey zone.
    """
    now = now or mbcp.utc_now()
    day = now[:10].replace("-", "")
    base = {"ts": now, "profile": profile_name, "event": "daily_bundle"}
    try:
        _check_id_grammars(profile_name)
        secret = profile_name in cfg["secret_tier_profiles"]
        entries = _read_entries(cfg, profile_name)
        current_ids = {content_record_id(profile_name, e): e for e in entries}

        root, _log_dir, _runs = profile_paths(cfg, profile_name)
        service = mbcp.L1DeletionService(root)
        live = _live_records(service)
        tombstoned = {
            mbcp.normalize_id(t["target_id"]) for t in service.all_tombstones()
        }

        reappeared = sorted(i for i in current_ids if mbcp.normalize_id(i) in tombstoned)
        if reappeared:
            raise DispatcherError(
                "entry reappeared with a tombstoned id (write boundary would "
                f"reject it, silently dropping a live fact): {reappeared}"
            )
        new_ids = sorted(i for i in current_ids if i not in live)
        gone = {rid: bid for rid, bid in live.items() if rid not in current_ids}

        bundle_id = _make_bundle_id(profile_name, day)
        record = dict(base, status="ok", bundle_id=None, added=0, tombstoned=0,
                      receipts=0)
        if not new_ids and not gone:
            record["detail"] = "no changes since last run"
            return record

        sensitivity = "secret" if secret else None
        exportable = not secret
        records = [
            mbcp.make_record(
                rid,
                "fact",
                current_ids[rid],
                cfg["owner"],
                source=f"hermes:{profile_name}",
                created=now,
                lifecycle="active",
                exportable=exportable,
                sensitivity=sensitivity,
                priority="standard",
                max_chars=cfg["max_entry_chars"],
                on_budget_exceed="skip",
                merge="append_first_wins",
            )
            for rid in new_ids
        ]
        manifest = mbcp.build_bundle(bundle_id, records=records)

        # Same-day bundle id: identical bytes = idempotent re-run; different
        # bytes = refuse (RFC §7: no retry-overwrite).
        existing = service.bundle_path(bundle_id)
        if existing.exists():
            if existing.read_bytes() == mbcp.canonical_bytes(manifest):
                record.update(bundle_id=bundle_id, added=0,
                              detail="already present (idempotent re-run)")
            else:
                raise DispatcherError(
                    f"bundle {bundle_id} already exists with different content; "
                    "refusing to overwrite (no retry-overwrite)"
                )
        else:
            service.put_bundle(manifest, lock_timeout=cfg["lock_timeout_seconds"])
            # round-trip check: the bundle we just wrote must read back equal
            if service.get_bundle(bundle_id) != manifest:
                raise DispatcherError(f"bundle {bundle_id} failed post-write readback")
            record.update(bundle_id=bundle_id, added=len(records))

        # Disappeared ids (edited or removed — indistinguishable at content
        # level): RFC §4 semantics = real delete with journal tombstone +
        # receipt, never a bare manifest tombstone.
        receipt_problems = []
        for rid, containing in sorted(gone.items()):
            receipt = service.delete(
                containing, rid, REASON_VANISHED,
                lock_timeout=cfg["lock_timeout_seconds"],
            )
            verdict = service.verify_receipt(receipt)
            record["tombstoned"] += 1
            record["receipts"] += 1
            if not verdict.get("ok"):
                receipt_problems.append(f"{rid}: {'; '.join(verdict.get('problems', []))}")
        if receipt_problems:
            raise DispatcherError("receipt verification failed: " + "; ".join(receipt_problems))
        return record
    except DispatcherError as err:
        record = dict(base, status="failed", bundle_id=None, added=0, tombstoned=0,
                      error_type=type(err).__name__, detail=str(err))
    except Exception as err:  # typed mbcp errors (ValidationError, LockTimeoutError, ...)
        record = dict(base, status="failed", bundle_id=None, added=0, tombstoned=0,
                      error_type=type(err).__name__, detail=str(err)[:500])
    if notify:
        record["notify"] = _notify(
            cfg, f"profile {profile_name}: {now[:10]} bundle build failed — {record['detail']}"
        )
    return record

def run_all(cfg, *, now=None, notify=True):
    """Run every enumerated profile; returns (records, exit_code)."""
    now = now or mbcp.utc_now()
    profiles = iter_profiles(cfg)
    if not profiles:
        raise DispatcherError(
            f"no profiles with {cfg['memories_dir']}/{cfg['memory_filename']} under {cfg['profiles_root']}"
        )
    records = []
    for profile_dir in profiles:
        record = run_profile(cfg, profile_dir.name, now=now, notify=notify)
        _append_run_record(cfg, profile_dir.name, record)
        records.append(record)
        line = json.dumps(record, sort_keys=True, ensure_ascii=False)
        print(line)
    exit_code = 0 if all(r["status"] == "ok" for r in records) else 1
    return records, exit_code


def _last_run_records(cfg):
    """Read the most recent run record per profile (profiles with a log)."""
    last = {}
    root = Path(cfg["profiles_root"])
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        _r, _ld, runs_path = profile_paths(cfg, child.name)
        if not runs_path.is_file():
            continue
        try:
            lines = runs_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                last[child.name] = json.loads(line)
            except json.JSONDecodeError:
                continue
            break
    return last


def status(cfg, *, expect_date=None, notify=False, out=sys.stdout):
    """Report per-profile last run status; optionally assert a date.

    ``--expect-date`` exits 1 unless every profile enumerated on disk has
    an "ok" run record for that date (the RFC §7.1 cron-miss watcher: run
    records, not manifest existence, are the source of truth).
    """
    last = _last_run_records(cfg)
    enumerated = [p.name for p in iter_profiles(cfg)]
    problems = []
    for name in enumerated:
        rec = last.get(name)
        if rec is None:
            problems.append(f"{name}: no run record at all")
            print(f"{name}\tNO-RUNS", file=out)
        else:
            print(f"{name}\t{rec.get('status')}\t{rec.get('ts')}\t{rec.get('detail') or ''}",
                  file=out)
    for name in sorted(set(last) - set(enumerated)):
        print(f"{name}\t(stale log; profile no longer on disk)", file=out)
    if expect_date:
        for name in enumerated:
            rec = last.get(name)
            if not rec or rec.get("status") != "ok" or not str(rec.get("ts", "")).startswith(expect_date):
                problems.append(
                    f"{name}: no ok run record for {expect_date} "
                    f"(last: {rec.get('ts') if rec else 'none'})"
                )
    for problem in problems:
        print(f"PROBLEM\t{problem}", file=out)
    if notify and problems:
        _notify(cfg, "hermes dispatcher status check failed: " + "; ".join(problems))
    return 1 if problems else 0


def delete_entry(cfg, profile_name, target, reason, *, now=None, out=sys.stdout):
    """Explicit user-requested deletion with a real L1 receipt.

    ``target`` is a record id or a body substring that must match exactly
    one live record. Calls ``L1DeletionService.delete`` and verifies the
    returned receipt with ``verify_receipt``.
    """
    now = now or mbcp.utc_now()
    _check_id_grammars(profile_name)
    root, _log_dir, _runs = profile_paths(cfg, profile_name)
    service = mbcp.L1DeletionService(root)
    live = _live_records(service)
    if not live:
        raise DispatcherError(f"profile {profile_name}: no live records in root")

    norm = mbcp.normalize_id(target)
    id_hits = {rid: bid for rid, bid in live.items() if mbcp.normalize_id(rid) == norm}
    if id_hits:
        matches = id_hits
    else:
        matches = {
            rid: bid for rid, bid in live.items() if target in _live_body(service, rid, bid)
        }
    if not matches:
        raise DispatcherError(f"profile {profile_name}: no live record matches {target!r}")
    if len(matches) > 1:
        raise DispatcherError(
            f"profile {profile_name}: {target!r} matches {len(matches)} live "
            f"records {sorted(matches)} — refine the target"
        )
    rid, bundle_id = next(iter(matches.items()))
    receipt = service.delete(
        bundle_id, rid, reason, lock_timeout=cfg["lock_timeout_seconds"]
    )
    verdict = service.verify_receipt(receipt)
    print(json.dumps({"receipt": receipt, "verify_receipt": verdict},
                     sort_keys=True, ensure_ascii=False), file=out)
    record = {
        "ts": now, "profile": profile_name, "event": "delete",
        "status": "ok" if verdict.get("ok") else "failed",
        "target_id": rid, "bundle_id": bundle_id, "reason": reason,
        "receipt_ok": bool(verdict.get("ok")),
        "detail": None if verdict.get("ok") else "; ".join(verdict.get("problems", [])),
    }
    _append_run_record(cfg, profile_name, record)
    return record


def _live_body(service, record_id, bundle_id):
    """Body of one live record copy (for substring matching)."""
    manifest = service.get_bundle(bundle_id)
    for record in manifest.get("records", []):
        if record["id"] == record_id:
            return record.get("body", "")
    return ""


def _today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="daily incremental bundle run (all profiles)")
    p_run.add_argument("--config", required=True)
    p_run.add_argument("--now", default=None, help="ISO timestamp override (tests/dry-runs)")

    p_status = sub.add_parser("status", help="per-profile run-record status")
    p_status.add_argument("--config", required=True)
    p_status.add_argument("--expect-date", default=None,
                          help="YYYY-MM-DD that must have an ok record for every profile")
    p_status.add_argument("--notify", action="store_true",
                          help="invoke notify_cmd when the check fails")

    p_del = sub.add_parser("delete", help="explicit deletion with a real L1 receipt")
    p_del.add_argument("--config", required=True)
    p_del.add_argument("--profile", required=True)
    p_del.add_argument("--target", required=True,
                       help="record id or unique body substring")
    p_del.add_argument("--reason", required=True)

    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
        if args.command == "run":
            _records, exit_code = run_all(cfg, now=args.now)
            return exit_code
        if args.command == "status":
            expect = args.expect_date or _today()
            return status(cfg, expect_date=expect, notify=args.notify)
        if args.command == "delete":
            record = delete_entry(cfg, args.profile, args.target, args.reason)
            return 0 if record["status"] == "ok" else 1
    except DispatcherError as err:
        print(f"dispatcher: {type(err).__name__}: {err}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
