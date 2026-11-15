# Hermes self-host dispatcher (RFC-B deployment layer)

Deployment-layer tooling that packages every Hermes profile's
`memories/MEMORY.md` into per-profile MBCP service roots. It uses the
`mbcp/` library strictly through its public API and modifies nothing under
`mbcp/` (RFC scope guard). The library stays a pure spec+suite repo; all
runtime data lives on disk under `/opt/data/profiles/<profile>/memory/`,
never in git.

Honest framing (RFC §9): this is an *internal daily use by the Hermes
profile system (self-hosted)* — not a public external adoption, and no
stronger protection-grade claim than verification.

## Files

- `hermes_dispatcher.py` — the dispatcher (`run` / `status` / `delete`).
- `hermes_dispatcher.config.json` — the single source of deployment rules
  (paths, sensitivity tiers, notify hook). No secrets; nothing here may
  ever point at a key file or `.env`.
- `hermes_dispatcher.cron` — the daily 03:00 run line plus the 06:00
  cron-miss watcher line (RFC §5/§7). Install is a manual ops step:
  `crontab -l | cat - deploy/hermes_dispatcher.cron | crontab -`.

## Layout per profile (created on first run)

```
/opt/data/profiles/<profile>/memory/
    mbcp_root/                 # the MBCP service root (B-Q2); library-managed
    dispatcher/runs.jsonl      # one definite ok/failed record per run per day
```

Run records — not manifest existence — are the §7.1 source of truth: a
no-change day writes no bundle but still writes an `ok` record.

## Sensitivity tiers (deployment config, RFC §6)

- `secret_tier_profiles` in the config (currently `job_applicator`, which
  does not exist on disk yet — the rule fires automatically the day it
  appears): `sensitivity="secret"`, `exportable=false`. The library's
  build-path invariant rejects secret+exportable with ValueError.
- every other profile: no sensitivity marker, `exportable=true`. Note the
  RFC table's `standard` label is not a library vocabulary value
  ({public, internal, sensitive, secret}); deployment mapping is "marker
  absent" (flagged in the worker report).

## Failure modes (RFC §7, fail-closed)

Any schema/validation/sensitivity/lock error, oversized entry, reappearing
tombstoned id, or same-day bundle conflict turns into a typed `failed` run
record for that profile: nothing is half-written, no retry-overwrite, the
run continues with the other profiles, and `notify_cmd` (if configured) is
invoked with a plain-text message. Per-profile outcomes are never silent.

## Delete

`delete --profile P --target T --reason R` removes one live fact with a
real L1 deletion receipt (`T` = record id or a body substring matching
exactly one live record). Entries that vanish from MEMORY.md between daily
runs (edit or removal — indistinguishable at content level) are handled
the same way during the daily run: `put_bundle` for new content plus
`L1DeletionService.delete` per disappeared id, so every removal lands in
the tombstone journal with a verified receipt (RFC §4 append-only
semantics).
