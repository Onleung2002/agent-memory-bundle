# MBCP External Anchor Tool

Standalone third-party timestamp anchoring for MBCP deletion-receipt
digests. This tool is a **consumer** of MBCP, not a component:

- it never imports `mbcp/` (the canonical-replay module re-implements
  the SPEC 1.4 rules read-only; tests pin byte-equality against
  `mbcp.canonical` so the two cannot drift);
- it does not modify `mbcp/`, the receipt schema, SPEC/GOVERNANCE, the
  journal/tombstone/evidence layout, or `verify_receipt` behaviour;
- submission is pure stdlib (hand-built RFC3161 DER over HTTPS);
  token verification is delegated to the external `openssl ts` command.

## What it provides

**Third-party timestamped evidence**: verifiable evidence, from a trust
root outside the MBCP service root, that a receipt (or a journal
snapshot digest) existed at a point in time held by the TSA's clock.

**What it does not provide** (capability ceiling, verbatim from the
approved RFC): it does not provide protection against rewriting, it does
not protect against full-root recreation — a root writer can still
recreate a set of artifacts and re-anchor them, but the older token
makes two simultaneously-self-proclaimed-true versions detectable, which
is its real value — it provides no erasure assurance and no legal
effect.

**Trust-root statement** (verbatim from the approved RFC):

> 「RFC3161 timestamp 嘅信任根係該 TSA，唔係 MBCP。MBCP 對 TSA 嘅營運、
> 時鐘準確性、金鑰保管冇任何控制或背書。TSA snapshot 檔案由提交者自行
> out-of-band 核對後先入庫；呢個核對步驟唔由本工具自動完成。」

The default endpoint (freetsa.org) is a convenience endpoint, not a
trust endorsement; any RFC3161 TSA can be substituted via `--tsa` /
`--trust-url`. Free public TSAs carry no SLA.

## Layout (inside the bundle service root)

```
evidence/anchors/<digest>.tsr            RFC3161 token (DER)
evidence/anchors/<digest>.meta.json      submission metadata
evidence/anchors/<digest>.<n>.tsr        re-anchor of the same digest
evidence/anchors/trust/<host>/cacert.pem TSA trust-chain snapshot
evidence/anchors/pending.jsonl           append-only pending events
```

All anchor files are immutable: re-anchoring never overwrites; the next
free `.<n>` suffix is used. `pending.jsonl` is an append-only JSONL log
structurally homologous to the tombstone journal; a digest with a token
file is *anchored*, a digest with only pending events is *pending*, and
`status` shows both states honestly — pending is never reported as
success.

## Usage

Run from the repo root (`anchor` is a package; no installation needed).

```bash
# anchor every supersession chain-tail receipt + the journal snapshot
python3 -m anchor submit --root /path/to/root --chain-tails --journal

# anchor one receipt explicitly, or retry everything recorded pending
python3 -m anchor submit --root /path/to/root --receipt receipts/rcpt-....json
python3 -m anchor submit --root /path/to/root --retry-pending

# use a different TSA (trust URL = its PEM trust chain)
python3 -m anchor submit --root ... --chain-tails \
    --tsa https://example-tsa.example/tsr --trust-url https://example-tsa.example/cacert.pem

# verify one anchored digest (four steps, no network access)
python3 -m anchor verify --root /path/to/root --digest <hex64>

# anchored / pending overview
python3 -m anchor status --root /path/to/root
```

## Verification chain (third-party view)

A third party needs only `openssl`, the receipt file, and the stored
token + trust snapshot — no MBCP code except for the final step:

0. **anchor binding** — the token bytes must hash to the metadata's
   `token_sha256`; a mismatch means the anchor layer was modified and
   verification fails.
1. **token** — `openssl ts -reply -in <digest>.tsr -token_in -text` reads
   the message imprint, and `openssl ts -verify -in <digest>.tsr
   -token_in -digest <d> -CAfile
   evidence/anchors/trust/<host>/cacert.pem` verifies the imprint AND
   the TSA signature chain against the stored snapshot. (`python -m
   anchor verify` runs exactly this chain plus steps 0/2/3.)
2. **receipt** — the independent canonical-replay script
   (`anchor/canonical_replay.py`, zero `mbcp` imports) recomputes the
   receipt-body canonical SHA-256; it must equal the token imprint and
   the envelope's `integrity.digest`. For `journal_snapshot` anchors the
   replayed digest is the canonical digest of the tombstone array in
   file order instead.
3. **verify_receipt** — MBCP's own `verify_receipt` runs against the
   service root (in a subprocess; skipped for journal snapshots, which
   are not receipts). If MBCP is not importable this step fails closed.

Any failing step fails the whole verification and names the step.

## Failure modes (fail-closed)

| Situation | Behaviour |
|---|---|
| TSA unreachable / timeout / non-2xx | no anchor files written; `tsa_unreachable` / `tsa_non2xx` recorded in `pending.jsonl`; `--retry-pending` resubmits |
| Trust-chain snapshot fetch fails | no anchor files; `trust_chain_fetch_failed` recorded |
| Token imprint ≠ submitted digest, or openssl signature verification fails | token never stored; `token_rejected` recorded; a bad token is never silently accepted |
| Receipt digest changed on disk before or during submission | submission aborted; `stale_receipt` recorded; no anchor written for a preimage that no longer exists |
| Local write fails after a good submission | token bytes not retained; `persist_failed` recorded; any half-written token is rolled back |
| Verify step fails | explicit `FAIL` naming the step; there is no skip-verification-but-report-ok output |

## Anchored preimages

- **receipt** (`kind: receipt`): the canonical SHA-256 of the receipt
  *body* — the same preimage the envelope's `integrity.digest` commits
  to. Granule: each supersession chain's tail receipt (mid-chain
  receipts are covered by the tail).
- **journal snapshot** (`kind: journal_snapshot`): the canonical SHA-256
  of the JSON array of tombstone objects in `tombstones.jsonl`, in file
  order (empty journal → canonical of `[]`). Lets a third party phrase
  "no deletions were added after this point".

## Honesty notes

- The TSA trust-chain snapshot is fetched automatically but its
  authenticity must be checked **out-of-band by the submitter** before
  first use; the tool does not perform that check (see the trust-root
  statement above).
- `submitted_at` in the metadata is a local RFC3339 display timestamp;
  the authoritative time is the TSA's `genTime` inside the token.
- Terminology: this tool keeps the GOVERNANCE terminology law — it does
  not use "certi-" family words for any conformance claim, and the
  append-only pending log is not a transparency log. Tests enforce both
  (`tests/test_anchor_banned_words.py`).
