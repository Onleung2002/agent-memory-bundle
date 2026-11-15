"""Anchor operations: submit a digest to an RFC3161 TSA, verify an
anchor chain, and report anchored/pending state.

Fail-closed table (RFC anchor tool 6) is implemented exactly:

- TSA unreachable / timeout / non-2xx  -> no anchor files written;
  a ``tsa_unreachable`` / ``tsa_non2xx`` event lands in
  ``evidence/anchors/pending.jsonl`` for the next run to retry.
- Token fails verification (imprint mismatch vs the requested digest,
  or openssl signature verification failure) -> not stored; pending
  records ``token_rejected``. A bad token is never silently accepted.
- Submission succeeded but a local write failed -> pending records
  ``persist_failed``; token bytes are not retained (re-submission is
  harmless: a TSA is stateless).
- Receipt digest changed on disk during submission (stale read) ->
  abort, no anchor written, pending records ``stale_receipt``.
- Any verify step failing -> explicit fail naming the step; there is no
  "skip verification but report ok" output. The verify command never
  touches the network.
- Anchor-layer modification (token bytes != meta ``token_sha256``) ->
  step 0 fails, naming the anchor layer as the mismatched party.

Trust-chain snapshots are fetched once per endpoint into
``evidence/anchors/trust/<host>/``; the snapshot's authenticity must be
checked out-of-band by the submitter before first use (the tool does not
perform that check — see the package docstring trust-root statement).
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .canonical_replay import canonical_sha256, json_loads_strict
from .rfc3161 import (
    STATUS_GRANTED,
    TSDecodeError,
    build_request,
    parse_response,
    parse_token,
)
from .store import (
    ANCHORS_REL,
    AnchorStore,
    AnchorStoreError,
    PersistError,
    build_meta,
)

KIND_RECEIPT = "receipt"
KIND_JOURNAL = "journal_snapshot"

DEFAULT_TSA = "https://freetsa.org/tsr"
DEFAULT_TRUST_URLS = {
    "freetsa.org": "https://freetsa.org/files/cacert.pem",
}

VERIFY_RECEIPT_SNIPPET = (
    "import sys, json;"
    "sys.path.insert(0, sys.argv[1]);"
    "from mbcp import L1DeletionService;"
    "svc = L1DeletionService(sys.argv[2]);"
    "print(json.dumps(svc.verify_receipt(sys.argv[3])))"
)


class AnchorError(Exception):
    """Base error for anchor operations (message is user-facing)."""


class SubmitError(AnchorError):
    """One submission failed; carries the pending-log category."""

    def __init__(self, message, *, event, detail=""):
        super().__init__(message)
        self.event = event
        self.detail = detail


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# digest computation (canonical replay, no mbcp import)
# ---------------------------------------------------------------------------

def receipt_digest(receipt):
    """Canonical SHA-256 of a receipt body — the anchored preimage.

    The preimage is the same one ``integrity.digest`` commits to (RFC
    anchor tool 3): the canonical bytes of the receipt *body* (the
    ``receipt`` field). Fail-closed: if the replayed digest does not
    equal the envelope's own ``integrity.digest``, the receipt is
    inconsistent and must not be anchored.
    """
    try:
        body = receipt["receipt"]
        claimed = receipt["integrity"]["digest"]
    except (KeyError, TypeError) as err:
        raise AnchorError(f"receipt missing field: {err}") from err
    replayed = canonical_sha256(body)
    if replayed != claimed:
        raise AnchorError(
            "receipt digest mismatch: integrity.digest does not match the "
            "canonical body (receipt is inconsistent; refusing to anchor)"
        )
    return replayed


def read_receipt(path):
    try:
        return json_loads_strict(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise AnchorError(f"receipt unreadable: {err}") from err


def journal_snapshot_digest(root):
    """Canonical digest of the whole tombstone journal (RFC anchor tool 3).

    Defined operationally as the SHA-256 of the canonical JSON array of
    the journal's tombstone objects, in file order (empty journal ->
    canonical of ``[]``). Journal lines are written canonically by the
    service, so this is order-faithful and byte-stable.
    """
    journal_path = Path(root) / "tombstones.jsonl"
    tombstones = []
    if journal_path.exists():
        with open(journal_path, "rb") as fh:
            for raw in fh:
                raw = raw.strip()
                if raw:
                    tombstones.append(json_loads_strict(raw.decode("utf-8")))
    return canonical_sha256(tombstones)


def chain_tail_receipts(root):
    """Chain-tail receipts: receipts no other receipt supersedes.

    Returns ``(tails, skipped)`` where ``tails`` is a list of
    ``(digest, path)`` and ``skipped`` lists paths that could not be
    anchored (unreadable or internally inconsistent receipts) with the
    reason. A mid-chain receipt has no incremental anchor value — the
    tail covers it (RFC anchor tool 3).
    """
    receipts_dir = Path(root) / "receipts"
    tails, skipped = [], []
    superseded = set()
    parsed = []
    if not receipts_dir.exists():
        return tails, skipped
    for path in sorted(receipts_dir.glob("*.json")):
        try:
            receipt = read_receipt(path)
            digest = receipt_digest(receipt)
        except AnchorError as err:
            skipped.append((path, str(err)))
            continue
        parsed.append((digest, path, receipt))
        supersedes = receipt["receipt"].get("supersedes")
        if supersedes:
            superseded.add(supersedes)
    for digest, path, _receipt in parsed:
        if digest not in superseded:
            tails.append((digest, path))
    return tails, skipped


# ---------------------------------------------------------------------------
# TSA client (stdlib)
# ---------------------------------------------------------------------------

def fetch_trust_chain(trust_url, *, timeout):
    """Fetch a TSA trust-chain snapshot (PEM bytes); fail-closed on error."""
    try:
        with urllib.request.urlopen(trust_url, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as err:
        raise SubmitError(
            f"trust-chain fetch returned HTTP {err.code}",
            event="trust_chain_fetch_failed",
            detail=f"http_status={err.code}",
        ) from err
    except (urllib.error.URLError, OSError) as err:
        raise SubmitError(
            f"trust-chain fetch failed: {err}",
            event="trust_chain_fetch_failed",
            detail=type(err).__name__,
        ) from err
    if not body.strip():
        raise SubmitError(
            "trust-chain fetch returned an empty body",
            event="trust_chain_fetch_failed",
            detail="empty_body",
        )
    return body


def submit_to_tsa(endpoint, request_bytes, *, timeout):
    """POST a TimeStampRequest; return the raw TimeStampResp body."""
    http_req = urllib.request.Request(
        endpoint,
        data=request_bytes,
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
        },
    )
    try:
        with urllib.request.urlopen(http_req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as err:
        raise SubmitError(
            f"TSA returned HTTP {err.code}",
            event="tsa_non2xx",
            detail=f"http_status={err.code}",
        ) from err
    except (urllib.error.URLError, OSError) as err:
        raise SubmitError(
            f"TSA unreachable: {err}",
            event="tsa_unreachable",
            detail=type(err).__name__,
        ) from err


def openssl_verify_token(token, digest, trust_path):
    """``openssl ts -verify`` a token against a trust snapshot.

    Verifies BOTH the message imprint (against ``digest``) and the TSA
    signature chain. Returns (ok, output).
    """
    result = subprocess.run(
        [
            "openssl", "ts", "-verify",
            "-token_in",
            "-in", "/dev/stdin",
            "-digest", digest,
            "-CAfile", str(trust_path),
        ],
        input=token,
        capture_output=True,
    )
    output = (result.stdout + result.stderr).decode("utf-8", "replace")
    return result.returncode == 0, output


def openssl_token_text(token):
    """``openssl ts -reply -text`` for one token; returns (rc, output)."""
    result = subprocess.run(
        ["openssl", "ts", "-reply", "-token_in", "-in", "/dev/stdin", "-text"],
        input=token,
        capture_output=True,
    )
    output = (result.stdout + result.stderr).decode("utf-8", "replace")
    return result.returncode, output


_IMPRINT_LINE = re.compile(
    r"^\s*[0-9a-fA-F]{4} - ((?:[0-9a-fA-F]{2}[ -]){15}[0-9a-fA-F]{2})"
)


def imprint_from_token_text(text):
    """Extract the message-imprint hex from ``openssl ts -reply -text``.

    Returns lowercase hex64, or None if the block is absent.
    """
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if "Message data:" in line:
            hex_parts = []
            for follow in lines[idx + 1:]:
                match = _IMPRINT_LINE.match(follow)
                if not match:
                    break
                hex_parts.append(match.group(1).replace(" ", "").replace("-", ""))
            if hex_parts:
                return "".join(hex_parts).lower()
    return None


def gen_time_from_token_text(text):
    for line in text.splitlines():
        if line.strip().startswith("Time stamp:"):
            return line.split(":", 1)[1].strip()
    return None


# ---------------------------------------------------------------------------
# submit
# ---------------------------------------------------------------------------

def _source_rel(root, source_path):
    try:
        return str(Path(source_path).resolve().relative_to(Path(root).resolve()))
    except ValueError:
        return str(source_path)


def submit_digest(store, digest, *, kind, source_path, endpoint,
                  trust_url=None, timeout=30, stale_check=True):
    """Anchor one digest: TSA submit -> token gates -> versioned store.

    Every failure path records one pending event and raises
    :class:`SubmitError`; no anchor files are written on any failure
    (fail-closed, RFC anchor tool 6).
    """
    root = store.root
    event_base = {
        "kind": kind,
        "digest": digest,
        "endpoint": endpoint,
        "source": _source_rel(root, source_path),
        "at": utc_now(),
    }

    def _fail(exc):
        store.append_pending({"event": exc.event, "detail": exc.detail,
                              **event_base})
        raise exc

    # Trust-chain snapshot must be available BEFORE the token is checked
    # (a token we cannot verify is never accepted).
    if trust_url is None:
        from urllib.parse import urlparse
        host = urlparse(endpoint).hostname
        trust_url = DEFAULT_TRUST_URLS.get(host)
    if trust_url is None:
        _fail(SubmitError(
            f"no trust-chain URL known for endpoint {endpoint!r}; "
            "pass --trust-url",
            event="trust_chain_fetch_failed",
            detail="unknown_endpoint",
        ))
    trust_path = store.trust_path(endpoint)
    if not trust_path.exists():
        try:
            store.write_trust(endpoint, fetch_trust_chain(
                trust_url, timeout=timeout))
        except SubmitError as err:
            _fail(err)
    trust_rel = str(trust_path.relative_to(root))

    # Stale-read guard #1: the digest must match what is on disk NOW.
    try:
        digest_now = _recompute_digest(root, kind, source_path)
    except AnchorError as err:
        _fail(SubmitError(
            f"artifact is no longer consistent on disk: {err}",
            event="stale_receipt",
            detail="pre-submit consistency loss",
        ))
    if stale_check and digest_now != digest:
        _fail(SubmitError(
            "stale read: digest of the on-disk artifact changed before "
            "submission",
            event="stale_receipt",
            detail="pre-submit digest drift",
        ))

    request_bytes = build_request(bytes.fromhex(digest))
    try:
        resp_body = submit_to_tsa(endpoint, request_bytes, timeout=timeout)
    except SubmitError as err:
        _fail(err)

    try:
        resp = parse_response(resp_body)
    except TSDecodeError as err:
        _fail(SubmitError(
            f"TSA response undecodable: {err}",
            event="token_rejected",
            detail="ts_decode_error",
        ))
    if resp["status"] != STATUS_GRANTED or resp["token"] is None:
        detail = f"status={resp['status']}"
        if resp["status_string"]:
            detail += f" status_string={resp['status_string']!r}"
        _fail(SubmitError(
            f"TSA did not grant the timestamp ({detail})",
            event="token_rejected",
            detail=detail,
        ))
    token = resp["token"]

    # Token gate 1: the imprint inside the token must be exactly the
    # digest we asked to timestamp (pure-Python parse, no trust needed).
    try:
        tst = parse_token(token)
    except TSDecodeError as err:
        _fail(SubmitError(
            f"token undecodable: {err}",
            event="token_rejected",
            detail="token_decode_error",
        ))
    imprint_hex = tst["imprint"].hex()
    if tst["algo_oid"] != "2.16.840.1.101.3.4.2.1":
        _fail(SubmitError(
            f"token imprint algorithm is {tst['algo_oid']}, not sha256",
            event="token_rejected",
            detail=f"algo_oid={tst['algo_oid']}",
        ))
    if imprint_hex != digest:
        _fail(SubmitError(
            "token imprint does not match the submitted digest",
            event="token_rejected",
            detail=f"imprint={imprint_hex}",
        ))

    # Token gate 2: openssl signature verification against the trust
    # snapshot (also re-checks the imprint).
    ok, output = openssl_verify_token(token, digest, trust_path)
    if not ok:
        _fail(SubmitError(
            "openssl token verification failed",
            event="token_rejected",
            detail=output.strip().splitlines()[-1][:200]
            if output.strip() else "openssl_verify_failed",
        ))

    # Stale-read guard #2: the artifact must not have changed while the
    # TSA request was in flight — never anchor a preimage that no longer
    # exists on disk.
    if stale_check:
        try:
            digest_after = _recompute_digest(root, kind, source_path)
        except AnchorError as err:
            _fail(SubmitError(
                f"artifact changed during submission: {err}",
                event="stale_receipt",
                detail="mid-flight consistency loss",
            ))
        if digest_after != digest:
            _fail(SubmitError(
                "stale read: digest of the on-disk artifact changed during "
                "submission; aborted, no anchor written",
                event="stale_receipt",
                detail="mid-flight digest drift",
            ))

    meta = build_meta(
        digest=digest,
        kind=kind,
        endpoint=endpoint,
        request_bytes=request_bytes,
        token_bytes=token,
        trust_rel_path=trust_rel,
        submitted_at=utc_now(),
    )
    try:
        store.write_anchor(digest, token, meta)
    except PersistError as err:
        _fail(SubmitError(
            f"local persist failed: {err}",
            event="persist_failed",
            detail=str(err)[:200],
        ))
    return meta


def _recompute_digest(root, kind, source_path):
    """Recompute the anchor digest straight from disk (stale-read guard)."""
    if kind == KIND_JOURNAL:
        return journal_snapshot_digest(root)
    return receipt_digest(read_receipt(source_path))


# ---------------------------------------------------------------------------
# verify (no network access; openssl + canonical replay + verify_receipt)
# ---------------------------------------------------------------------------

def _run_verify_receipt(mbcp_repo, root, receipt_path):
    """Step 3: run MBCP's own verify_receipt in a subprocess.

    The anchor tool never imports mbcp; the library is invoked against
    the service root exactly as a consumer would. If mbcp cannot be
    imported from ``mbcp_repo``, the step fails closed (never ok).
    """
    result = subprocess.run(
        [sys.executable, "-c", VERIFY_RECEIPT_SNIPPET,
         str(mbcp_repo), str(root), str(receipt_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        tail = (result.stderr or result.stdout).strip().splitlines()
        detail = tail[-1][:200] if tail else "subprocess failed"
        return False, f"verify_receipt could not run: {detail}"
    try:
        report = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return False, "verify_receipt returned undecodable output"
    if report.get("ok"):
        return True, "verify_receipt ok:True"
    problems = "; ".join(report.get("problems") or [])[:300]
    return False, f"verify_receipt ok:False ({problems})"


def verify_anchor(store, digest, *, kind=None, mbcp_repo=None):
    """Verify one anchored digest. Returns an ordered step report.

    Steps (RFC anchor tool 5):
      0. anchor-layer binding: token bytes must hash to meta's
         ``token_sha256`` (detects anchor-layer modification);
      1. token: imprint extraction + openssl signature verification
         against the stored trust-chain snapshot;
      2. receipt: canonical-replay digest == token imprint == (for
         receipts) the envelope's ``integrity.digest``;
      3. verify_receipt against the service root (receipts only).

    Any step failing fails the whole verification, naming the step.
    """
    steps = []

    def _step(name, ok, detail):
        steps.append({"step": name, "ok": ok, "detail": detail})
        return ok

    anchor = store.latest_anchor(digest)
    if anchor is None:
        _step("resolve", False, f"no anchor stored for digest {digest}")
        return {"digest": digest, "ok": False, "steps": steps}
    token_path, meta_path = anchor
    token = token_path.read_bytes()
    meta = store.read_meta(meta_path)
    if kind is None:
        kind = meta.get("kind", KIND_RECEIPT)

    # step 0: anchor-layer modification check
    binding_ok = (
        store.sha256_hex(token) == meta.get("token_sha256")
        and meta.get("receipt_digest") == digest
    )
    if not _step("0:anchor-binding", binding_ok,
                 "token bytes match meta token_sha256" if binding_ok else
                 "anchor layer modified: token bytes do not match meta "
                 "token_sha256 (or meta names a different digest)"):
        return {"digest": digest, "ok": False, "steps": steps}

    # step 1: token imprint + signature (openssl, local trust snapshot)
    rc, text = openssl_token_text(token)
    if rc != 0:
        _step("1:token", False, f"openssl could not read token: {text.strip()[:200]}")
        return {"digest": digest, "ok": False, "steps": steps}
    imprint = imprint_from_token_text(text)
    gen_time = gen_time_from_token_text(text)
    trust_path = store.root / meta["tsa_trust_chain_snapshot_path"]
    sig_ok, sig_out = openssl_verify_token(token, digest, trust_path)
    imprint_ok = imprint == digest
    step1_ok = imprint_ok and sig_ok
    detail_bits = []
    if gen_time:
        detail_bits.append(f"genTime {gen_time}")
    if imprint is None:
        detail_bits.append("no imprint parsed")
    elif not imprint_ok:
        detail_bits.append(f"imprint {imprint} != digest {digest}")
    if not sig_ok:
        tail = sig_out.strip().splitlines()
        detail_bits.append(tail[-1][:200] if tail else "openssl verify failed")
    _step("1:token", step1_ok,
          "; ".join(detail_bits) if step1_ok else
          "; ".join(detail_bits) or "token verification failed")
    if not step1_ok:
        return {"digest": digest, "ok": False, "steps": steps}

    # step 2: receipt-side replay
    try:
        if kind == KIND_JOURNAL:
            replayed = journal_snapshot_digest(store.root)
            claimed = digest
        else:
            receipt_path = _find_receipt_by_digest(store.root, digest)
            if receipt_path is None:
                raise AnchorError(
                    "no on-disk receipt has integrity.digest == anchored digest"
                )
            receipt = read_receipt(receipt_path)
            replayed = receipt_digest(receipt)
            claimed = receipt["integrity"]["digest"]
    except AnchorError as err:
        _step("2:receipt", False, str(err))
        return {"digest": digest, "ok": False, "steps": steps}
    step2_ok = replayed == imprint == claimed
    _step("2:receipt", step2_ok,
          f"canonical replay digest == token imprint == integrity.digest "
          f"({digest})" if step2_ok else
          f"digest mismatch: replay={replayed} imprint={imprint} "
          f"claimed={claimed}")
    if not step2_ok:
        return {"digest": digest, "ok": False, "steps": steps}

    # step 3: verify_receipt (receipts only; a journal snapshot has no
    # receipt-style verification entry point — steps 0-2 are its chain)
    if kind == KIND_JOURNAL:
        _step("3:verify_receipt", True,
              "journal snapshot: no verify_receipt step (not a receipt)")
    else:
        ok, detail = _run_verify_receipt(
            mbcp_repo or _default_mbcp_repo(), store.root,
            _find_receipt_by_digest(store.root, digest))
        _step("3:verify_receipt", ok, detail)

    return {
        "digest": digest,
        "ok": all(s["ok"] for s in steps),
        "steps": steps,
        "token_path": str(token_path),
        "meta_path": str(meta_path),
    }


def _default_mbcp_repo():
    return Path(__file__).resolve().parent.parent


def _find_receipt_by_digest(root, digest):
    receipts_dir = Path(root) / "receipts"
    if not receipts_dir.exists():
        return None
    for path in sorted(receipts_dir.glob("*.json")):
        try:
            receipt = read_receipt(path)
        except AnchorError:
            continue
        if receipt.get("integrity", {}).get("digest") == digest:
            return path
    return None


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def collect_status(store):
    """Anchored vs pending state, shown as two honest states (RFC 6)."""
    anchored_by_digest = {}
    if store.anchors_dir.exists():
        for meta_path in sorted(store.anchors_dir.glob("*.meta.json")):
            try:
                meta = store.read_meta(meta_path)
            except (OSError, ValueError):
                continue
            digest = meta.get("receipt_digest", "?")
            if not _looks_like_digest(digest):
                continue
            entry = anchored_by_digest.setdefault(digest, {
                "digest": digest,
                "kind": meta.get("kind"),
                "versions": 0,
                "submitted_at": meta.get("submitted_at"),
                "endpoint": meta.get("tsa_endpoint"),
            })
            entry["versions"] = len(store.token_paths(digest))
            if meta.get("submitted_at", "") >= entry["submitted_at"]:
                entry["submitted_at"] = meta.get("submitted_at")
                entry["endpoint"] = meta.get("tsa_endpoint")
    anchored = sorted(anchored_by_digest.values(),
                      key=lambda item: item["digest"])
    pending_by_digest = {}
    for event in store.pending_events():
        digest = event.get("digest", "?")
        entry = pending_by_digest.setdefault(digest, {"events": []})
        entry["events"].append(event)
    for digest in list(pending_by_digest):
        if _looks_like_digest(digest) and store.token_paths(digest):
            del pending_by_digest[digest]  # anchored since: event is history
    return {"anchored": anchored, "pending": pending_by_digest}


def _looks_like_digest(value):
    return isinstance(value, str) and len(value) == 64 and all(
        c in "0123456789abcdef" for c in value)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_report(report):
    for step in report["steps"]:
        mark = "ok" if step["ok"] else "FAIL"
        print(f"  [{mark}] {step['step']}: {step['detail']}")
    print(f"{'OK' if report['ok'] else 'FAIL'} {report['digest']}")
    return 0 if report["ok"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="anchor",
        description="Third-party RFC3161 timestamp anchoring for MBCP "
                    "deletion-receipt digests (standalone consumer tool).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_submit = sub.add_parser("submit", help="anchor digest(s) with a TSA")
    p_submit.add_argument("--root", required=True, help="bundle service root")
    p_submit.add_argument("--receipt", action="append", default=[],
                          help="receipt file to anchor (repeatable)")
    p_submit.add_argument("--chain-tails", action="store_true",
                          help="anchor every supersession chain tail")
    p_submit.add_argument("--journal", action="store_true",
                          help="anchor the tombstone journal snapshot digest")
    p_submit.add_argument("--retry-pending", action="store_true",
                          help="retry digests recorded in pending.jsonl")
    p_submit.add_argument("--tsa", default=DEFAULT_TSA,
                          help="RFC3161 endpoint URL")
    p_submit.add_argument("--trust-url", default=None,
                          help="TSA trust-chain (PEM) URL for this endpoint")
    p_submit.add_argument("--timeout", type=int, default=30)

    p_verify = sub.add_parser("verify", help="verify one anchored digest")
    p_verify.add_argument("--root", required=True)
    p_verify.add_argument("--digest", required=True)
    p_verify.add_argument("--kind", choices=[KIND_RECEIPT, KIND_JOURNAL],
                          default=None)
    p_verify.add_argument("--mbcp-repo", default=None,
                          help="path containing the mbcp package (default: "
                               "the repo this tool ships in)")

    p_status = sub.add_parser("status", help="anchored / pending state")
    p_status.add_argument("--root", required=True)

    args = parser.parse_args(argv)
    store = AnchorStore(Path(args.root).resolve())

    if args.command == "status":
        state = collect_status(store)
        print(f"root: {store.root}")
        print(f"anchors dir: {store.root / ANCHORS_REL}")
        print(f"anchored: {len(state['anchored'])}")
        for item in state["anchored"]:
            print(f"  [anchored] {item['digest']} kind={item['kind']} "
                  f"versions={item['versions']} at={item['submitted_at']} "
                  f"via={item['endpoint']}")
        print(f"pending: {len(state['pending'])}")
        for digest, entry in state["pending"].items():
            latest = entry["events"][-1]
            print(f"  [pending] {digest} last_event={latest['event']} "
                  f"kind={latest.get('kind')} at={latest.get('at')} "
                  f"detail={latest.get('detail', '')}")
        return 0

    if args.command == "verify":
        report = verify_anchor(
            store, args.digest, kind=args.kind,
            mbcp_repo=args.mbcp_repo,
        )
        return _print_report(report)

    # submit
    jobs = []  # (digest, kind, source_path)
    if args.chain_tails:
        tails, skipped = chain_tail_receipts(store.root)
        for path, reason in skipped:
            print(f"skip (not anchorable): {path}: {reason}", file=sys.stderr)
        for digest, path in tails:
            jobs.append((digest, KIND_RECEIPT, path))
    for receipt_path in args.receipt:
        receipt = read_receipt(receipt_path)
        jobs.append((receipt_digest(receipt), KIND_RECEIPT, receipt_path))
    if args.journal:
        jobs.append((journal_snapshot_digest(store.root), KIND_JOURNAL,
                     store.root / "tombstones.jsonl"))
    if args.retry_pending:
        for event in store.pending_events():
            digest = event.get("digest", "")
            if not _looks_like_digest(digest) or store.token_paths(digest):
                continue
            kind = event.get("kind", KIND_RECEIPT)
            source = store.root / event.get("source", "")
            if not source.exists():
                print(f"pending retry skipped (source gone): {digest}",
                      file=sys.stderr)
                continue
            jobs.append((digest, kind, source))
    if not jobs:
        print("nothing to anchor", file=sys.stderr)
        return 1

    failures = 0
    for digest, kind, source_path in jobs:
        try:
            meta = submit_digest(
                store, digest, kind=kind, source_path=source_path,
                endpoint=args.tsa, trust_url=args.trust_url,
                timeout=args.timeout,
            )
        except SubmitError as err:
            failures += 1
            print(f"FAIL {digest} ({kind}): {err} "
                  f"[pending event: {err.event}]", file=sys.stderr)
            continue
        print(f"anchored {digest} ({kind}) -> {meta['tsa_endpoint']} "
              f"(token_sha256={meta['token_sha256'][:16]}…)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
