"""RFC-A anchor tool tests — offline, with a local fake TSA.

The fake TSA is an http.server on 127.0.0.1 whose timestamps are real
RFC3161 tokens signed by a throwaway test CA (openssl-generated once per
process). Every test exercises the REAL code path — real DER, real
openssl verification, real store layout — with only the network
endpoint and the trust root faked. No test contacts an external service.

Zero-argument test functions throughout: the stdlib fallback runner
(tools/run_tests.py) skips fixture-parameterised tests, so everything
here builds its fixtures inside the test body.
"""

import http.server
import json
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from anchor import rfc3161, tool
from anchor.canonical_replay import (
    NonFiniteConstantError,
    canonical_bytes,
    canonical_sha256,
    json_loads_strict,
)
from anchor.store import AnchorStore, AnchorStoreError
from anchor.tool import AnchorError, SubmitError
from mbcp import (
    L1DeletionService,
    build_bundle,
    build_receipt,
    canonical_sha256 as mbcp_sha256,
    make_record,
    make_tombstone,
)
from mbcp import canonical_bytes as mbcp_canonical_bytes
from syn import FIXED_TS, syn_keypair

DELETED_AT = "2026-11-05T09:00:00Z"


# ---------------------------------------------------------------------------
# process-wide throwaway CA + fake TSA server
# ---------------------------------------------------------------------------

def _sh(*args, cwd=None):
    return subprocess.run(list(args), capture_output=True, check=True,
                          cwd=cwd)


_CA = None


def _ca():
    """One throwaway CA + TSA cert (with timeStamping EKU) per process."""
    global _CA
    if _CA is None:
        ca_dir = Path(tempfile.mkdtemp(prefix="anchor-test-ca-"))
        _sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout",
            "ca.key", "-out", "ca.crt", "-days", "1", "-nodes",
            "-subj", "/CN=anchor-test-ca", cwd=ca_dir)
        _sh("openssl", "req", "-newkey", "rsa:2048", "-keyout", "tsa.key",
            "-out", "tsa.csr", "-nodes", "-subj", "/CN=anchor-test-tsa",
            cwd=ca_dir)
        (ca_dir / "ext.cnf").write_text(
            "extendedKeyUsage = critical,timeStamping\n")
        (ca_dir / "demoCA").mkdir()
        (ca_dir / "demoCA" / "tsaserial").write_text("01\n")
        _sh("openssl", "x509", "-req", "-in", "tsa.csr", "-CA", "ca.crt",
            "-CAkey", "ca.key", "-CAcreateserial", "-out", "tsa.crt",
            "-days", "1", "-extfile", "ext.cnf", cwd=ca_dir)
        _CA = {
            "dir": ca_dir,
            "ca_crt": ca_dir / "ca.crt",
            "tsa_key": ca_dir / "tsa.key",
            "tsa_crt": ca_dir / "tsa.crt",
            "serial": [0],
        }
    return _CA


def _openssl_token(ca, digest_hex, out_path):
    q = out_path.parent / (out_path.name + ".tsq")
    _sh("openssl", "ts", "-query", "-digest", digest_hex, "-sha256",
        "-cert", "-out", str(q))
    _sh("openssl", "ts", "-reply", "-queryfile", str(q), "-inkey",
        str(ca["tsa_key"]), "-signer", str(ca["tsa_crt"]), "-chain",
        str(ca["ca_crt"]), "-out", str(out_path), "-token_out")
    return out_path.read_bytes()


class _FakeTSAHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/cacert.pem":
            body = self.server.ca["ca_crt"].read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-pem-file")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        query = self.rfile.read(int(self.headers["Content-Length"]))
        if self.server.on_query is not None:
            self.server.on_query(query)
        if self.server.status_code != 200:
            self.send_response(self.server.status_code)
            self.end_headers()
            return
        ca = self.server.ca
        ca["serial"][0] += 1
        tmp = ca["dir"] / f"handler-token-{ca['serial'][0]}.p7"
        digest_hex = self.server.sign_digest
        if digest_hex is None:
            digest_hex = rfc3161.parse_request_imprint(query).hex()
        token = _openssl_token(ca, digest_hex, tmp)
        # a real TSA returns a TimeStampResp (PKIStatusInfo + token), not
        # the bare token — wrap exactly like the wire format
        body = rfc3161._der_seq(
            rfc3161._der_seq(rfc3161._der_int(0)), token)
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeTSA:
    """Context manager: a live local TSA on an ephemeral port."""

    def __init__(self):
        self.ca = _ca()
        self.sign_digest = None     # None -> sign the queried digest
        self.status_code = 200
        self.on_query = None
        self._server = http.server.HTTPServer(
            ("127.0.0.1", 0), _FakeTSAHandler)
        self._server.ca = self.ca
        self._server.sign_digest = None
        self._server.status_code = 200
        self._server.on_query = None
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        host, port = self._server.server_address
        self.endpoint = f"http://{host}:{port}/tsr"
        self.trust_url = f"http://{host}:{port}/cacert.pem"
        # proxy hook attributes onto the server for the handler
        self._sync()
        return self

    def _sync(self):
        self._server.sign_digest = self.sign_digest
        self._server.status_code = self.status_code
        self._server.on_query = self.on_query

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()


# ---------------------------------------------------------------------------
# service-root fixture helper
# ---------------------------------------------------------------------------

def _service(root):
    svc = L1DeletionService(root, clock=lambda: DELETED_AT)
    svc.put_bundle(build_bundle(
        "bundle-alpha",
        records=[
            make_record("rec-001", "fact", "synthetic one", "user-syn",
                        created=FIXED_TS),
            make_record("rec-002", "fact", "synthetic two", "user-syn",
                        created=FIXED_TS),
        ],
    ))
    return svc


def _receipt_path(svc, receipt):
    return svc.receipts_dir / (receipt["receipt"]["id"] + ".json")


def _submit(store, digest, kind, source, endpoint, trust_url):
    return tool.submit_digest(
        store, digest, kind=kind, source_path=source,
        endpoint=endpoint, trust_url=trust_url, timeout=10,
    )


# ---------------------------------------------------------------------------
# canonical replay anti-drift
# ---------------------------------------------------------------------------

def test_replay_matches_mbcp_canonical_on_value_corpus():
    corpus = [
        {},
        [],
        {"b": 1, "a": {"y": [True, None, 1.5], "x": "héllo 世界"}},
        {"ts": "2026-11-05T08:00:00.123456+08:00", "n": 0, "s": "tab\tnl\n"},
        [1, "two", {"three": [3]}, False],
        {"emoji": "🫠", "empty": "", "zero": 0, "neg": -7, "float": 2.0},
    ]
    for value in corpus:
        assert canonical_bytes(value) == mbcp_canonical_bytes(value)
        assert canonical_sha256(value) == mbcp_sha256(value)


def test_replay_matches_mbcp_on_real_receipt_fixture():
    # anti-drift on the actual anchored artifact shape: the receipt BODY
    # is the anchor preimage (RFC anchor tool 3).
    keypair = syn_keypair()
    tombstone = make_tombstone("rec-002", "synthetic erasure",
                               deleted_at=DELETED_AT)
    removed = [{"id": "rec-002", "integrity": {"digest": "ab" * 32}}]
    receipt = build_receipt("bundle-alpha", tombstone, removed,
                            issued_at=FIXED_TS, keypair=keypair)
    body = receipt["receipt"]
    assert canonical_sha256(body) == mbcp_sha256(body)
    assert canonical_sha256(body) == receipt["integrity"]["digest"]
    assert tool.receipt_digest(receipt) == receipt["integrity"]["digest"]


def test_replay_rejects_nonfinite_constants():
    for bad in ("NaN", "Infinity", "-Infinity"):
        try:
            json_loads_strict('{"x": %s}' % bad)
        except NonFiniteConstantError:
            pass
        else:
            raise AssertionError(f"{bad} was accepted")


# ---------------------------------------------------------------------------
# RFC3161 DER layer
# ---------------------------------------------------------------------------

def test_request_roundtrip_parsed_by_openssl():
    # our hand-built DER request must be accepted by openssl as a query
    digest = bytes(range(32))
    req = rfc3161.build_request(digest, nonce=b"\x01" * 16)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "tok.p7"
        token = _openssl_token(_ca(), digest.hex(), out)
        tst = rfc3161.parse_token(token)
        assert tst["imprint"] == digest
        assert tst["algo_oid"] == "2.16.840.1.101.3.4.2.1"
        assert tst["gen_time"].endswith("Z")
        # and the request's own imprint decodes back
        assert rfc3161.parse_request_imprint(req) == digest


def test_parse_response_rejects_non_granted_status():
    bad = rfc3161._der_seq(rfc3161._der_seq(rfc3161._der_int(2)))
    resp = rfc3161.parse_response(bad)
    assert resp["status"] == 2
    assert resp["token"] is None


def test_parse_response_rejects_garbage():
    for garbage in (b"", b"\x30", b"\x31\x00", b"\x30\x03\x02\x01\x00"):
        try:
            rfc3161.parse_response(garbage)
        except rfc3161.TSDecodeError:
            pass
        else:
            raise AssertionError(f"garbage {garbage!r} was accepted")


def test_parse_token_rejects_truncated_token():
    try:
        rfc3161.parse_token(b"\x30\x82\x10")
    except rfc3161.TSDecodeError:
        pass
    else:
        raise AssertionError("truncated token was accepted")


# ---------------------------------------------------------------------------
# store: immutability + versioning + pending log
# ---------------------------------------------------------------------------

def test_store_versioned_writes_never_overwrite():
    with tempfile.TemporaryDirectory() as tmp:
        store = AnchorStore(Path(tmp) / "root")
        meta1 = {"receipt_digest": "ab" * 32, "token_sha256": "1"}
        meta2 = {"receipt_digest": "ab" * 32, "token_sha256": "2"}
        store.write_anchor("ab" * 32, b"token-one", meta1)
        store.write_anchor("ab" * 32, b"token-two", meta2)
        paths = store.token_paths("ab" * 32)
        assert [p.name for p in paths] == [
            "ab" * 32 + ".tsr", "ab" * 32 + ".1.tsr"]
        assert paths[0].read_bytes() == b"token-one"  # first untouched
        assert paths[1].read_bytes() == b"token-two"
        assert store.latest_anchor("ab" * 32)[0] == paths[1]


def test_store_pending_append_only_and_readback():
    with tempfile.TemporaryDirectory() as tmp:
        store = AnchorStore(Path(tmp) / "root")
        store.append_pending({"event": "tsa_unreachable", "digest": "cd" * 32})
        store.append_pending({"event": "token_rejected", "digest": "cd" * 32})
        events = store.pending_events()
        assert [e["event"] for e in events] == [
            "tsa_unreachable", "token_rejected"]
        # readback is strict-JSON: a NaN line must not parse silently
        with open(store.pending_path, "ab") as fh:
            fh.write(b'{"event": NaN}\n')
        try:
            store.pending_events()
        except NonFiniteConstantError:
            pass
        else:
            raise AssertionError("NaN pending line was accepted")


def test_store_write_anchor_rejects_malformed_digest():
    with tempfile.TemporaryDirectory() as tmp:
        store = AnchorStore(Path(tmp) / "root")
        try:
            store.write_anchor("not-a-digest", b"x", {})
        except AnchorStoreError:
            pass
        else:
            raise AssertionError("malformed digest was accepted")


# ---------------------------------------------------------------------------
# submit: fail-closed table
# ---------------------------------------------------------------------------

def test_submit_happy_path_writes_anchor_and_meta():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        path = _receipt_path(svc, receipt)
        meta = _submit(store, digest, tool.KIND_RECEIPT, path,
                       tsa.endpoint, tsa.trust_url)
        assert meta["receipt_digest"] == digest
        assert meta["kind"] == "receipt"
        token_file = store.anchors_dir / f"{digest}.tsr"
        assert meta["token_sha256"] == store.sha256_hex(token_file.read_bytes())
        # the request carries a fresh nonce, so only its shape is pinned
        assert len(meta["request_sha256"]) == 64
        assert meta["request_sha256"] != meta["token_sha256"]
        assert meta["tsa_trust_chain_snapshot_path"].endswith(
            "trust/127.0.0.1/cacert.pem")
        assert store.pending_events() == []
        # trust snapshot stored once and immutable across re-anchors
        trust = store.trust_path(tsa.endpoint)
        before = trust.read_bytes()
        _submit(store, digest, tool.KIND_RECEIPT, path,
                tsa.endpoint, tsa.trust_url)
        assert trust.read_bytes() == before
        # re-anchor of the same digest versions up, never overwrites
        assert len(store.token_paths(digest)) == 2


def test_submit_non2xx_records_pending_and_writes_nothing():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        tsa.status_code = 503
        tsa._sync()
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        try:
            _submit(store, digest, tool.KIND_RECEIPT,
                    _receipt_path(svc, receipt), tsa.endpoint, tsa.trust_url)
        except SubmitError as exc:
            assert exc.event == "tsa_non2xx"
        else:
            raise AssertionError("non-2xx was accepted")
        assert store.token_paths(digest) == []
        events = store.pending_events()
        assert len(events) == 1 and events[0]["event"] == "tsa_non2xx"


def test_submit_unreachable_records_pending_and_writes_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        try:
            tool.submit_digest(
                store, digest, kind=tool.KIND_RECEIPT,
                source_path=_receipt_path(svc, receipt),
                endpoint="http://127.0.0.1:1/tsr", trust_url=None,
                timeout=3)
        except SubmitError as exc:
            # either the trust fetch or the TSA call fails first; both
            # are fail-closed pending categories
            assert exc.event in (
                "tsa_unreachable", "trust_chain_fetch_failed")
        else:
            raise AssertionError("unreachable TSA was accepted")
        assert store.token_paths(digest) == []


def test_submit_token_rejected_on_imprint_mismatch():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        tsa.sign_digest = "12" * 32   # sign a DIFFERENT digest
        tsa._sync()
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        try:
            _submit(store, digest, tool.KIND_RECEIPT,
                    _receipt_path(svc, receipt), tsa.endpoint, tsa.trust_url)
        except SubmitError as exc:
            assert exc.event == "token_rejected"
        else:
            raise AssertionError("mismatched imprint was accepted")
        assert store.token_paths(digest) == []
        assert store.pending_events()[-1]["event"] == "token_rejected"


def test_submit_stale_read_detected_mid_flight():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        path = _receipt_path(svc, receipt)

        def mutate_receipt(_query):
            data = json.loads(path.read_text(encoding="utf-8"))
            data["receipt"]["reason"] = "changed while TSA call in flight"
            path.write_text(json.dumps(data), encoding="utf-8")

        tsa.on_query = mutate_receipt
        tsa._sync()
        try:
            _submit(store, digest, tool.KIND_RECEIPT, path,
                    tsa.endpoint, tsa.trust_url)
        except SubmitError as exc:
            assert exc.event == "stale_receipt"
        else:
            raise AssertionError("stale read was anchored")
        # the anchor must NOT exist for a preimage that changed mid-flight
        assert store.token_paths(digest) == []


def test_submit_persist_failed_records_pending():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        # sabotage the meta target: a DIRECTORY with the meta's name makes
        # the exclusive create raise OSError after a good submission; the
        # half-written token must be rolled back (no partial anchor state)
        (store.anchors_dir / f"{digest}.meta.json").mkdir(parents=True)
        try:
            _submit(store, digest, tool.KIND_RECEIPT,
                    _receipt_path(svc, receipt), tsa.endpoint, tsa.trust_url)
        except SubmitError as exc:
            assert exc.event == "persist_failed"
        else:
            raise AssertionError("persist failure was accepted")
        assert store.pending_events()[-1]["event"] == "persist_failed"
        # fail-closed: the half-written token was rolled back
        assert store.token_paths(digest) == []


def test_submit_rejects_inconsistent_receipt():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        path = _receipt_path(svc, receipt)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["integrity"]["digest"] = "ff" * 32
        path.write_text(json.dumps(data), encoding="utf-8")
        try:
            tool.receipt_digest(tool.read_receipt(path))
        except AnchorError:
            pass
        else:
            raise AssertionError("inconsistent receipt was not rejected")


# ---------------------------------------------------------------------------
# chain tails + journal snapshot
# ---------------------------------------------------------------------------

def test_chain_tails_excludes_superseded():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        r1 = svc.delete("bundle-alpha", "rec-002", "first erasure")
        # force a supersession: out-of-band resurrect + recover + retry
        # (put_bundle rejects journal-tombstoned ids, so the copy lands
        # through the direct producer channel, like the real attack path)
        manifest = build_bundle(
            "bundle-stale",
            records=[make_record("rec-002", "fact", "stale variant",
                                 "user-syn", created=FIXED_TS)],
        )
        stale_path = svc.bundle_path("bundle-stale")
        stale_path.parent.mkdir(parents=True, exist_ok=True)
        stale_path.write_bytes(mbcp_canonical_bytes(manifest))
        assert svc.recover() == ["rec-002"]
        r2 = svc.delete("bundle-alpha", "rec-002", "second erasure")
        assert r2["receipt"]["supersedes"] == r1["integrity"]["digest"]
        tails, skipped = tool.chain_tail_receipts(svc.root)
        assert skipped == []
        assert [d for d, _p in tails] == [r2["integrity"]["digest"]]


def test_journal_snapshot_digest_is_stable():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "root"
        svc = _service(root)
        # empty journal is the canonical empty array
        assert tool.journal_snapshot_digest(root) == canonical_sha256([])
        svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        d1 = tool.journal_snapshot_digest(root)
        assert d1 == tool.journal_snapshot_digest(root)
        assert len(d1) == 64
        # appending a tombstone changes the snapshot digest
        svc.delete("bundle-alpha", "rec-001", "second erasure")
        assert tool.journal_snapshot_digest(root) != d1


def test_journal_anchor_happy_path():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.journal_snapshot_digest(svc.root)
        meta = _submit(store, digest, tool.KIND_JOURNAL,
                       svc.root / "tombstones.jsonl",
                       tsa.endpoint, tsa.trust_url)
        assert meta["kind"] == "journal_snapshot"
        report = tool.verify_anchor(store, digest, kind=tool.KIND_JOURNAL)
        assert report["ok"] is True, report


# ---------------------------------------------------------------------------
# verify: the third-party chain
# ---------------------------------------------------------------------------

def test_verify_full_chain_green():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        _submit(store, digest, tool.KIND_RECEIPT,
                _receipt_path(svc, receipt), tsa.endpoint, tsa.trust_url)
        report = tool.verify_anchor(store, digest)
        assert report["ok"] is True, report
        assert [s["step"] for s in report["steps"]] == [
            "0:anchor-binding", "1:token", "2:receipt", "3:verify_receipt"]
        # the openssl gate really ran against the test CA, not a stub:
        # swapping the trust snapshot for an unrelated CA must break it
        trust = store.trust_path(tsa.endpoint)
        good = trust.read_bytes()
        other = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", "/dev/null", "-out", "/dev/stdout", "-days", "1",
             "-nodes", "-subj", "/CN=other-ca"],
            capture_output=True, text=True, check=True).stdout
        trust.write_text(other)
        try:
            report2 = tool.verify_anchor(store, digest)
        finally:
            trust.write_bytes(good)
        assert report2["ok"] is False
        assert report2["steps"][1]["step"] == "1:token"
        assert report2["steps"][1]["ok"] is False


def test_verify_detects_receipt_mutation():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        path = _receipt_path(svc, receipt)
        _submit(store, digest, tool.KIND_RECEIPT, path,
                tsa.endpoint, tsa.trust_url)
        data = json.loads(path.read_text(encoding="utf-8"))
        data["receipt"]["reason"] = "mutated after anchoring"
        path.write_text(json.dumps(data), encoding="utf-8")
        report = tool.verify_anchor(store, digest)
        assert report["ok"] is False
        step2 = report["steps"][2]
        assert step2["step"] == "2:receipt" and step2["ok"] is False


def test_verify_detects_anchor_layer_modification():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        _submit(store, digest, tool.KIND_RECEIPT,
                _receipt_path(svc, receipt), tsa.endpoint, tsa.trust_url)
        token_path = store.token_paths(digest)[0]
        body = bytearray(token_path.read_bytes())
        body[len(body) // 2] ^= 0x01
        token_path.write_bytes(bytes(body))
        report = tool.verify_anchor(store, digest)
        assert report["ok"] is False
        assert report["steps"][0]["step"] == "0:anchor-binding"
        assert report["steps"][0]["ok"] is False


def test_verify_step3_runs_real_verify_receipt():
    # step 3 must be MBCP's own verify_receipt result, not a
    # re-derivation: a receipt whose on-disk chain breaks after anchoring
    # fails step 3 even though its body digest is unchanged.
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        _submit(store, digest, tool.KIND_RECEIPT,
                _receipt_path(svc, receipt), tsa.endpoint, tsa.trust_url)
        # resurrect the deleted record directly in bundles/ so the
        # receipt's absence check fails (same channel as a real attack)
        manifest = build_bundle(
            "bundle-alpha",
            records=[make_record("rec-002", "fact", "resurrected",
                                 "user-syn", created=FIXED_TS)],
        )
        bundle_path = svc.bundle_path("bundle-alpha")
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        bundle_path.write_bytes(mbcp_canonical_bytes(manifest))
        report = tool.verify_anchor(store, digest)
        step3 = report["steps"][3]
        assert step3["step"] == "3:verify_receipt" and step3["ok"] is False
        assert "ok:False" in step3["detail"]


def test_verify_unanchored_digest_fails():
    with tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        report = tool.verify_anchor(store, tool.receipt_digest(receipt))
        assert report["ok"] is False
        assert report["steps"][0]["step"] == "resolve"


def test_verify_never_touches_network():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        _submit(store, digest, tool.KIND_RECEIPT,
                _receipt_path(svc, receipt), tsa.endpoint, tsa.trust_url)
        # unwiring the network must not change the verify outcome
        real_urlopen = tool.urllib.request.urlopen

        def _boom(*args, **kwargs):
            raise AssertionError("verify touched the network")

        tool.urllib.request.urlopen = _boom
        try:
            report = tool.verify_anchor(store, digest)
        finally:
            tool.urllib.request.urlopen = real_urlopen
        assert report["ok"] is True, report


# ---------------------------------------------------------------------------
# status + CLI + retry-pending
# ---------------------------------------------------------------------------

def test_status_shows_pending_and_anchored_two_states():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        path = _receipt_path(svc, receipt)
        tsa.status_code = 503
        tsa._sync()
        try:
            _submit(store, digest, tool.KIND_RECEIPT, path,
                    tsa.endpoint, tsa.trust_url)
        except SubmitError:
            pass
        state = tool.collect_status(store)
        assert list(state["pending"].keys()) == [digest]
        assert state["anchored"] == []
        # after a successful retry the digest moves to anchored only
        tsa.status_code = 200
        tsa._sync()
        _submit(store, digest, tool.KIND_RECEIPT, path,
                tsa.endpoint, tsa.trust_url)
        state = tool.collect_status(store)
        assert state["pending"] == {}
        assert [a["digest"] for a in state["anchored"]] == [digest]


def test_retry_pending_resubmits_after_outage():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        store = AnchorStore(svc.root)
        digest = tool.receipt_digest(receipt)
        tsa.status_code = 503
        tsa._sync()
        try:
            _submit(store, digest, tool.KIND_RECEIPT,
                    _receipt_path(svc, receipt), tsa.endpoint, tsa.trust_url)
        except SubmitError:
            pass
        assert store.token_paths(digest) == []
        tsa.status_code = 200
        tsa._sync()
        rc = tool.main([
            "submit", "--root", str(svc.root), "--retry-pending",
            "--tsa", tsa.endpoint, "--trust-url", tsa.trust_url,
        ])
        assert rc == 0
        assert len(store.token_paths(digest)) == 1


def test_cli_submit_verify_status_roundtrip():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        receipt = svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        digest = tool.receipt_digest(receipt)
        rc = tool.main(["submit", "--root", str(svc.root), "--chain-tails",
                        "--tsa", tsa.endpoint, "--trust-url", tsa.trust_url])
        assert rc == 0
        rc = tool.main(["verify", "--root", str(svc.root),
                        "--digest", digest])
        assert rc == 0
        rc = tool.main(["status", "--root", str(svc.root)])
        assert rc == 0


def test_cli_submit_all_granules_at_once():
    with FakeTSA() as tsa, tempfile.TemporaryDirectory() as tmp:
        svc = _service(Path(tmp) / "root")
        svc.delete("bundle-alpha", "rec-002", "synthetic erasure")
        rc = tool.main(["submit", "--root", str(svc.root),
                        "--chain-tails", "--journal",
                        "--tsa", tsa.endpoint, "--trust-url", tsa.trust_url])
        assert rc == 0
        store = AnchorStore(svc.root)
        state = tool.collect_status(store)
        assert len(state["anchored"]) == 2  # one tail + one journal
        kinds = sorted(a["kind"] for a in state["anchored"])
        assert kinds == ["journal_snapshot", "receipt"]
