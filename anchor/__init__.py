"""External anchor tool — third-party RFC3161 timestamping of MBCP
deletion-receipt digests.

This package is a standalone *consumer* of MBCP, not a component of it:

- zero imports of ``mbcp/`` (the canonical-replay module re-implements
  SPEC 1.4 read-only so third parties can replay receipt digests without
  the MBCP package; tests pin byte-equality against ``mbcp.canonical``);
- stdlib-only for all submission logic (hand-built RFC3161 DER); token
  verification is delegated to the external ``openssl ts`` command;
- the only MBCP surface it ever invokes is ``verify_receipt``, executed
  in a subprocess against a service root, and only by the ``verify``
  command — it never patches, wraps or re-implements verification.

Trust-root statement (verbatim, RFC anchor tool 7.1):

    「RFC3161 timestamp 嘅信任根係該 TSA，唔係 MBCP。MBCP 對 TSA 嘅營運、
    時鐘準確性、金鑰保管冇任何控制或背書。TSA snapshot 檔案由提交者自行
    out-of-band 核對後先入庫；呢個核對步驟唔由本工具自動完成。」

Capability ceiling (verbatim, RFC anchor tool 7.1): this tool provides
"third-party timestamped evidence" — third-party-verifiable evidence
that a receipt existed at a point in time. It does NOT provide
protection against rewriting, protection against full-root recreation,
erasure assurances, or any legal effect. A timestamped older artifact
can still be recreated by a root writer and re-anchored; the old token
makes two self-proclaimed-true versions detectable, which is its real
value.

Endpoint note (RFC anchor tool 7.1(4)): the default freetsa.org
endpoint is a convenience endpoint, not a trust endorsement; any
RFC3161 TSA can be substituted via config (``--tsa`` / ``--trust-url``).
Free public TSAs carry no SLA and must not be used for legal-grade
claims.
"""

__all__ = ["canonical_replay", "rfc3161", "store", "tool"]
