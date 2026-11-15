"""Minimal RFC3161 Time-Stamp protocol structures (stdlib-only DER).

Only what the anchor tool needs:

- :func:`build_request` — encode a TimeStampRequest (SHA-256
  messageImprint, optional nonce, certReq TRUE so the reply embeds the
  TSA signer chain);
- :func:`parse_response` — decode a TimeStampResp (PKIStatus, optional
  statusString, optional timeStampToken) returned by a TSA;
- :func:`parse_token` — read the messageImprint algorithm OID, imprint
  digest and genTime out of a stored token's TSTInfo, so the submit path
  can fail closed on a mismatched imprint *before* trusting the token.

DER encoding is emitted canonically (definite length form); parsing
accepts any valid definite-length DER. Signature verification is NOT
done here — it is delegated to the external ``openssl ts`` command
(RFC anchor tool 1: submission is stdlib, verification is openssl).
"""

import os

# sha256 (NIST OIDS arc)
_SHA256_OID = "2.16.840.1.101.3.4.2.1"


class TSDecodeError(ValueError):
    """RFC3161/DER structure could not be decoded (fail-closed input)."""


# ---------------------------------------------------------------------------
# DER encoding
# ---------------------------------------------------------------------------

def _der_len(n):
    if n < 0:
        raise ValueError("negative DER length")
    if n < 128:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(n):
    if n < 0:
        raise ValueError("negative INTEGER not supported")
    body = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _der(0x02, body)


def _der_octets(body):
    return _der(0x04, body)


def _der_oid(oid):
    nums = [int(part) for part in oid.split(".")]
    if len(nums) < 2 or nums[0] > 2 or nums[1] >= 40 and nums[0] < 2:
        raise ValueError(f"malformed OID {oid!r}")
    out = bytes([nums[0] * 40 + nums[1]])
    for num in nums[2:]:
        stack = [num & 0x7F]
        num >>= 7
        while num:
            stack.append(0x80 | (num & 0x7F))
            num >>= 7
        out += bytes(reversed(stack))
    return _der(0x06, out)


def _der_seq(*parts):
    return _der(0x30, b"".join(parts))


def _der_bool(value):
    return _der(0x01, b"\xff" if value else b"\x00")


def _der_null():
    return b"\x05\x00"


def build_request(digest, *, nonce=None, with_cert=True):
    """Encode a TimeStampRequest for a SHA-256 ``digest`` (32 bytes).

    ``version`` is 1; ``messageImprint`` binds the receipt's canonical
    digest; ``certReq`` TRUE asks the TSA to embed its signer chain in
    the token (keeps later verification self-contained given the trust
    snapshot). A random nonce (when ``nonce`` is None, 16 fresh bytes)
    binds this request to this submission.
    """
    digest = bytes(digest)
    if len(digest) != 32:
        raise ValueError("SHA-256 imprint must be 32 bytes")
    if nonce is None:
        nonce = os.urandom(16)
    imprint = _der_seq(
        _der_seq(_der_oid(_SHA256_OID), _der_null()),
        _der_octets(digest),
    )
    parts = [_der_int(1), imprint]
    if nonce:
        parts.append(_der_int(int.from_bytes(nonce, "big")))
    parts.append(_der_bool(with_cert))
    return _der_seq(*parts)


# ---------------------------------------------------------------------------
# DER decoding
# ---------------------------------------------------------------------------

def _read_tlv(data, offset=0):
    """Parse one TLV at ``offset``; return (tag, content, next_offset)."""
    if offset + 2 > len(data):
        raise TSDecodeError("truncated DER element")
    tag = data[offset]
    first_len = data[offset + 1]
    pos = offset + 2
    if first_len & 0x80:
        n_len = first_len & 0x7F
        if n_len == 0 or n_len > 4 or pos + n_len > len(data):
            raise TSDecodeError("bad DER long-form length")
        length = int.from_bytes(data[pos:pos + n_len], "big")
        pos += n_len
    else:
        length = first_len
    end = pos + length
    if end > len(data):
        raise TSDecodeError("DER content overruns buffer")
    return tag, data[pos:end], end


def _read_int(content):
    if not content:
        raise TSDecodeError("empty INTEGER")
    return int.from_bytes(content, "big", signed=bool(content[0] & 0x80))


def _read_oid(content):
    if not content:
        raise TSDecodeError("empty OID")
    nums = [content[0] // 40, content[0] % 40]
    if content[0] >= 80:  # first arc 2, second arc >= 40
        nums = [2, content[0] - 80]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            nums.append(value)
            value = 0
    if content[-1] & 0x80:
        raise TSDecodeError("truncated OID arc")
    return ".".join(str(n) for n in nums)


# PKIStatus values (RFC3161 2.4.2)
STATUS_GRANTED = 0
STATUS_STRING_TAGS = {0xA0: "statusString"}


def parse_response(data):
    """Decode a TimeStampResp.

    Returns ``{"status": int, "status_string": str|None,
    "token": bytes|None}``. ``token`` (when present) is the raw DER of
    the timeStampToken ContentInfo — the bytes stored as ``<digest>.tsr``.
    Raises :class:`TSDecodeError` on malformed input (fail-closed).
    """
    tag, content, end = _read_tlv(data, 0)
    if tag != 0x30 or end != len(data):
        raise TSDecodeError("TimeStampResp must be a single SEQUENCE")
    offset = 0
    tag, status_info, offset = _read_tlv(content, offset)
    if tag != 0x30:
        raise TSDecodeError("TimeStampResp: PKIStatusInfo SEQUENCE missing")
    s_offset = 0
    s_tag, status_content, s_offset = _read_tlv(status_info, s_offset)
    if s_tag != 0x02:
        raise TSDecodeError("PKIStatusInfo: status INTEGER missing")
    status = _read_int(status_content)
    status_string = None
    if s_offset < len(status_info) and status_info[s_offset] == 0xA0:
        _tag, inner, _ = _read_tlv(status_info, s_offset)
        if inner:
            str_tag, str_content, _ = _read_tlv(inner, 0)
            if str_tag != 0x0C:
                raise TSDecodeError("statusString must be a UTF8String")
            status_string = str_content.decode("utf-8", "replace")
    token = content[offset:] or None
    if token is not None:
        t_tag, _t_content, t_end = _read_tlv(token, 0)
        if t_tag != 0x30 or t_end != len(token):
            raise TSDecodeError("timeStampToken is not a ContentInfo SEQUENCE")
    return {
        "status": status,
        "status_string": status_string,
        "token": token,
    }


def parse_request_imprint(request):
    """Decode a TimeStampRequest's messageImprint digest bytes.

    Validates just enough structure (version INTEGER, messageImprint
    SEQUENCE of { AlgorithmIdentifier, OCTET STRING }) for a TSA handler
    to re-sign a query. Raises :class:`TSDecodeError` on malformed input.
    """
    tag, content, end = _read_tlv(request, 0)
    if tag != 0x30 or end != len(request):
        raise TSDecodeError("TimeStampRequest must be a single SEQUENCE")
    offset = 0
    ver_tag, _ver, offset = _read_tlv(content, offset)
    if ver_tag != 0x02:
        raise TSDecodeError("TimeStampRequest version INTEGER missing")
    mi_tag, mi_content, _offset = _read_tlv(content, offset)
    if mi_tag != 0x30:
        raise TSDecodeError("TimeStampRequest messageImprint missing")
    alg_tag, alg_content, mi_offset = _read_tlv(mi_content, 0)
    if alg_tag != 0x30:
        raise TSDecodeError("messageImprint algorithm missing")
    oid_tag, oid_content, _ = _read_tlv(alg_content, 0)
    if oid_tag != 0x06 or _read_oid(oid_content) != _SHA256_OID:
        raise TSDecodeError("messageImprint algorithm is not sha256")
    hash_tag, hash_content, _ = _read_tlv(mi_content, mi_offset)
    if hash_tag != 0x04:
        raise TSDecodeError("messageImprint hashedMessage missing")
    return hash_content


def parse_token(token):
    """Decode a token's TSTInfo.

    Returns ``{"algo_oid": str, "imprint": bytes, "gen_time": str}``.
    Only the leading fields (version, policy, messageImprint, serial,
    genTime) are decoded; everything after genTime is skipped. Raises
    :class:`TSDecodeError` on malformed input (fail-closed).
    """
    tag, content, end = _read_tlv(token, 0)
    if tag != 0x30 or end != len(token):
        raise TSDecodeError("token is not a ContentInfo SEQUENCE")
    # ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT content }
    ct_tag, ct_content, offset = _read_tlv(content, 0)
    if ct_tag != 0x06 or _read_oid(ct_content) != "1.2.840.113549.1.7.2":
        raise TSDecodeError("token contentType is not signedData")
    if offset >= len(content) or content[offset] != 0xA0:
        raise TSDecodeError("token signedData content missing")
    _tag, explicit, _ = _read_tlv(content, offset)
    # [0] EXPLICIT wraps the full SignedData TLV.
    sd_tag, signed, _ = _read_tlv(explicit, 0)
    if sd_tag != 0x30:
        raise TSDecodeError("signedData is not a SEQUENCE")
    # SignedData ::= SEQUENCE { version, digestAlgorithms, contentInfo, ... }
    _v_tag, _v, offset = _read_tlv(signed, 0)
    _da_tag, _da, offset = _read_tlv(signed, offset)
    ci_tag, ci_content, _ = _read_tlv(signed, offset)
    if ci_tag != 0x30:
        raise TSDecodeError("SignedData contentInfo missing")
    eci_tag, eci_content, offset = _read_tlv(ci_content, 0)
    # RFC3161 A: eContentType is id-ct-TSTInfo (not id-data).
    if eci_tag != 0x06 or _read_oid(eci_content) != "1.2.840.113549.1.9.16.1.4":
        raise TSDecodeError("encapContentInfo is not TSTInfo content")
    if offset >= len(ci_content) or ci_content[offset] != 0xA0:
        raise TSDecodeError("encapContentInfo eContent missing")
    _tag, explicit_econtent, _ = _read_tlv(ci_content, offset)
    # [0] EXPLICIT wraps the eContent OCTET STRING.
    o_tag, econtent_octets, _ = _read_tlv(explicit_econtent, 0)
    if o_tag != 0x04:
        raise TSDecodeError("eContent is not an OCTET STRING")
    t_tag, tstinfo, _ = _read_tlv(econtent_octets, 0)
    if t_tag != 0x30:
        raise TSDecodeError("eContent does not carry a TSTInfo SEQUENCE")
    # TSTInfo ::= SEQUENCE { version, policy, messageImprint, serial,
    #                        genTime, ... }
    _ver_tag, _ver, offset = _read_tlv(tstinfo, 0)
    _pol_tag, _pol, offset = _read_tlv(tstinfo, offset)
    mi_tag, mi_content, offset = _read_tlv(tstinfo, offset)
    if mi_tag != 0x30:
        raise TSDecodeError("TSTInfo messageImprint missing")
    alg_tag, alg_content, mi_offset = _read_tlv(mi_content, 0)
    if alg_tag != 0x30:
        raise TSDecodeError("messageImprint algorithm missing")
    oid_tag, oid_content, _ = _read_tlv(alg_content, 0)
    if oid_tag != 0x06:
        raise TSDecodeError("messageImprint algorithm OID missing")
    hash_tag, hash_content, _ = _read_tlv(mi_content, mi_offset)
    if hash_tag != 0x04:
        raise TSDecodeError("messageImprint hashedMessage missing")
    _ser_tag, _ser, offset = _read_tlv(tstinfo, offset)
    gt_tag, gt_content, _ = _read_tlv(tstinfo, offset)
    if gt_tag != 0x18:
        raise TSDecodeError("TSTInfo genTime missing")
    return {
        "algo_oid": _read_oid(oid_content),
        "imprint": hash_content,
        "gen_time": gt_content.decode("ascii", "replace"),
    }
