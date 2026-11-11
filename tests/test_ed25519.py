"""RFC 8032 known-answer pins for the vendored ed25519 (mbcp/_ed25519.py).

The vendored module follows the public-domain reference code published in
RFC 8032 §8; these §7.1 vectors are the conformance gate for it. The
vectors were verified verbatim against rfc-editor.org/rfc8032.txt AND
cross-checked against OpenSSL 3.5.7 (key derivation + signatures on the
non-empty-message vectors) during M4 Round B — a mutation to the vendored
math must turn this file red.

Performance note: the reference implementation is deliberately slow
(affine coordinates, per-addition inversion); the suite accepts that.
"""

from mbcp import _ed25519

# RFC 8032 section 7.1, TEST 1 / 2 / 3 (exact transcription).
TEST_VECTORS = [
    {
        "secret": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522"
        "4901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e"
        "7a100b",
    },
    {
        "secret": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb"
        "69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb"
        "0c00",
    },
    {
        "secret": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5a"
        "c3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1e"
        "c40a",
    },
]


def test_rfc8032_public_keys_match_section_7_1():
    for vector in TEST_VECTORS:
        seed = bytes.fromhex(vector["secret"])
        assert _ed25519.publickey(seed).hex() == vector["public"]


def test_rfc8032_signatures_match_section_7_1():
    for vector in TEST_VECTORS:
        seed = bytes.fromhex(vector["secret"])
        public = bytes.fromhex(vector["public"])
        message = bytes.fromhex(vector["message"])
        sig = _ed25519.signature(message, seed, public)
        assert sig.hex() == vector["signature"]


def test_rfc8032_checkvalid_accepts_section_7_1():
    for vector in TEST_VECTORS:
        public = bytes.fromhex(vector["public"])
        message = bytes.fromhex(vector["message"])
        sig = bytes.fromhex(vector["signature"])
        assert _ed25519.checkvalid(sig, message, public) is True


def test_rfc8032_checkvalid_rejects_flipped_bits():
    # every single-bit flip in R or S must break verification
    vector = TEST_VECTORS[1]
    public = bytes.fromhex(vector["public"])
    message = bytes.fromhex(vector["message"])
    sig = bytearray(bytes.fromhex(vector["signature"]))
    for byte_index in (0, 32, 63):
        for bit in (0x01, 0x80):
            mutated = bytearray(sig)
            mutated[byte_index] ^= bit
            rejected = False
            try:
                rejected = _ed25519.checkvalid(bytes(mutated), message, public) is False
            except ValueError:
                rejected = True
            assert rejected, f"bitflip at byte {byte_index} bit {bit:#x} verified!"


def test_rfc8032_checkvalid_rejects_wrong_key():
    vector = TEST_VECTORS[1]
    message = bytes.fromhex(vector["message"])
    sig = bytes.fromhex(vector["signature"])
    other_public = bytes.fromhex(TEST_VECTORS[0]["public"])
    assert _ed25519.checkvalid(sig, message, other_public) is False


def test_rfc8032_signing_is_deterministic():
    # ed25519 has no nonce randomness: same (seed, message) -> same sig
    # (SPEC 1.2.6 pins this for attestation reproducibility).
    seed = bytes.fromhex(TEST_VECTORS[1]["secret"])
    public = _ed25519.publickey(seed)
    message = b"determinism pin"
    sig1 = _ed25519.signature(message, seed, public)
    sig2 = _ed25519.signature(message, seed, public)
    assert sig1 == sig2


def test_rfc8032_structurally_invalid_input_raises_not_false():
    seed = bytes.fromhex(TEST_VECTORS[1]["secret"])
    public = _ed25519.publickey(seed)
    sig = _ed25519.signature(b"m", seed, public)
    for bad_sig, bad_pk, label in (
        (sig[:63], public, "short signature"),
        (sig, public[:31], "short public key"),
    ):
        try:
            _ed25519.checkvalid(bad_sig, b"m", bad_pk)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected ValueError for {label}")
    try:
        _ed25519.publickey(b"\x00" * 31)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for short seed")
