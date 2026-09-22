"""The vendored Ed25519 verifier, against RFC 8032's own test vectors.

A verifier that accepts a forgery is worse than no verifier, so the tests that
matter are the ones proving it rejects a tampered signature, message and key --
not only that it accepts a good one. The vectors are from RFC 8032 section 7.1.
"""

from __future__ import annotations

import pytest

from cordon_scanner.intel._ed25519 import verify

# (public key, message, signature) from RFC 8032, all hex.
VECTORS = [
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a"
        "33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15"
        "996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16"
        "f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


@pytest.mark.parametrize(("public", "message", "signature"), VECTORS)
def test_valid_rfc8032_signatures_verify(public: str, message: str, signature: str) -> None:
    assert verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature))


@pytest.mark.parametrize(("public", "message", "signature"), VECTORS)
def test_a_tampered_signature_is_rejected(public: str, message: str, signature: str) -> None:
    sig = bytearray.fromhex(signature)
    sig[0] ^= 1
    assert not verify(bytes.fromhex(public), bytes.fromhex(message), bytes(sig))


@pytest.mark.parametrize(("public", "message", "signature"), VECTORS)
def test_a_tampered_message_is_rejected(public: str, message: str, signature: str) -> None:
    assert not verify(
        bytes.fromhex(public), bytes.fromhex(message) + b"\x00", bytes.fromhex(signature)
    )


@pytest.mark.parametrize(("public", "message", "signature"), VECTORS)
def test_a_wrong_key_is_rejected(public: str, message: str, signature: str) -> None:
    key = bytearray.fromhex(public)
    key[0] ^= 1
    assert not verify(bytes(key), bytes.fromhex(message), bytes.fromhex(signature))


def test_malformed_inputs_return_false_not_raise() -> None:
    good = VECTORS[0]
    assert not verify(b"", b"", bytes.fromhex(good[2]))  # short key
    assert not verify(bytes.fromhex(good[0]), b"", b"")  # short signature
    assert not verify(bytes.fromhex(good[0]), b"", b"\x00" * 64)  # zero signature
