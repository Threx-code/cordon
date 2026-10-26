"""Cordon's own signature verifiers against every Wycheproof vector they cover.

A vector marked valid must verify; one marked invalid must not. `acceptable` vectors (encodings
the standard leaves to the implementation) must not verify either: these verifiers take only the
strict form, and a refusal there is a stricter verifier, never a weaker one.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from cordon_scanner.intel.provenance._der import Der, DerError
from cordon_scanner.intel.provenance._dsa import Dsa
from cordon_scanner.intel.provenance._ecdsa import Ecdsa
from cordon_scanner.intel.provenance._ed25519 import Ed25519
from cordon_scanner.intel.provenance._rsa import Rsa
from support import ROOT as REPO


class Vectors:
    ROOT = REPO / "tests" / "unit" / "data" / "wycheproof"

    @staticmethod
    def cases(name: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        data = json.loads((Vectors.ROOT / name).read_text(encoding="utf-8"))
        return [(group, test) for group in data["testGroups"] for test in group["tests"]]

    @staticmethod
    def hash_name(sha: str) -> str:
        return sha.replace("-", "").lower()

    @staticmethod
    def expected(test: dict[str, Any]) -> bool:
        return bool(test["result"] == "valid")


class TestEcdsa:
    @pytest.mark.parametrize(
        "name",
        [
            "ecdsa_secp256r1_sha256_test.json",
            "ecdsa_secp384r1_sha256_test.json",
            "ecdsa_secp384r1_sha384_test.json",
            "ecdsa_secp521r1_sha512_test.json",
        ],
    )
    def test_every_vector(self, name: str) -> None:
        wrong = []
        for group, test in Vectors.cases(name):
            try:
                key = Ecdsa.public_key(bytes.fromhex(group["publicKeyDer"]))
            except DerError:
                key = None
            got = key is not None and Ecdsa.verify(
                key,
                bytes.fromhex(test["msg"]),
                bytes.fromhex(test["sig"]),
                Vectors.hash_name(group["sha"]),
            )
            if got != Vectors.expected(test):
                wrong.append((test["tcId"], test["comment"], test["result"]))
        assert not wrong, wrong[:10]

    def test_a_point_off_the_curve_is_refused(self) -> None:
        curve = Ecdsa.P256
        with pytest.raises(DerError):
            Ecdsa.point(curve, b"\x04" + (1).to_bytes(32, "big") + (1).to_bytes(32, "big"))


class TestRsa:
    @pytest.mark.parametrize(
        "name", ["rsa_signature_2048_sha256_test.json", "rsa_signature_4096_sha512_test.json"]
    )
    def test_every_pkcs1_vector(self, name: str) -> None:
        wrong = []
        for group, test in Vectors.cases(name):
            key = Rsa.public_key(bytes.fromhex(group["publicKeyDer"]))
            got = Rsa.verify_pkcs1(
                key,
                bytes.fromhex(test["msg"]),
                bytes.fromhex(test["sig"]),
                Vectors.hash_name(group["sha"]),
            )
            if got != Vectors.expected(test):
                wrong.append((test["tcId"], test["comment"], test["result"]))
        assert not wrong, wrong[:10]

    def test_every_pss_vector(self) -> None:
        wrong = []
        for group, test in Vectors.cases("rsa_pss_2048_sha256_mgf1_32_test.json"):
            key = Rsa.public_key(bytes.fromhex(group["publicKeyDer"]))
            got = Rsa.verify_pss(
                key,
                bytes.fromhex(test["msg"]),
                bytes.fromhex(test["sig"]),
                Vectors.hash_name(group["sha"]),
                group["sLen"],
                Vectors.hash_name(group["mgfSha"]),
            )
            if got != Vectors.expected(test):
                wrong.append((test["tcId"], test["comment"], test["result"]))
        assert not wrong, wrong[:10]

    def test_a_short_key_is_refused(self) -> None:
        with pytest.raises(DerError):
            Rsa.checked((1 << 1023) + 1, 65537)


class TestEd25519:
    def test_every_vector(self) -> None:
        wrong = []
        for group, test in Vectors.cases("ed25519_test.json"):
            got = Ed25519.verify(
                bytes.fromhex(group["publicKey"]["pk"]),
                bytes.fromhex(test["msg"]),
                bytes.fromhex(test["sig"]),
            )
            if got != Vectors.expected(test):
                wrong.append((test["tcId"], test["comment"], test["result"]))
        assert not wrong, wrong[:10]


class TestDsa:
    @pytest.mark.parametrize(
        "name",
        [
            "dsa_2048_224_sha256_test.json",
            "dsa_2048_256_sha256_test.json",
            "dsa_3072_256_sha256_test.json",
        ],
    )
    def test_every_vector(self, name: str) -> None:
        import hashlib

        wrong = []
        for group, test in Vectors.cases(name):
            k = group["publicKey"]
            key = Dsa.checked(*(int(k[part], 16) for part in ("p", "q", "g", "y")))
            try:
                parts = Der.parse(bytes.fromhex(test["sig"]), Der.SEQUENCE).children()
                r, s = (parts[0].integer(), parts[1].integer()) if len(parts) == 2 else (0, 0)
            except DerError:
                r = s = 0
            digest = hashlib.new(
                Vectors.hash_name(group["sha"]), bytes.fromhex(test["msg"])
            ).digest()
            got = Dsa.verify_digest(key, digest, r, s)
            if got != Vectors.expected(test):
                wrong.append((test["tcId"], test["comment"], test["result"]))
        assert not wrong, wrong[:10]

    def test_a_key_outside_its_group_is_refused(self) -> None:
        with pytest.raises(ValueError):
            Dsa.checked((1 << 2047) + 1, (1 << 223) + 1, 2, 3)
