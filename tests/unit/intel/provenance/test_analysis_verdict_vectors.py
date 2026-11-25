"""The analysis service's verdict signatures, checked with the scanner's own P-256 code.

The signing account signs a SHA-256 digest taken over a purpose prefix and the 512-byte verdict
record, with ECDSA over P-256. The scanner's verify-only code must accept what the signer signs and
refuse what the signer's tests refuse, and a record in the old format is refused whatever its
signature says: there is no way down. The vectors file is the one the signing repository pins as
well (by SHA-256 there and here), so neither side can change it alone.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.foundation.signatures.ecdsa import Ecdsa
from support import ROOT as REPO

FILE = REPO / "tests" / "unit" / "data" / "analysis_verdicts" / "verdict_p256_vectors.json"
SHA256 = "e9841da6f9f4356ce7f4cad62da7ea10970f7d7e4117997992ecff93849a198b"
RECORD_SIZE = 512
FORMAT = b"CVR3\x03"
OLD_FORMAT = b"CVR2\x02"
#: The first eight hex digits of the SHA-256 of the golden records the verdict library publishes.
GOLDEN_PREFIXES = ("c556179b", "bd2b7a8e", "20b429fc")


class Vectors:
    @staticmethod
    def document() -> dict[str, Any]:
        value: dict[str, Any] = json.loads(FILE.read_text(encoding="utf-8"))
        return value

    @staticmethod
    def cases() -> list[dict[str, Any]]:
        cases: list[dict[str, Any]] = Vectors.document()["cases"]
        return cases

    @staticmethod
    def signature_ok(case: dict[str, Any]) -> bool:
        value = Vectors.document()
        key = Ecdsa.public_key(bytes.fromhex(value["public_key"]))
        message = bytes.fromhex(value["domain"]) + bytes.fromhex(case["record"])
        return Ecdsa.verify(key, message, bytes.fromhex(case["signature"]), "sha256")

    @staticmethod
    def accepted(case: dict[str, Any]) -> bool:
        return bytes.fromhex(case["record"])[:5] == FORMAT and Vectors.signature_ok(case)


class TestTheFile:
    def test_it_is_the_file_both_repositories_pin(self) -> None:
        assert hashlib.sha256(FILE.read_bytes()).hexdigest() == SHA256

    def test_it_names_p256_with_sha256_and_a_purpose_prefix(self) -> None:
        value = Vectors.document()
        assert value["type"] == "cordon-analysis/verdict-vectors/v2"
        assert value["algorithm"] == "ecdsa_p256_sha256"
        assert bytes.fromhex(value["domain"]).startswith(b"cordon-analysis/verdict/")

    def test_its_key_is_a_p256_key(self) -> None:
        curve, _ = Ecdsa.public_key(bytes.fromhex(Vectors.document()["public_key"]))
        assert curve.name in ("P-256", "secp256r1", "prime256v1") and curve.size == 32

    def test_it_holds_valid_and_refused_cases_of_whole_records(self) -> None:
        cases = Vectors.cases()
        assert sum(c["valid"] for c in cases) >= 3 and sum(not c["valid"] for c in cases) >= 6
        assert all(len(bytes.fromhex(c["record"])) == RECORD_SIZE for c in cases)

    def test_the_accepted_records_are_the_verdict_librarys_golden_records(self) -> None:
        for case in Vectors.cases():
            if case["valid"]:
                prefix = hashlib.sha256(bytes.fromhex(case["record"])).hexdigest()[:8]
                assert prefix in GOLDEN_PREFIXES, case["name"]


class TestEveryCase:
    @pytest.mark.parametrize("case", Vectors.cases(), ids=lambda c: c["name"])
    def test_the_signature_and_the_verdict_are_as_marked(self, case: dict[str, Any]) -> None:
        assert Vectors.signature_ok(case) is case["signature_ok"]
        assert Vectors.accepted(case) is case["valid"]


class TestTheOldFormatHasNoWayBack:
    def test_a_validly_signed_format_two_record_is_in_the_file_and_is_refused(self) -> None:
        downgrade = [c for c in Vectors.cases() if c["signature_ok"] and not c["valid"]]
        assert len(downgrade) == 1
        assert bytes.fromhex(downgrade[0]["record"])[:5] == OLD_FORMAT
        assert Vectors.signature_ok(downgrade[0]) and not Vectors.accepted(downgrade[0])
