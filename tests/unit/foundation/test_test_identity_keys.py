"""A private key whose certificate names a test identity is a test key (review 98, FP-6).

Built at run time: no key or certificate is committed. The "certificates" are minimal DER
strings, which is all the check reads.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

BEGIN, END = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"


class KeyKit:
    @staticmethod
    def key() -> str:
        seed = b"".join(hashlib.sha256(bytes([i])).digest() for i in range(19))
        body = base64.b64encode(seed).decode()
        lines = [body[i : i + 64] for i in range(0, len(body), 64)]
        return "\n".join([BEGIN, *lines, END]) + "\n"

    @staticmethod
    def certificate(name: str) -> str:
        der = b"\x30\x82\x01\x00" + b"\x13" + bytes([len(name)]) + name.encode()
        return (
            "-----BEGIN CERTIFICATE-----\n"
            + base64.b64encode(der * 4).decode()
            + "\n-----END CERTIFICATE-----\n"
        )

    @staticmethod
    def key_grades(tmp_path: Path, certificate_name: str | None) -> set[str]:
        (tmp_path / "certs").mkdir()
        (tmp_path / "certs" / "server.key").write_text(KeyKit.key(), encoding="utf-8")
        if certificate_name is not None:
            (tmp_path / "certs" / "server.crt").write_text(
                KeyKit.certificate(certificate_name), encoding="utf-8"
            )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.severity.name for f in result.findings if f.rule_id == "SECRET.PRIVATE_KEY.001"}


class TestTestIdentityKeys:
    def test_a_key_beside_a_test_certificate_is_low(self, tmp_path: Path) -> None:
        assert KeyKit.key_grades(tmp_path, "FOR TESTING PURPOSES ONLY") == {"LOW"}

    def test_a_key_beside_a_real_looking_certificate_keeps_its_grade(self, tmp_path: Path) -> None:
        grades = KeyKit.key_grades(tmp_path, "Acme Payments Ltd")
        assert grades and "LOW" not in grades

    def test_a_key_alone_keeps_its_grade(self, tmp_path: Path) -> None:
        grades = KeyKit.key_grades(tmp_path, None)
        assert grades and "LOW" not in grades
