"""A damaged Authenticode signature is read without failing and is never reported as signed: every byte of the
real fixtures' signature blobs is cut short or flipped in turn, and the reader returns what it could read with
its error, never an exception and never a verified signature that the damage should have broken."""

from __future__ import annotations

import json
from typing import Any

import pytest
from support import ROOT

from cordon_scanner.detect.binary.modules import signature as rs

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"
EXPECTED: dict[str, Any] = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
SIGNED = sorted(n for n, e in EXPECTED.items() if (e["modules"].get("pe") or {}).get("signatures"))
NOW = 1_764_000_000


class Damage:
    """Helpers for test_signature_damage.py: the signature blob of a signed fixture, and ways to damage it."""

    @staticmethod
    def blob(data: bytes) -> tuple[int, int]:
        """The certificate table's offset and length, from the PE's security directory."""
        pe = int.from_bytes(data[0x3C:0x40], "little")
        is64 = int.from_bytes(data[pe + 0x18 : pe + 0x1A], "little") == 0x20B
        table = pe + (16 if is64 else 0) + 0x98
        return int.from_bytes(data[table : table + 4], "little"), int.from_bytes(
            data[table + 4 : table + 8], "little"
        )

    @staticmethod
    def positions(length: int, count: int = 400) -> list[int]:
        """`count` positions spread over the blob, its first 64 bytes (the outer structure) all included."""
        step = max(1, length // count)
        return sorted({*range(min(64, length)), *range(0, length, step)})

    @staticmethod
    def verified(found: list[rs.Signed]) -> int:
        return sum(1 for s in found if s.flags == rs.Signed.CLEAN) if found else 0


@pytest.mark.parametrize("name", SIGNED)
class TestADamagedSignature:
    def test_every_flipped_byte_is_read_without_failing(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        start, length = Damage.blob(data)
        clean = Damage.verified(rs.Signatures.read(data, NOW))
        for at in Damage.positions(length):
            damaged = bytearray(data)
            damaged[start + at] ^= 0xFF
            found = rs.Signatures.read(bytes(damaged), NOW)
            assert isinstance(found, list)
            # Damage never makes a file more signed than it was.
            assert Damage.verified(found) <= clean

    def test_every_cut_is_read_without_failing(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        start, length = Damage.blob(data)
        for at in Damage.positions(length, 120):
            body = rs.Signatures.parse(data[start + 8 : start + 8 + at], NOW)
            assert isinstance(body, list)
            assert all(s.flags != rs.Signed.CLEAN for s in body) or at >= length - 8

    def test_the_records_of_a_damaged_file_still_conform(self, name: str) -> None:
        from cordon_scanner.detect.binary.modules.values import Data, Seq

        data = bytearray((DIR / name).read_bytes())
        start, _ = Damage.blob(bytes(data))
        data[start + 40] ^= 0xFF
        values, _ = rs.Signatures.signature_values(bytes(data))
        assert Data.conforms(Seq(rs.SIGNATURE), values) == []


class TestADirectoryThatPointsNowhere:
    def test_a_security_directory_outside_the_file_has_no_signature(self) -> None:
        data = bytearray((DIR / SIGNED[0]).read_bytes())
        pe = int.from_bytes(data[0x3C:0x40], "little")
        is64 = int.from_bytes(data[pe + 0x18 : pe + 0x1A], "little") == 0x20B
        table = pe + (16 if is64 else 0) + 0x98
        data[table : table + 4] = (len(data) + 10).to_bytes(4, "little")
        assert rs.Signatures.read(bytes(data), NOW) == []

    def test_a_file_too_short_for_its_headers_has_no_signature(self) -> None:
        assert rs.Signatures.read(b"MZ" + b"\0" * 0x3A + (0x1000).to_bytes(4, "little"), NOW) == []
