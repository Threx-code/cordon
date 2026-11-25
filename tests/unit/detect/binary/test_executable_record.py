"""SI-T9: one record per executable, from its own bytes: format, architecture, imports by group, string shapes, packer, entropy, signature.

The ELF, PE and Mach-O files are built here, byte by byte; nothing is executed.
"""

from __future__ import annotations

import json
import struct

import pytest
from test_binary_imports import Build

from cordon_scanner.detect.binary.executable_record import ExecutableRecord

URL_FIXTURE = b"fetch https://c2.example.net/a https://c2.example.net/b http://other.example.org/x 10.1.2.3 \x00"


class Fixtures:
    @staticmethod
    def macho(*, signed: bool, cpu: int = 0x0100000C, payload: bytes = b"") -> bytes:
        """A Mach-O 64 with one segment holding one section of `payload`, and a code-signature command when `signed`."""
        data_off = 32 + 72 + 80 + (16 if signed else 0)
        segment = struct.pack(
            "<II16sQQQQIIII",
            0x19,
            152,
            b"__TEXT",
            0,
            len(payload),
            data_off,
            len(payload),
            7,
            5,
            1,
            0,
        )
        section = struct.pack(
            "<16s16sQQIIIIIIII",
            b"__text",
            b"__TEXT",
            0,
            len(payload),
            data_off,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        commands = segment + section + (struct.pack("<IIII", 0x1D, 16, 0, 0) if signed else b"")
        header = struct.pack(
            "<IIIIIIII", 0xFEEDFACF, cpu, 0, 2, 2 if signed else 1, len(commands), 0, 0
        )
        return header + commands + payload

    @staticmethod
    def signed_pe() -> bytes:
        data = bytearray(Build.pe({"kernel32.dll": ["CreateFileA", "WinExec"]}))
        struct.pack_into("<II", data, 0x98 + 96 + 32, 0x400, 0x200)
        return bytes(data)


class TestWhatTheFileIs:
    def test_elf(self) -> None:
        record = ExecutableRecord.of(Build.elf(["connect", "system"], ["libc.so.6"]))
        assert record is not None and (record["format"], record["architecture"]) == (
            "elf",
            "x86_64",
        )
        assert record["signature"]["present"] is False
        assert record["entropy"]["sections"] == 3

    def test_pe(self) -> None:
        record = ExecutableRecord.of(Build.pe({"kernel32.dll": ["CreateFileA"]}))
        assert record is not None and (record["format"], record["architecture"]) == ("pe", "x86")
        assert record["entropy"]["sections"] == 1 and record["signature"]["present"] is False

    def test_macho(self) -> None:
        record = ExecutableRecord.of(Fixtures.macho(signed=False, payload=b"\x00" * 64))
        assert record is not None and (record["format"], record["architecture"]) == (
            "macho",
            "arm64",
        )
        assert record["entropy"] == {"max": 0.0, "mean": 0.0, "sections": 1}

    def test_a_universal_binary_names_each_slice(self) -> None:
        one, two = (
            Fixtures.macho(signed=False, payload=b"a" * 16),
            Fixtures.macho(signed=True, cpu=0x01000007, payload=b"b" * 16),
        )
        head = struct.pack(">II", 0xCAFEBABE, 2)
        first = 8 + 40
        table = struct.pack(">iIIII", 0x0100000C, 0, first, len(one), 4) + struct.pack(
            ">iIIII", 0x01000007, 0, first + len(one), len(two), 4
        )
        record = ExecutableRecord.of(head + table + one + two)
        assert (
            record is not None
            and record["architecture"] == "arm64+x86_64"
            and record["signature"]["present"] is True
        )

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"MZ",
            b"MZ" + b"\x00" * 100,
            b"\x7fELF",
            b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x34" + b"\x00" * 40,
            b"\xca\xfe\xba\xbe",
            b"\xca\xfe\xba\xbe\x00\x00\x00\x01",
            b"\x7fELF\x02\x01",
            b"\xcf\xfa\xed\xfe",
            b"plain text",
        ],
    )
    def test_anything_else_is_not_an_executable_and_never_raises(self, data: bytes) -> None:
        record = ExecutableRecord.of(data)
        assert record is None or record["architecture"] in ("unknown", "other")


class TestWhatItImports:
    def test_by_group_from_a_fixed_vocabulary(self) -> None:
        record = ExecutableRecord.of(
            Build.pe(
                {
                    "kernel32.dll": ["CreateFileA", "RegSetValueExA", "WinExec"],
                    "ws2_32.dll": ["connect"],
                    "advapi32.dll": ["CryptEncrypt"],
                }
            )
        )
        assert record is not None
        found = record["imports"]["functions"]
        assert found["file"] == ["CreateFileA"] and found["registry"] == ["RegSetValueExA"]
        assert found["crypto"] == ["CryptEncrypt"] and found["network"] == ["connect"]
        assert found["process"] and set(found) == set(ExecutableRecord.GROUPS)

    def test_injection(self) -> None:
        record = ExecutableRecord.of(
            Build.pe(
                {"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]}
            )
        )
        assert (
            record is not None
            and "WriteProcessMemory" in record["imports"]["functions"]["injection"]
        )

    def test_a_name_outside_the_vocabulary_is_counted_never_listed(self) -> None:
        record = ExecutableRecord.of(Build.elf(["my_secret_symbol_name"], ["libc.so.6"]))
        assert record is not None and record["imports"]["total"] == 1
        assert "my_secret_symbol_name" not in json.dumps(record)


class TestWhatItCarries:
    def test_string_shapes_are_counts_and_the_hosts_are_counted_not_named(self) -> None:
        record = ExecutableRecord.of(Fixtures.macho(signed=False, payload=URL_FIXTURE))
        assert record is not None
        assert (
            record["strings"]["url"] == 3
            and record["strings"]["url_hosts"] == 2
            and record["strings"]["ip"] == 1
        )
        assert "example" not in json.dumps(record)

    def test_a_packer_is_named(self) -> None:
        record = ExecutableRecord.of(Fixtures.macho(signed=False, payload=b"UPX!" + b"\x01" * 32))
        assert record is not None and record["packer"] == "upx"
        plain = ExecutableRecord.of(Fixtures.macho(signed=False, payload=b"\x01" * 32))
        assert plain is not None and plain["packer"] is None

    def test_entropy_tells_a_random_section_from_a_plain_one(self) -> None:
        random_like = bytes(range(256)) * 16
        high = ExecutableRecord.of(Fixtures.macho(signed=False, payload=random_like))
        low = ExecutableRecord.of(Fixtures.macho(signed=False, payload=b"\x00" * 4096))
        assert high is not None and low is not None
        assert high["entropy"]["max"] == 8.0 and low["entropy"]["max"] == 0.0


class TestTheSignature:
    def test_presence_is_read_and_validity_is_never_claimed(self) -> None:
        for data, present in [
            (Fixtures.signed_pe(), True),
            (Build.pe({"kernel32.dll": ["WinExec"]}), False),
            (Fixtures.macho(signed=True), True),
            (Fixtures.macho(signed=False), False),
        ]:
            record = ExecutableRecord.of(data)
            assert record is not None
            assert record["signature"]["present"] is present
            assert record["signature"]["valid"] is None and record["signature"]["signer"] is None
            assert record["signature"]["unchecked"]


class TestWhetherItWasReadWhole:
    def test_whole(self) -> None:
        record = ExecutableRecord.of(Build.elf(["connect"], ["libc.so.6"]))
        assert (
            record is not None and record["read_whole"] is True and record["unread_reason"] is None
        )

    def test_a_prefix_says_why(self) -> None:
        record = ExecutableRecord.of(
            Build.elf(["connect"], ["libc.so.6"]), whole=False, reason="truncated"
        )
        assert (
            record is not None
            and record["read_whole"] is False
            and record["unread_reason"] == "truncated"
        )

    def test_a_file_past_the_string_limit_is_recorded_as_not_read_whole(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ExecutableRecord, "STRING_BYTES", 64)
        record = ExecutableRecord.of(Build.elf(["connect"], ["libc.so.6"]))
        assert (
            record is not None
            and record["read_whole"] is False
            and record["unread_reason"] == "over_the_read_limit"
        )

    def test_the_record_is_json_and_stable(self) -> None:
        data = Build.elf(["connect", "system"], ["libc.so.6"])
        assert json.dumps(ExecutableRecord.of(data), sort_keys=True) == json.dumps(
            ExecutableRecord.of(data), sort_keys=True
        )
