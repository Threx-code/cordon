"""The `magic` module (modules.file_type): our own reading of a file's kind, in libmagic's words.

The expected strings are libmagic's (through YARA 4.5.8's magic module, cordon-yara-ref:2) for
headers built here field by field; the R10 benchmark run holds the same on 4,200 real binaries.
"""

from __future__ import annotations

import pytest

from cordon_scanner.detect.binary.modules.file_type import FileType
from cordon_scanner.detect.binary.modules.values import Data
from cordon_scanner.detect.binary.rule_engine.lang import Rules


class Headers:
    """Minimal headers: only the fields the description reads."""

    @staticmethod
    def elf(width: int, order: int, kind: int, machine: int, flags: int = 0, abi: int = 0) -> bytes:
        big = order == 2
        h = bytearray(64)
        h[:8] = b"\x7fELF" + bytes((1 if width == 32 else 2, order, 1, abi))
        h[16:18] = kind.to_bytes(2, "big" if big else "little")
        h[18:20] = machine.to_bytes(2, "big" if big else "little")
        at = 36 if width == 32 else 48
        h[at : at + 4] = flags.to_bytes(4, "big" if big else "little")
        return bytes(h)

    @staticmethod
    def pe(
        machine: int, characteristics: int, subsystem: int, plus: bool = False, sections: int = 3
    ) -> bytes:
        h = bytearray(1024)
        h[:2] = b"MZ"
        h[0x3C:0x40] = (0x80).to_bytes(4, "little")
        h[0x80:0x84] = b"PE\x00\x00"
        h[0x84:0x86] = machine.to_bytes(2, "little")
        h[0x86:0x88] = sections.to_bytes(2, "little")
        h[0x94:0x96] = (240 if plus else 224).to_bytes(2, "little")
        h[0x96:0x98] = characteristics.to_bytes(2, "little")
        opt = 0x98
        h[opt : opt + 2] = (0x20B if plus else 0x10B).to_bytes(2, "little")
        h[opt + 68 : opt + 70] = subsystem.to_bytes(2, "little")
        return bytes(h)


class TestDescriptions:
    @pytest.mark.parametrize(
        ("header", "want"),
        [
            (Headers.elf(64, 1, 3, 62), ("ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)", "application/x-sharedlib")),
            (Headers.elf(64, 1, 2, 183, abi=3), ("ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux)", "application/x-executable")),
            (Headers.elf(32, 1, 1, 40, flags=0x05000000), ("ELF 32-bit LSB relocatable, ARM, EABI5 version 1 (SYSV)", "application/x-object")),
            (Headers.elf(64, 2, 3, 21, flags=1, abi=3), ("ELF 64-bit MSB shared object, 64-bit PowerPC or cisco 7500, Power ELF V1 ABI, version 1 (GNU/Linux)", "application/x-sharedlib")),
            (Headers.elf(64, 1, 3, 243, flags=5), ("ELF 64-bit LSB shared object, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV)", "application/x-sharedlib")),
            (Headers.elf(64, 1, 3, 0x107), ("ELF 64-bit LSB shared object, *unknown arch 0x107* version 1 (SYSV)", "application/x-sharedlib")),
            (Headers.elf(64, 1, 3, 8, flags=0xA0000000), ("ELF 64-bit LSB shared object, MIPS, MIPS64 rel6 version 1 (SYSV)", "application/x-sharedlib")),
            (Headers.pe(0x8664, 0x2022, 2, plus=True), ("PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 3 sections", "application/vnd.microsoft.portable-executable")),
            (Headers.pe(0x14C, 0x0302, 3), ("PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows, 3 sections", "application/vnd.microsoft.portable-executable")),
            # a .NET ReadyToRun image's machine is OS-xored, and libmagic leaves it out
            (Headers.pe(0x7ABD, 0x2022, 3), ("PE32 executable (DLL) (console), for MS Windows, 3 sections", "application/vnd.microsoft.portable-executable")),
            (b"\x00\x01\x02", ("data", "application/octet-stream")),
        ],
    )  # fmt: skip
    def test_the_words_are_libmagics(self, header: bytes, want: tuple[str, str]) -> None:
        assert FileType.describe(header) == want

    def test_upx_is_named_only_where_libmagic_looks(self) -> None:
        pe32 = bytearray(Headers.pe(0x14C, 0x0102, 2))
        pe32[0x80 + 0xF8 : 0x80 + 0xFC] = b"UPX0"
        assert "UPX compressed" in FileType.describe(bytes(pe32))[0]
        plus = bytearray(Headers.pe(0x8664, 0x0022, 3, plus=True))
        plus[0x80 + 0x108 : 0x80 + 0x10C] = b"UPX0"  # a PE32+ table's first name: not looked at
        assert "UPX" not in FileType.describe(bytes(plus))[0]

    def test_a_rule_reads_it(self) -> None:
        rules = Rules.compile(
            'import "magic" rule r { condition: magic.mime_type() == "application/x-sharedlib" and magic.type() contains "x86-64" }'
        )
        assert rules.match(Headers.elf(64, 1, 3, 62))

    def test_the_values_fit_the_declaration(self) -> None:
        assert Data.conforms(FileType.SCHEMA, FileType.data(Headers.elf(64, 1, 3, 62))) == []
