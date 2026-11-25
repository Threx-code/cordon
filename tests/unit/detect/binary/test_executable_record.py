"""SI-T9: one record per executable, from its own bytes: format, architecture, imports by group, string shapes, packer, entropy, signature.

The ELF, PE and Mach-O files are built here, byte by byte; nothing is executed.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
from collections import Counter

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


# -- header, slice walk, caps and tables (mutation survivors) --------------------------------------

FLAT = bytes(range(256)) * 16  # 4 KiB, every byte equally often: 8 bits
PLAIN = b"\x00" * 4096  # 0 bits


class Bits:
    @staticmethod
    def of(block: bytes) -> float:
        n = len(block)
        return -sum(c / n * math.log2(c / n) for c in Counter(block).values())


class Make:
    @staticmethod
    def elf(
        *,
        wide: bool = True,
        big: bool = False,
        machine: int = 62,
        sections: tuple[tuple[int, bytes], ...] = (),
    ) -> bytes:
        order = ">" if big else "<"
        ident = b"\x7fELF" + bytes([2 if wide else 1, 2 if big else 1, 1]) + bytes(9)
        header_size, entry = (64, 64) if wide else (52, 40)
        cursor, offsets = header_size, []
        for _kind, data in sections:
            offsets.append(cursor)
            cursor += len(data)
        fields = "HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"
        header = ident + struct.pack(
            order + fields,
            3,
            machine,
            1,
            0,
            0,
            cursor,
            0,
            header_size,
            0,
            0,
            entry,
            len(sections),
            0,
        )
        heads = b""
        for (kind, data), offset in zip(sections, offsets, strict=True):
            heads += (
                struct.pack(order + "IIQQQQIIQQ", 0, kind, 0, 0, offset, len(data), 0, 0, 1, 0)
                if wide
                else struct.pack(order + "IIIIIIIIII", 0, kind, 0, 0, offset, len(data), 0, 0, 1, 0)
            )
        return header + b"".join(data for _kind, data in sections) + heads

    @staticmethod
    def pe(
        *,
        plus: bool = False,
        machine: int = 0x14C,
        sections: tuple[bytes, ...] = (),
        sign: tuple[int, int] = (0, 0),
        optional_size: int | None = None,
        lfanew: int = 0x80,
    ) -> bytes:
        full = 240 if plus else 224
        size = full if optional_size is None else optional_size
        optional = bytearray(full)
        struct.pack_into("<H", optional, 0, 0x20B if plus else 0x10B)
        struct.pack_into("<II", optional, (112 if plus else 96) + 32, *sign)
        table = lfanew + 24 + size
        raw = table + 40 * len(sections)
        heads, body = b"", b""
        for data in sections:
            heads += b".text\x00\x00\x00" + struct.pack(
                "<IIIIIIHHI", len(data), 0, len(data), raw + len(body), 0, 0, 0, 0, 0
            )
            body += data
        coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", machine, len(sections), 0, 0, 0, size, 0x102)
        dos = (b"MZ" + bytes(58) + struct.pack("<I", lfanew)).ljust(lfanew, b"\x00")
        return dos + coff + bytes(optional[:size]) + heads + body

    @staticmethod
    def macho(
        *,
        wide: bool = True,
        big: bool = False,
        cpu: int = 0x0100000C,
        payloads: tuple[bytes, ...] = (),
        signed: bool = False,
        commands: int | None = None,
    ) -> bytes:
        order = ">" if big else "<"
        header_size = 32 if wide else 28
        sections = len(payloads)
        segment_size = 72 + 80 * sections
        total = header_size + (segment_size if wide else 0) + (16 if signed else 0)
        cursor, offsets = total, []
        for data in payloads:
            offsets.append(cursor)
            cursor += len(data)
        body = b""
        if wide:
            body += struct.pack(
                order + "II16sQQQQIIII",
                0x19,
                segment_size,
                b"__TEXT",
                0,
                0,
                0,
                0,
                7,
                5,
                sections,
                0,
            )
            for data, offset in zip(payloads, offsets, strict=True):
                body += struct.pack(
                    order + "16s16sQQIIIIIIII",
                    b"__text",
                    b"__TEXT",
                    0,
                    len(data),
                    offset,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
        if signed:
            body += struct.pack(order + "IIII", 0x1D, 16, 0, 0)
        count = commands if commands is not None else (1 if wide else 0) + (1 if signed else 0)
        magic = struct.pack(order + "I", 0xFEEDFACF if wide else 0xFEEDFACE)
        fields = struct.pack(order + "iIIII", cpu, 0, 2, count, len(body))
        return magic + fields + bytes(4) + (bytes(4) if wide else b"") + body + b"".join(payloads)

    @staticmethod
    def universal(*slices: tuple[int, bytes]) -> bytes:
        head = struct.pack(">II", 0xCAFEBABE, len(slices))
        cursor = 8 + 20 * len(slices)
        table = b""
        for cpu, data in slices:
            table += struct.pack(">iIIII", cpu, 0, cursor, len(data), 4)
            cursor += len(data)
        return head + table + b"".join(data for _cpu, data in slices)


class Read:
    @staticmethod
    def of(data: bytes) -> dict:
        found = ExecutableRecord.of(data)
        assert found is not None
        return found


record = Read.of


class TestTheArchitectureTables:
    @pytest.mark.parametrize(
        "machine, name",
        [
            (3, "x86"),
            (8, "mips"),
            (20, "ppc"),
            (21, "ppc64"),
            (22, "s390"),
            (40, "arm"),
            (62, "x86_64"),
            (183, "arm64"),
            (243, "riscv"),
            (999, "other"),
        ],
    )
    def test_elf_machines(self, machine: int, name: str) -> None:
        assert record(Make.elf(machine=machine))["architecture"] == name

    @pytest.mark.parametrize(
        "machine, name",
        [
            (0x14C, "x86"),
            (0x1C0, "arm"),
            (0x1C4, "arm"),
            (0x8664, "x86_64"),
            (0xAA64, "arm64"),
            (0x200, "ia64"),
            (0x1234, "other"),
        ],
    )
    def test_pe_machines(self, machine: int, name: str) -> None:
        assert record(Make.pe(machine=machine))["architecture"] == name

    @pytest.mark.parametrize(
        "cpu, name",
        [
            (7, "x86"),
            (0x01000007, "x86_64"),
            (12, "arm"),
            (0x0100000C, "arm64"),
            (18, "ppc"),
            (0x01000012, "ppc64"),
            (99, "other"),
        ],
    )
    def test_macho_cpus(self, cpu: int, name: str) -> None:
        assert record(Make.macho(cpu=cpu))["architecture"] == name


class TestElfHeaders:
    @pytest.mark.parametrize("wide", [True, False])
    @pytest.mark.parametrize("big", [False, True])
    def test_every_width_and_byte_order_reads_machine_and_sections(
        self, wide: bool, big: bool
    ) -> None:
        found = record(Make.elf(wide=wide, big=big, machine=40, sections=((1, FLAT), (1, PLAIN))))
        assert found["architecture"] == "arm"
        assert found["entropy"] == {"max": 8.0, "mean": 4.0, "sections": 2}

    def test_a_section_that_holds_no_bytes_in_the_file_or_has_none_or_runs_past_the_end_is_not_measured(
        self,
    ) -> None:
        sections = ((8, FLAT), (1, b""), (1, PLAIN))
        found = record(Make.elf(sections=sections))
        assert found["entropy"] == {"max": 0.0, "mean": 0.0, "sections": 1}
        cut = Make.elf(sections=((1, FLAT),))[
            :-70
        ]  # the header table is cut: the section list is unreadable
        assert record(cut)["entropy"]["sections"] == 0

    def test_a_section_header_that_points_past_the_file_is_not_measured(self) -> None:
        data = bytearray(Make.elf(sections=((1, PLAIN),)))
        struct.pack_into("<Q", data, len(data) - 64 + 24, 10_000_000)  # its offset
        assert record(bytes(data))["entropy"]["sections"] == 0

    def test_a_header_cut_short_is_unknown_not_an_error(self) -> None:
        found = record(b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x03\x00")
        assert (
            found["architecture"],
            found["entropy"]["sections"],
            found["signature"]["present"],
        ) == ("unknown", 0, False)


class TestPeHeaders:
    @pytest.mark.parametrize("plus", [False, True])
    def test_the_signature_directory_of_either_optional_header(self, plus: bool) -> None:
        assert record(Make.pe(plus=plus, sign=(0x400, 0x200)))["signature"]["present"] is True
        assert record(Make.pe(plus=plus, sign=(0x400, 0)))["signature"]["present"] is False
        assert record(Make.pe(plus=plus))["signature"]["present"] is False

    def test_an_optional_header_too_short_to_hold_the_directory_says_unsigned(self) -> None:
        assert (
            record(Make.pe(sign=(0x400, 0x200), optional_size=100))["signature"]["present"] is False
        )

    def test_sections_are_measured_by_their_raw_pointer_and_size(self) -> None:
        found = record(Make.pe(sections=(FLAT, PLAIN)))
        assert found["entropy"] == {"max": 8.0, "mean": 4.0, "sections": 2}

    def test_a_section_past_the_end_or_empty_is_not_measured(self) -> None:
        data = bytearray(Make.pe(sections=(PLAIN,)))
        table = 0x80 + 24 + 224
        struct.pack_into("<I", data, table + 20, 50_000_000)
        assert record(bytes(data))["entropy"]["sections"] == 0
        empty = record(Make.pe(sections=(b"", PLAIN)))
        assert empty["entropy"]["sections"] == 1

    @pytest.mark.parametrize(
        "data",
        [
            b"MZ" + bytes(20),
            b"MZ" + bytes(58) + struct.pack("<I", 0x40) + bytes(100),
            Make.pe()[: 0x80 + 10],
        ],
    )
    def test_a_dos_stub_with_no_pe_header_is_not_an_executable(self, data: bytes) -> None:
        assert ExecutableRecord.of(data) is None

    def test_a_pe_header_whose_signature_is_wrong_is_not_an_executable(self) -> None:
        data = bytearray(Make.pe())
        data[0x80:0x84] = b"PX\x00\x00"
        assert ExecutableRecord.of(bytes(data)) is None

    def test_another_header_offset_is_followed(self) -> None:
        assert record(Make.pe(lfanew=0x100, machine=0x8664))["architecture"] == "x86_64"


class TestMachOHeaders:
    def test_a_big_endian_file_is_not_recognised_on_its_own(self) -> None:
        assert ExecutableRecord.of(Make.macho(big=True, payloads=(FLAT,))) is None

    def test_a_big_endian_slice_of_a_universal_binary_is_read(self) -> None:
        wide = Make.macho(big=True, cpu=0x0100000C, payloads=(FLAT,), signed=True)
        narrow = Make.macho(wide=False, big=True, cpu=7, signed=False)
        found = record(Make.universal((0x0100000C, wide), (7, narrow)))
        assert found["architecture"] == "arm64+x86"
        assert found["entropy"]["sections"] == 1 and found["signature"]["present"] is True

    def test_a_wide_header(self) -> None:
        big = False
        found = record(Make.macho(big=big, payloads=(FLAT,), signed=True))
        assert found["architecture"] == "arm64"
        assert found["entropy"] == {"max": 8.0, "mean": 8.0, "sections": 1}
        assert found["signature"]["present"] is True

    def test_a_narrow_header_has_no_sections_and_may_be_signed(self) -> None:
        found = record(Make.macho(wide=False, cpu=7, signed=True))
        assert (
            found["architecture"],
            found["entropy"]["sections"],
            found["signature"]["present"],
        ) == ("x86", 0, True)

    def test_a_load_command_smaller_than_its_own_header_ends_the_walk(self) -> None:
        data = bytearray(Make.macho(payloads=(PLAIN,), signed=True, commands=2))
        # the segment's command size, cut to 4: the walk stops before it reads a section or the signature
        struct.pack_into("<I", data, 36, 4)
        found = record(bytes(data))
        assert (found["entropy"]["sections"], found["signature"]["present"]) == (0, False)

    def test_the_walk_reads_at_most_256_commands(self) -> None:
        data = Make.macho(commands=300)
        # 300 commands are declared but only 1 exists; the walk is bounded and the cut input is not an error
        assert record(data)["architecture"] == "arm64"

    def test_a_section_with_no_offset_or_no_length_or_past_the_end_is_not_measured(self) -> None:
        for field in (48, 40):
            data = bytearray(Make.macho(payloads=(PLAIN,)))
            struct.pack_into("<I" if field == 48 else "<Q", data, 32 + 72 + field, 0)
            assert record(bytes(data))["entropy"]["sections"] == 0
        data = bytearray(Make.macho(payloads=(PLAIN,)))
        struct.pack_into("<I", data, 32 + 72 + 48, 90_000_000)
        assert record(bytes(data))["entropy"]["sections"] == 0


class TestTheUniversalSliceWalk:
    THIN = Make.macho(payloads=(FLAT,))

    def test_each_slice_is_named_measured_and_checked_for_a_signature(self) -> None:
        one = Make.macho(cpu=0x0100000C, payloads=(FLAT,))
        two = Make.macho(cpu=0x01000007, payloads=(PLAIN,), signed=True)
        found = record(Make.universal((0x0100000C, one), (0x01000007, two)))
        assert found["architecture"] == "arm64+x86_64"
        assert found["entropy"] == {"max": 8.0, "mean": 4.0, "sections": 2}
        assert found["signature"]["present"] is True

    def test_two_slices_of_one_architecture_name_it_once(self) -> None:
        assert (
            record(Make.universal((12, Make.macho(cpu=12)), (12, Make.macho(cpu=12))))[
                "architecture"
            ]
            == "arm"
        )

    def test_a_slice_only_counts_when_it_starts_with_a_mach_o_magic(self) -> None:
        assert (
            ExecutableRecord.of(Make.universal((12, b"not a mach-o file at all, but long enough")))
            is None
        )

    @pytest.mark.parametrize("count", [0, 9, 50])
    def test_a_count_outside_one_to_eight_is_not_a_universal_binary(self, count: int) -> None:
        assert ExecutableRecord.of(struct.pack(">II", 0xCAFEBABE, count) + bytes(400)) is None

    def test_a_table_longer_than_the_file_is_not_a_universal_binary(self) -> None:
        assert ExecutableRecord.of(struct.pack(">II", 0xCAFEBABE, 8) + bytes(100)) is None

    def test_a_slice_that_runs_past_the_end_is_not_a_universal_binary(self) -> None:
        data = bytearray(Make.universal((12, self.THIN)))
        struct.pack_into(">I", data, 8 + 12, len(data) + 1)  # its size
        assert ExecutableRecord.of(bytes(data)) is None

    def test_exactly_eight_slices_are_read(self) -> None:
        found = record(Make.universal(*[(12, Make.macho(cpu=12)) for _ in range(8)]))
        assert found["architecture"] == "arm"

    def test_the_slice_offsets_are_added_to_the_section_offsets(self) -> None:
        found = record(
            Make.universal(
                (12, Make.macho(cpu=12, payloads=(FLAT,))),
                (12, Make.macho(cpu=12, payloads=(PLAIN,))),
            )
        )
        assert (
            found["entropy"]["sections"] == 2
            and found["entropy"]["max"] == 8.0
            and found["entropy"]["mean"] == 4.0
        )


class TestTheCaps:
    def test_at_most_96_sections_of_an_elf_are_measured(self) -> None:
        assert (
            record(Make.elf(sections=tuple((1, PLAIN) for _ in range(100))))["entropy"]["sections"]
            == 96
        )

    def test_at_most_96_sections_of_a_pe_are_measured(self) -> None:
        assert (
            record(Make.pe(sections=tuple(PLAIN for _ in range(100))))["entropy"]["sections"] == 96
        )

    def test_at_most_96_sections_of_a_mach_o_are_measured(self) -> None:
        assert (
            record(Make.macho(payloads=tuple(PLAIN for _ in range(100))))["entropy"]["sections"]
            == 96
        )

    def test_a_section_is_measured_over_its_first_mebibyte_only(self) -> None:
        big = PLAIN * 256 + FLAT * 300  # 1 MiB of zeros, then a lot of every byte
        assert len(big) > 1 << 20
        assert (
            record(Make.elf(sections=((1, big),)))["entropy"]["max"]
            == round(Bits.of(big[: 1 << 20]), 2)
            == 0.0
        )
        mixed = PLAIN * 192 + FLAT * 100  # 768 KiB of zeros, then flat: inside the first MiB
        assert record(Make.elf(sections=((1, mixed),)))["entropy"]["max"] == round(
            Bits.of(mixed[: 1 << 20]), 2
        )

    def test_strings_are_read_from_the_first_eight_mebibytes_and_a_larger_file_says_so(
        self,
    ) -> None:
        url = b" https://inside.example.net/x \x00"
        late = Make.elf(sections=((1, b"\x00" * (8 << 20)),)) + url
        found = record(late)
        assert (
            found["strings"]["url"] == 0
            and found["read_whole"] is False
            and found["unread_reason"] == "over_the_read_limit"
        )
        early = record(Make.elf(sections=((1, url + b"\x00" * ((8 << 20) - 400)),)))
        assert early["strings"]["url"] == 1 and early["read_whole"] is True

    def test_at_most_32_functions_are_named_in_a_group(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ExecutableRecord, "FUNCTIONS", 2)
        names = sorted(ExecutableRecord.vocabulary()["network"])[:5]
        found = record(Build.elf(names, ["libc.so.6"]))
        assert (
            found["imports"]["functions"]["network"] == names[:2] and found["imports"]["total"] == 5
        )

    def test_the_default_caps(self) -> None:
        assert (
            ExecutableRecord.MAX_SECTIONS,
            ExecutableRecord.SECTION_BYTES,
            ExecutableRecord.STRING_BYTES,
            ExecutableRecord.FUNCTIONS,
        ) == (96, 1 << 20, 8 << 20, 32)


class TestTheRecordItself:
    def test_a_format_that_is_not_a_native_executable_is_not_recorded(self) -> None:
        assert ExecutableRecord.of(b"\x00asm\x01\x00\x00\x00") is None
        assert ExecutableRecord.of(b"MZ") is None

    def test_a_file_with_no_import_table_says_it_was_not_read(self) -> None:
        assert record(Make.elf()[:20])["imports"]["read"] is False
        assert record(Build.elf(["connect"], ["libc.so.6"]))["imports"]["read"] is True

    def test_no_measurable_section_is_null_not_zero(self) -> None:
        assert record(Make.elf())["entropy"] == {"max": None, "mean": None, "sections": 0}

    def test_the_entropy_is_rounded_to_two_places(self) -> None:
        data = b"aaaab"
        found = record(Make.elf(sections=((1, data),)))
        assert found["entropy"]["max"] == round(Bits.of(data), 2) == 0.72

    def test_the_record_carries_the_digest_and_size_of_the_file(self) -> None:
        data = Make.elf(sections=((1, FLAT),))
        found = record(data)
        assert found["sha256"] == hashlib.sha256(data).hexdigest() and found["size"] == len(data)
        json.dumps(found)


class Raw:
    @staticmethod
    def macho(
        commands: list[bytes],
        *,
        wide: bool = True,
        cpu: int = 0x0100000C,
        declared: int | None = None,
        tail: bytes = b"",
    ) -> bytes:
        body = b"".join(commands)
        count = len(commands) if declared is None else declared
        magic = struct.pack("<I", 0xFEEDFACF if wide else 0xFEEDFACE)
        return (
            magic
            + struct.pack("<iIIII", cpu, 0, 2, count, len(body))
            + bytes(4)
            + (bytes(4) if wide else b"")
            + body
            + tail
        )

    @staticmethod
    def filler(size: int = 8) -> bytes:
        return struct.pack("<II", 0x30, size).ljust(size, b"\x00")

    SIGN = struct.pack("<IIII", 0x1D, 16, 0, 0)


class TestTheLoadCommandWalk:
    def test_the_walk_stops_at_256_commands_and_not_before(self) -> None:
        for fillers, signed in ((255, True), (256, False), (300, False)):
            data = Raw.macho([Raw.filler() for _ in range(fillers)] + [Raw.SIGN])
            assert record(data)["signature"]["present"] is signed, fillers

    def test_a_command_smaller_than_its_own_header_ends_the_walk_before_what_follows(self) -> None:
        data = Raw.macho([Raw.filler(4), Raw.SIGN], declared=2)
        assert record(data)["signature"]["present"] is False

    def test_a_command_of_exactly_eight_bytes_is_walked_over(self) -> None:
        assert record(Raw.macho([Raw.filler(8), Raw.SIGN]))["signature"]["present"] is True

    def test_a_command_that_is_not_a_segment_is_not_read_as_one(self) -> None:
        segment = struct.pack("<II16sQQQQIIII", 0x19, 72 + 80, b"__TEXT", 0, 0, 0, 0, 7, 5, 1, 0)
        section = struct.pack(
            "<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0, 4, 0, 0, 0, 0, 0, 0, 0, 0
        )
        # a filler command whose bytes would read as a huge section count if it were taken for a segment
        junk = struct.pack("<II", 0x30, 96) + b"\xff" * 88
        data = Raw.macho([junk, segment + section])
        assert (
            record(data)["entropy"]["sections"] == 0
        )  # the one section has offset 0: not measured

    def test_a_declared_count_beyond_the_commands_present_keeps_what_was_read(self) -> None:
        found = record(Raw.macho([Raw.SIGN], declared=40))
        assert (found["architecture"], found["signature"]["present"]) == ("arm64", True)

    def test_a_section_whose_length_runs_past_the_end_is_not_measured(self) -> None:
        data = bytearray(Make.macho(payloads=(PLAIN,)))
        struct.pack_into("<Q", data, 32 + 72 + 40, 50_000_000)
        assert record(bytes(data))["entropy"]["sections"] == 0


class TestBoundariesOfTheHeaders:
    def test_an_elf_whose_section_table_is_cut_keeps_its_machine(self) -> None:
        found = record(Make.elf(sections=((1, FLAT),))[:-70])
        assert (found["architecture"], found["entropy"]["sections"]) == ("x86_64", 0)

    def test_an_elf_section_whose_size_runs_past_the_end_is_not_measured(self) -> None:
        data = bytearray(Make.elf(sections=((1, PLAIN),)))
        struct.pack_into("<Q", data, len(data) - 64 + 32, 50_000_000)
        assert record(bytes(data))["entropy"]["sections"] == 0

    def test_a_pe_header_that_just_fits_is_a_record_and_one_byte_less_is_not(self) -> None:
        pe = Make.pe()
        assert ExecutableRecord.of(pe[: 0x80 + 24]) is not None
        assert ExecutableRecord.of(pe[: 0x80 + 23]) is None

    @pytest.mark.parametrize("plus, size", [(False, 96 + 40), (True, 112 + 40)])
    def test_the_signature_directory_must_fit_inside_the_optional_header(
        self, plus: bool, size: int
    ) -> None:
        assert (
            record(Make.pe(plus=plus, sign=(0x400, 0xFF), optional_size=size))["signature"][
                "present"
            ]
            is True
        )
        assert (
            record(Make.pe(plus=plus, sign=(0x400, 0xFF), optional_size=size - 1))["signature"][
                "present"
            ]
            is False
        )

    @pytest.mark.parametrize("plus", [False, True])
    def test_the_directory_is_read_at_its_own_place_and_a_size_of_one_counts(
        self, plus: bool
    ) -> None:
        assert record(Make.pe(plus=plus, sign=(0x11223344, 0)))["signature"]["present"] is False
        assert record(Make.pe(plus=plus, sign=(0x400, 1)))["signature"]["present"] is True
        assert record(Make.pe(plus=plus, sign=(0, 0x80)))["signature"]["present"] is True

    def test_a_pe_whose_section_count_is_beyond_its_table_keeps_its_machine(self) -> None:
        data = bytearray(Make.pe(machine=0x8664, sections=(PLAIN,)))
        struct.pack_into("<H", data, 0x80 + 6, 60)
        found = record(bytes(data))
        assert (found["architecture"], found["entropy"]["sections"]) == ("x86_64", 1)

    def test_a_pe_section_whose_size_runs_past_the_end_is_not_measured(self) -> None:
        data = bytearray(Make.pe(sections=(PLAIN,)))
        struct.pack_into("<I", data, 0x80 + 24 + 224 + 16, 50_000_000)
        assert record(bytes(data))["entropy"]["sections"] == 0

    @pytest.mark.parametrize("count, length", [(1, 27), (2, 47), (8, 167)])
    def test_a_universal_table_one_byte_short_is_not_one(self, count: int, length: int) -> None:
        assert (
            ExecutableRecord.of((struct.pack(">II", 0xCAFEBABE, count) + bytes(400))[:length])
            is None
        )

    def test_a_thin_mach_o_reads_its_sections_from_their_own_offsets(self) -> None:
        assert record(Make.macho(payloads=(b"aaaab",)))["entropy"]["max"] == 0.72

    def test_a_universal_slice_reads_its_sections_from_their_own_offsets(self) -> None:
        found = record(
            Make.universal(
                (12, Make.macho(cpu=12, payloads=(b"aaaab",))),
                (12, Make.macho(cpu=12, payloads=(b"aaaab",))),
            )
        )
        assert found["entropy"] == {"max": 0.72, "mean": 0.72, "sections": 2}

    def test_a_universal_binary_none_of_whose_slices_is_signed_is_unsigned(self) -> None:
        assert (
            record(Make.universal((12, Make.macho(cpu=12)), (7, Make.macho(cpu=7))))["signature"][
                "present"
            ]
            is False
        )

    def test_the_mean_and_the_largest_are_rounded_to_two_places(self) -> None:
        found = record(Make.elf(sections=((1, b"aaaab"), (1, PLAIN))))
        assert found["entropy"] == {"max": 0.72, "mean": 0.36, "sections": 2}


class TestLastBoundaries:
    def test_a_signature_command_that_ends_exactly_at_the_end_of_the_file_is_read(self) -> None:
        assert record(Raw.macho([struct.pack("<II", 0x1D, 8)]))["signature"]["present"] is True

    @pytest.mark.parametrize("plus", [False, True])
    def test_an_optional_header_too_short_for_the_directory_never_reads_the_bytes_after_it(
        self, plus: bool
    ) -> None:
        short = (112 if plus else 96) + 39
        assert (
            record(Make.pe(plus=plus, sections=(PLAIN,), optional_size=short))["signature"][
                "present"
            ]
            is False
        )
