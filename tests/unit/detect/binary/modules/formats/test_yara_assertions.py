"""The macho and dex readers held to the reference engine's own test suite: every assertion of YARA 4.5.8's
tests/test-macho.c and tests/test-dex.c, replayed on the same files (tests/unit/data/rule_reference/yara_tests,
see its README) through Cordon's readers. Each check names the C test's condition it stands for; a `$1 at`
condition becomes the bytes at that offset."""

from __future__ import annotations

import hashlib
import re
from typing import Any

import pytest

from cordon_scanner.detect.binary.modules.formats.dex import Dex
from cordon_scanner.detect.binary.modules.formats.macho import Macho
from cordon_scanner.detect.binary.modules.formats.macho_tables import MachoTables
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "yara_tests"
T = MachoTables.MACHO
SHA256 = {
    "tiny-macho": "e29e46cc91651a52fa2078e747890ea9ceb89ed9f2f024fb4b60e04f7454fd63",
    "tiny-universal": "8917e8a4d33701d6c2f56f0acf62b9cad88abf48da394a5312fac0d0b93491bf",
    "macho_x86_file.bin": "f72b95cef1874d7c14228c1f3e0996eb75c6f7e3a3ec5e0659e7703818862e47",
    "macho_ppc_file.bin": "858e110792cde08d12c7dfa8e12e44586224a3d445a0d3a4781cd817212279fb",
    "macho_x86_object_file.bin": "1e709abbdd3e0681166ea3611fc80a25f6fc184f0ed143b51d496a931a91e8cf",
    "macho_x86_64_dylib_file.bin": "bf1907fec6d5ee364341b2bf3b7ddb0b5d37eaa9e102da5389b6afdcf816687c",
    "dex_file.bin": "94cfb4594a4b82fa29a1612f1c9260b728b58336bc797c48ccdd5e9d22fb93e7",
}


class Fixture:
    @staticmethod
    def read(name: str) -> bytes:
        data = (DIR / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == SHA256[name]
        return data

    @staticmethod
    def macho(name: str) -> dict[str, Any]:
        return Macho.data(Fixture.read(name))


class Regex:
    """A regular-expression argument as the engine hands one over: `run(text)` is the match's end, or -1."""

    def __init__(self, pattern: str) -> None:
        self.pattern = re.compile(pattern.encode())

    def run(self, text: bytes) -> int:
        m = self.pattern.search(text)
        return -1 if m is None else m.end()


class TestMachoX86:
    """test-macho.c on MACHO_X86_FILE."""

    def test_header_and_segments(self) -> None:
        m = Fixture.macho("macho_x86_file.bin")
        assert m["cputype"] == T["CPU_TYPE_X86"]
        assert m["filetype"] == T["MH_EXECUTE"]
        assert m["flags"] & T["MH_PIE"]
        assert m["number_of_segments"] == 4
        assert [m["segments"][i]["segname"] for i in range(4)] == [
            b"__PAGEZERO",
            b"__TEXT",
            b"__DATA",
            b"__LINKEDIT",
        ]
        assert m["segments"][0]["vmaddr"] == 0 and m["segments"][0]["vmsize"] == 0x1000
        assert m["segments"][2]["nsects"] == 2
        assert m["segments"][3]["fsize"] == 0x118

    def test_sections_and_entry_point(self) -> None:
        m = Fixture.macho("macho_x86_file.bin")
        text = m["segments"][1]["sections"][0]
        assert (text["addr"], text["size"], text["offset"]) == (0x1E90, 0xA6, 0x0E90)
        assert (text["sectname"], text["segname"]) == (b"__text", b"__TEXT")
        names = [m["segments"][1]["sections"][i]["sectname"] for i in range(1, 5)]
        assert names == [b"__symbol_stub", b"__stub_helper", b"__cstring", b"__unwind_info"]
        assert m["segments"][2]["sections"][0]["sectname"] == b"__nl_symbol_ptr"
        assert m["segments"][2]["sections"][1]["sectname"] == b"__la_symbol_ptr"
        assert m["entry_point"] == 0xE90


class TestMachoObjectAndPpc:
    def test_x86_object(self) -> None:
        """test-macho.c on MACHO_X86_OBJECT_FILE."""
        m = Fixture.macho("macho_x86_object_file.bin")
        assert m["cputype"] == T["CPU_TYPE_X86"] and m["filetype"] == T["MH_OBJECT"]
        assert m["number_of_segments"] == 1 and m["segments"][0]["segname"] == b""
        sec = m["segments"][0]["sections"][0]
        assert (sec["sectname"], sec["segname"]) == (b"__text", b"__TEXT")

    def test_ppc(self) -> None:
        """test-macho.c on MACHO_PPC_FILE (big-endian; the entry point from LC_UNIXTHREAD)."""
        m = Fixture.macho("macho_ppc_file.bin")
        assert m["cputype"] == T["CPU_TYPE_POWERPC"] and m["filetype"] == T["MH_EXECUTE"]
        assert m["number_of_segments"] == 4
        assert (
            m["segments"][0]["segname"] == b"__PAGEZERO"
            and m["segments"][2]["segname"] == b"__DATA"
        )
        assert m["segments"][2]["nsects"] == 6
        assert m["segments"][0]["vmaddr"] == 0 and m["segments"][0]["vmsize"] == 0x1000
        assert m["segments"][3]["fileoff"] == 65536 and m["segments"][3]["fsize"] == 46032
        assert m["entry_point"] == 0xEB8


class TestMachoDylib:
    """test-macho.c on MACHO_X86_64_DYLIB_FILE."""

    def test_header(self) -> None:
        m = Fixture.macho("macho_x86_64_dylib_file.bin")
        assert m["flags"] == 0x0000100085
        assert m["reserved"] == 0x00000001
        assert m["cputype"] == T["CPU_TYPE_X86_64"] and m["filetype"] == T["MH_DYLIB"]
        for flag in ("MH_DYLDLINK", "MH_NOUNDEFS", "MH_NO_REEXPORTED_DYLIBS", "MH_TWOLEVEL"):
            assert m["flags"] & T[flag]

    def test_segments_and_sections(self) -> None:
        m = Fixture.macho("macho_x86_64_dylib_file.bin")
        assert m["number_of_segments"] == 2
        assert (
            m["segments"][0]["segname"] == b"__TEXT"
            and m["segments"][1]["segname"] == b"__LINKEDIT"
        )
        link = m["segments"][1]
        assert (link["vmaddr"], link["vmsize"], link["nsects"], link["fsize"]) == (
            0x1000,
            0x1000,
            0,
            128,
        )
        text = m["segments"][0]["sections"]
        assert (text[0]["sectname"], text[0]["segname"]) == (b"__text", b"__TEXT")
        assert (text[1]["addr"], text[1]["size"], text[1]["offset"]) == (0xF98, 0x48, 3992)


class TestMachoFiles:
    def test_tiny_macho(self) -> None:
        assert Fixture.macho("tiny-macho")["number_of_segments"] == 1

    def test_tiny_universal_header_and_archs(self) -> None:
        m = Fixture.macho("tiny-universal")
        assert m["fat_magic"] == T["FAT_MAGIC"] and m["nfat_arch"] == 2
        a0, a1 = m["fat_arch"][0], m["fat_arch"][1]
        assert (a0["cputype"], a0["cpusubtype"], a0["offset"]) == (
            T["CPU_TYPE_I386"],
            T["CPU_SUBTYPE_I386_ALL"],
            4096,
        )
        assert a1["cputype"] == T["CPU_TYPE_X86_64"]
        assert (
            a1["cpusubtype"] == T["CPU_SUBTYPE_X86_64_ALL"] | T["CPU_SUBTYPE_LIB64"]
            and a1["align"] == 12
        )
        assert m["file"][0]["cputype"] == a0["cputype"] and m["file"][1]["cputype"] == a1["cputype"]
        assert m["file"][0]["magic"] == 0xCEFAEDFE and m["file"][1]["magic"] == 0xCFFAEDFE

    def test_tiny_universal_entry_points_and_functions(self) -> None:
        """`$1 at file[i].entry_point + fat_arch[i].offset` and `$1 at entry_point_for_arch(...)`: the
        bytes at those offsets are the ones the C test's strings name."""
        data = Fixture.read("tiny-universal")
        m = Macho.data(data)
        ep0 = m["file"][0]["entry_point"] + m["fat_arch"][0]["offset"]
        ep1 = m["file"][1]["entry_point"] + m["fat_arch"][1]["offset"]
        assert data[ep0 : ep0 + 7] == bytes.fromhex("5589e55683ec34")
        assert data[ep1 : ep1 + 8] == bytes.fromhex("554889e54883ec20")
        by_type, by_subtype = m["file_index_for_arch"]
        assert m["file"][by_type(T["CPU_TYPE_I386"])]["entry_point"] == m["file"][0]["entry_point"]
        assert (
            m["file"][by_type(T["CPU_TYPE_X86_64"])]["entry_point"] == m["file"][1]["entry_point"]
        )
        assert (
            m["file"][by_subtype(T["CPU_TYPE_I386"], T["CPU_SUBTYPE_I386_ALL"])]["entry_point"]
            == m["file"][0]["entry_point"]
        )
        both = by_subtype(
            T["CPU_TYPE_X86_64"], T["CPU_SUBTYPE_X86_64_ALL"] | T["CPU_SUBTYPE_LIB64"]
        )
        assert m["file"][both]["entry_point"] == m["file"][1]["entry_point"]
        ep_type, ep_subtype = m["entry_point_for_arch"]
        at = ep_subtype(T["CPU_TYPE_I386"], T["CPU_SUBTYPE_I386_ALL"])
        assert data[at : at + 7] == bytes.fromhex("5589e55683ec34")
        at = ep_type(T["CPU_TYPE_X86_64"])
        assert data[at : at + 8] == bytes.fromhex("554889e54883ec20")


class TestDex:
    """test-dex.c on DEX_FILE."""

    CLASS = b"Lcom/android/tools/ir/server/AppInfo;"

    @pytest.fixture
    def d(self) -> dict[str, Any]:
        return Dex.data(Fixture.read("dex_file.bin"))

    def test_header_and_tables(self, d: dict[str, Any]) -> None:
        assert d["header"]["magic"] == d["DEX_FILE_MAGIC_035"]
        assert d["header"]["checksum"] == 0x3F9C602F
        assert d["header"]["data_size"] == 0x18C
        assert d["string_ids"][0]["value"] == b"<clinit>"
        assert d["string_ids"][8]["value"] == b"com.google.helloyara"
        assert d["type_ids"][0]["descriptor_idx"] == 0x2
        assert d["proto_ids"][0]["shorty_idx"] == 0x6
        assert d["field_ids"][0]["class_idx"] == 0x1
        assert d["method_ids"][0]["class_idx"] == 0x1
        assert d["class_defs"][0]["class_idx"] == 0x1
        assert d["map_list"]["size"] == 12
        assert d["map_list"]["map_item"][0]["type"] == d["TYPE_HEADER_ITEM"]

    def test_fields_and_methods(self, d: dict[str, Any]) -> None:
        assert d["number_of_fields"] == 2
        assert (
            d["field"][0]["class_name"] == self.CLASS and d["field"][0]["name"] == b"applicationId"
        )
        assert d["number_of_methods"] == 2
        assert d["method"][0]["class_name"] == self.CLASS
        assert d["method"][0]["proto"] == b"V" and d["method"][0]["name"] == b"<clinit>"
        assert d["method"][1]["name"] == b"<init>"

    def test_functions(self, d: dict[str, Any]) -> None:
        by_name, by_class_and_name, by_regex, by_class_and_regex = d["has_method"]
        assert by_name(b"<init>") == 1
        assert by_class_and_name(self.CLASS, b"<clinit>") == 1
        assert by_regex(Regex("init")) == 1
        assert by_class_and_regex(Regex("AppInfo"), Regex("init")) == 1
        class_by_name, class_by_regex = d["has_class"]
        assert class_by_name(self.CLASS) == 1
        assert class_by_regex(Regex("AppInfo")) == 1
