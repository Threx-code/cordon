"""The one `dex` module answering both engines' shapes (modules.formats.dex with dex_x): YARA-X's names
filled from the same parse on the dex built in test_dex (decoded strings, resolved types, prototypes,
fields, methods and classes, the map items, is_dex, contains_*, checksum() and signature()); and the two
names both engines declare with different types, header.magic and header.signature, read through the
compiler by the operand's type, with the load note where nothing decides (rule_engine.build)."""

from __future__ import annotations

import hashlib
import zlib

from test_dex import Build

from cordon_scanner.detect.binary.modules.formats.dex import Dex
from cordon_scanner.detect.binary.modules.formats.dex_x import DexX
from cordon_scanner.detect.binary.modules.values import Data
from cordon_scanner.detect.binary.rule_engine.lang import Rules


class TestSecondShape:
    def test_resolved_tables(self) -> None:
        d = Dex.data(Build.dex())
        assert d["is_dex"] is True
        h = d["header"]
        assert h["magic"] == (b"dex\n035\x00", 0x6465780A)
        assert h["signature"] == (b"\xab" * 20, b"ab" * 20)
        assert (h["version"], h["link_off"], h["data_off"]) == (35, 0, h["data_offset"])
        assert "container_size" not in h
        assert d["strings"] == {0: b"Lcom/A;", 1: b"run", 2: b"V", 3: b"x"}
        assert d["types"] == {0: b"Lcom/A;"}
        assert d["protos"] == {
            0: {"shorty": b"V", "return_type": b"Lcom/A;", "parameters_count": 0, "parameters": {}}
        }
        assert d["fields"] == {0: {"class": b"Lcom/A;", "type": b"Lcom/A;", "name": b"x"}}
        assert d["methods"] == {0: {"class": b"Lcom/A;", "proto": d["protos"][0], "name": b"run"}}
        assert d["class_defs"][0]["class"] == b"Lcom/A;" and "superclass" not in d["class_defs"][0]
        assert d["class_defs"][0]["access_flags"] == 1  # one value under both shapes
        assert d["map_list"]["items"] == d["map_list"]["map_item"]

    def test_functions(self) -> None:
        data = Build.dex()
        d = Dex.data(data)
        assert d["contains_string"][0](b"run") is True and d["contains_string"][0](b"walk") is False
        assert d["contains_method"][0](b"run") is True and d["contains_method"][0](b"x") is False
        assert (
            d["contains_class"][0](b"Lcom/A;") is True
            and d["contains_class"][0](b"Lcom/B;") is False
        )
        assert d["checksum"][0]() == zlib.adler32(data[12:]) & 0xFFFFFFFF
        assert d["signature"][0]() == hashlib.sha1(data[32:]).hexdigest().encode()  # noqa: S324

    def test_not_a_dex_under_the_second_shape(self) -> None:
        d = Dex.data(b"not a dex at all, but long enough to be looked at " * 4)
        assert d["is_dex"] is False and d["strings"] == {} and d["header"] == {}
        assert d["contains_string"][0](b"run") is False and d["checksum"][0]() is None
        assert d["signature"][0]() is None

    def test_the_second_shape_has_its_own_acceptance(self) -> None:
        """A header YARA reads that YARA-X refuses (an endian tag it does not know) gives YARA's shape
        and `is_dex` false; a version 040 YARA-X reads and YARA does not gives the reverse."""
        refused = Dex.data(Build.patched(Build.dex(), 40, 0x11111111))
        assert refused["is_dex"] is False and refused["number_of_methods"] == 1
        assert refused["header"]["magic"] == (b"dex\n035\x00", None) and refused["strings"] == {}
        newer = Dex.data(b"dex\n040\x00" + Build.dex()[8:])
        assert newer["is_dex"] is True and newer["header"]["version"] == 40
        assert "number_of_methods" not in newer and newer["string_ids"] == {}
        assert newer["methods"][0]["name"] == b"run" and "checksum" in newer["header"]
        assert "magic" in newer["header"] and newer["header"]["magic"][0] == b"dex\n040\x00"

    def test_a_string_that_is_not_modified_utf8_is_left_out(self) -> None:
        d = Dex.data(Build.dex((b"Lcom/A;", b"run", b"V", b"\xed\xa0\x80")))  # a lone surrogate
        assert 3 not in d["strings"] and d["string_ids"][3]["value"] == b"\xed\xa0\x80"
        assert DexX.mutf8(b"a\xc0\x80b") == b"a\x00b"
        assert DexX.mutf8(b"\xed\xa0\xbd\xed\xb8\x80") == "\U0001f600".encode()  # a surrogate pair
        assert DexX.mutf8(b"\xff") is None

    def test_conforms_to_the_declared_schema(self) -> None:
        for data in (Build.dex(), b"dex\n040\x00" + Build.dex()[8:], Build.shared(2, 3), b"no"):
            assert Data.conforms(Dex.SCHEMA, Dex.data(data)) == []


class TestTheTwoShapesThroughTheCompiler:
    """header.magic and header.signature read by the operand's type; the load note where nothing decides."""

    @staticmethod
    def run(condition: str, data: bytes | None = None) -> tuple[bool, list[tuple[str, str]]]:
        rules = Rules.compile('import "dex" rule r { condition: ' + condition + " }")
        return bool(rules.match(Build.dex() if data is None else data)), rules.notes

    @staticmethod
    def signed(data: bytes) -> bytes:
        """`data` with the signature and checksum its header is meant to carry."""
        signature = hashlib.sha1(data[32:]).digest()  # noqa: S324
        body = data[:12] + signature + data[32:]
        checksum = zlib.adler32(body[12:]) & 0xFFFFFFFF
        return body[:8] + checksum.to_bytes(4, "little") + body[12:]

    def test_magic_by_the_operand_type(self) -> None:
        assert self.run("dex.header.magic == dex.DEX_FILE_MAGIC_035") == (True, [])
        assert self.run("dex.header.magic == 0x6465780A") == (True, [])
        assert self.run('dex.header.magic == "dex\\n035\\x00" and dex.header.version == 35') == (
            True,
            [],
        )
        assert self.run("dex.header.magic == 0x6465780B") == (False, [])

    def test_signature_by_the_literal_or_a_companion(self) -> None:
        raw = "".join("\\xab" for _ in range(20))
        assert self.run(f'dex.header.signature == "{raw}"') == (True, [])
        assert self.run('dex.header.signature == "' + "ab" * 20 + '"') == (True, [])
        signed = self.signed(Build.dex())
        assert self.run("dex.header.signature == dex.signature()", signed) == (
            True,
            [],
        )  # YARA-X's own test
        assert self.run("dex.header.checksum == dex.checksum()", signed) == (True, [])
        assert self.run("dex.header.signature == dex.signature()") == (
            False,
            [],
        )  # no true digest in the header

    def test_where_nothing_decides_the_reference_shape_is_read_and_noted(self) -> None:
        held, notes = self.run("defined dex.header.magic")
        assert held and notes == [
            (
                "r",
                "dex.header.magic has two shapes and nothing in the rule decides: read as YARA's shape, not YARA-X's shape",
            )
        ]
        held, notes = self.run("dex.header.signature matches /^\\xab/")
        assert (
            held
            and len(notes) == 1
            and notes[0][1].startswith("dex.header.signature has two shapes")
        )

    def test_each_name_keeps_its_own_engine(self) -> None:
        assert self.run('dex.has_method("run") and dex.contains_method("run")') == (True, [])
        assert self.run('dex.string_ids[1].value == "run" and dex.strings[1] == "run"') == (
            True,
            [],
        )
        assert self.run("dex.number_of_methods == 1 and dex.is_dex") == (True, [])
