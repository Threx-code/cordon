"""Unit tests for the declarative layout primitives (modules.layout), independently of any binary format:
the bulk tuple reader (``Grid.tuples``), the lazy record view (``Row``) and the deferred sequence
(``LazySeq``). The readers' value tests exercise these through real files; these pin the primitives' own
contract so a change to them is caught directly.
"""

from __future__ import annotations

import struct

import pytest

from cordon_scanner.detect.binary.modules.layout import (
    ABSENT,
    U8,
    U16,
    U32,
    Cursor,
    Grid,
    ImageMap,
    Index,
    Layout,
    LazyRecord,
    LazySeq,
    Row,
)


class Build:
    """Small crafted structures, so the primitives are exercised without a real executable."""

    ROW = Layout((("a", U8), ("b", U16), ("c", U32)))  # stride 7, little-endian by Cursor default

    @staticmethod
    def grid(rows: int, data: bytes, count: int | None = None) -> Grid:
        return Grid(Cursor(data), 0, Build.ROW, rows if count is None else count)


class TestGridTuples:
    """One ``struct.iter_unpack`` over the whole table equals reading each row, and never over-reads."""

    def test_tuples_match_per_row_reads(self) -> None:
        data = bytes([1, 2, 0, 3, 0, 0, 0, 9, 8, 0, 7, 0, 0, 0])  # two rows of (a, b, c)
        grid = Build.grid(2, data)
        tuples = grid.tuples()
        assert grid.names == ("a", "b", "c")
        assert len(tuples) == 2
        for i, values in enumerate(tuples):
            row = grid.row(i)
            assert row is not None
            assert {name: values[k] for k, name in enumerate(grid.names)} == row
        assert tuples[0] == (1, 2, 3)  # a=1, b=0x0002, c=0x00000003 (little-endian)

    def test_tuples_clamped_to_what_fits(self) -> None:
        data = bytes(range(7)) + bytes(range(7)) + b"\x00\x00\x00"  # two whole rows + 3 spare bytes
        grid = Build.grid(2, data, count=5)  # the header claims five rows; only two are present
        assert len(grid.tuples()) == 2

    def test_tuples_match_rows_for_an_index_width_table(self) -> None:
        # a metadata-table shape: heap/table indices whose width comes from the sizes map (like methoddef)
        row = Layout((("name", Index("str")), ("sig", Index("blob")), ("flags", U16)))
        sizes = {"str": 2, "blob": 4}  # stride 8
        data = bytes([5, 0, 9, 0, 0, 0, 0x30, 0, 6, 0, 10, 0, 0, 0, 0x10, 0])  # two rows
        grid = Grid(Cursor(data), 0, row, 2, sizes)
        tuples = grid.tuples()
        assert grid.names == ("name", "sig", "flags")
        assert tuples == [(5, 9, 0x30), (6, 10, 0x10)]
        for i, values in enumerate(tuples):
            assert {name: values[k] for k, name in enumerate(grid.names)} == grid.row(i)
        clamped = Grid(Cursor(data), 0, row, 5, sizes)  # claims five rows; only two fit
        assert len(clamped.tuples()) == 2


class TestRow:
    """A record view over one tuple: fields resolve on access through a shared spec and the costly ones cache."""

    def test_fields_resolve_by_kind_and_name_caches(self) -> None:
        calls: list[tuple[int, ...]] = []

        def resolve_name(values: tuple[int, ...]) -> bytes | None:
            calls.append(values)
            return {5: b"printf"}.get(values[1])

        spec = {"value": 0, "bind": lambda values: values[2] >> 4, "name": resolve_name}
        row = Row((10, 5, 0x30), spec)
        assert row.get("value") == 10  # an index field
        assert row.get("bind") == 3  # a derived field (0x30 >> 4)
        assert row.get("name") == b"printf"  # a string-table name
        assert row.get("name") == b"printf"
        assert len(calls) == 1  # resolved once, then served from the cache

    def test_absent_field_is_none(self) -> None:
        row = Row((1,), {"value": 0})
        assert row.get("missing") is None
        assert "missing" not in row
        with pytest.raises(KeyError):
            _ = row["missing"]

    def test_iterates_present_declared_names_only(self) -> None:
        spec = {
            "value": 0,
            "name": lambda _values: None,
        }  # an unresolved name is absent, as the reader omits it
        row = Row((7,), spec)
        assert list(row) == ["value"]
        assert dict(row) == {"value": 7}
        assert "name" not in row
        assert "value" in row


class TestLazySeqOverRows:
    """A sequence of rows read by index builds a Row only when its slot is read."""

    def test_len_iter_membership_build_no_row(self) -> None:
        built: list[int] = []

        def decode(index: int) -> Row:
            built.append(index)
            return Row((index,), {"value": 0})

        seq = LazySeq(range(4), decode)
        assert len(seq) == 4
        assert list(seq) == [0, 1, 2, 3]  # iteration yields the keys
        assert 2 in seq
        assert 9 not in seq
        assert built == []  # nothing decoded by length, iteration or membership
        assert seq[2].get("value") == 2  # the slot's Row is built on first access
        assert built == [2]


class TestLazyRecord:
    """A record whose costly fields are produced together on the first read of any of them."""

    def test_cheap_fields_never_trigger_the_build(self) -> None:
        built: list[int] = []

        def build() -> dict[str, object]:
            built.append(1)
            return {"number_of_methods": 3, "methods": {0: "m"}}

        rec = LazyRecord({"name": b"C", "sealed": 1}, ("number_of_methods", "methods"), build)
        assert rec["name"] == b"C"
        assert rec.get("sealed") == 1
        assert set(rec) == {"name", "sealed", "number_of_methods", "methods"}  # all keys, no build
        assert "methods" in rec and "absent" not in rec
        assert len(rec) == 4
        assert built == []  # reading a cheap field, membership and iteration never build

    def test_a_deferred_field_builds_once(self) -> None:
        built: list[int] = []

        def build() -> dict[str, object]:
            built.append(1)
            return {"number_of_methods": 3, "methods": {0: "m"}}

        rec = LazyRecord({"name": b"C"}, ("number_of_methods", "methods"), build)
        assert rec["number_of_methods"] == 3
        assert rec["methods"] == {0: "m"}  # second deferred read: still one build
        assert built == [1]


class TestImageMapStrict:
    """ImageMap's two RVA rules on a truncated section table: modules.pe (strict) fails the whole mapping,
    modules.dotnet (the default) maps an address below the sections straight through."""

    @staticmethod
    def truncated_pe() -> bytes:
        """A PE32 whose COFF header declares one section but whose file ends after the optional header, so
        the section header does not fit."""
        nt = 0x40
        buf = bytearray(0x40)
        buf[0:2] = b"MZ"
        buf[0x3C:0x40] = nt.to_bytes(4, "little")
        buf += b"PE\x00\x00"
        buf += struct.pack(
            "<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0
        )  # machine, nsec=1, ..., opt_size=0xE0
        opt = bytearray(0xE0)
        opt[0:2] = (0x10B).to_bytes(2, "little")  # PE32 magic
        opt[32:36] = (0x1000).to_bytes(4, "little")  # section_alignment
        opt[36:40] = (0x200).to_bytes(4, "little")  # file_alignment
        opt[92:96] = (0).to_bytes(4, "little")  # number_of_rva_and_sizes
        buf += opt  # ends here: the one section header at opt+0xE0 is absent
        return bytes(buf)

    def test_strict_fails_a_non_fitting_section_header(self) -> None:
        cur = Cursor(TestImageMapStrict.truncated_pe())
        strict = ImageMap.accept(cur, strict=True)
        tolerant = ImageMap.accept(cur)
        assert strict is not None
        assert tolerant is not None
        assert strict.to_offset(0x10) == -1  # pe: the truncated section table fails every address
        assert (
            tolerant.to_offset(0x10) == 0x10
        )  # dotnet: below the (empty) sections, straight through


class TestCursorWideInteger:
    """``Cursor.uint`` reads an integer of any width -- an ASN.1 bignum such as an RSA modulus is just a
    512-byte big-endian read -- with the cursor's own byte order or an explicit one, unsigned or two's
    complement, and reports ABSENT past the end. modules.signature reads every ASN.1 INTEGER through this."""

    def test_reads_a_4096_bit_modulus(self) -> None:
        modulus = (1 << 4095) | (7**500) | 1  # a 4096-bit odd number
        raw = modulus.to_bytes(512, "big")
        assert Cursor(raw).uint(0, 512, "big") == modulus

    def test_leading_zero_byte_is_kept_unsigned(self) -> None:
        raw = bytes([0x00, 0x80, 0x01])
        assert Cursor(raw).uint(0, 3, "big") == 0x8001  # the padding zero does not change the value

    def test_signed_reads_twos_complement(self) -> None:
        assert Cursor(bytes([0xFF])).uint(0, 1, "big", signed=True) == -1
        assert Cursor(bytes([0x80, 0x00])).uint(0, 2, "big", signed=True) == -32768
        assert (
            Cursor(bytes([0x00, 0x80])).uint(0, 2, "big", signed=True) == 128
        )  # leading zero -> positive

    def test_absent_past_the_end(self) -> None:
        assert Cursor(bytes(4)).uint(0, 8, "big") is ABSENT
        assert Cursor(bytes(4)).uint(2, 4, "big") is ABSENT
