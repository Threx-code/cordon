"""The `zip` module (modules.zip): archives written here by the standard library are read back entry by
entry, through the reader and through rules, with the reference's acceptance rules (YARA-X's zip module)
and the one named difference, every entry listed with no count limit. The real-file differential against
the reference lives in the review harness."""

from __future__ import annotations

import io
import struct
import time
import zipfile

import pytest

from cordon_scanner.detect.binary.modules.builtin import Builtin
from cordon_scanner.detect.binary.modules.formats.zip import Zip
from cordon_scanner.detect.binary.modules.values import Data
from cordon_scanner.detect.binary.rule_engine.lang import Rules


class Archive:
    @staticmethod
    def of(members: dict[str, bytes], *, method: int = zipfile.ZIP_DEFLATED, **kw: object) -> bytes:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=method, **kw) as z:  # type: ignore[arg-type]
            for name, data in members.items():
                z.writestr(name, data)
        return out.getvalue()

    @staticmethod
    def paths(file: bytes) -> list[bytes]:
        entries = Zip.data(file)["entries"]
        return [entries[i]["file_path"] for i in range(len(entries))]


class TestReader:
    def test_every_entry_value(self) -> None:
        file = Archive.of({"a.txt": b"hello" * 100, "dir/b.bin": b"\x00" * 10})
        out = Zip.data(file)
        assert out["is_zip"] is True
        e = out["entries"]
        assert [e[i]["file_path"] for i in range(2)] == [b"a.txt", b"dir/b.bin"]
        assert e[0]["compression"] == Zip.COMPRESSION["DEFLATED"]
        assert e[0]["uncompressed_size"] == 500 and 0 < e[0]["compressed_size"] < 500
        assert Data.conforms(Zip.SCHEMA, {**out, "entries": {i: e[i] for i in range(len(e))}}) == []

    @pytest.mark.parametrize(
        ("method", "name"),
        [(zipfile.ZIP_STORED, "STORED"), (zipfile.ZIP_BZIP2, "BZIP2"), (zipfile.ZIP_LZMA, "LZMA")],
    )
    def test_the_compression_method_by_its_number(self, method: int, name: str) -> None:
        out = Zip.data(Archive.of({"x": b"data"}, method=method))
        assert out["entries"][0]["compression"] == Zip.COMPRESSION[name]

    def test_a_method_the_enum_does_not_name_is_unknown(self) -> None:
        file = bytearray(Archive.of({"x": b"data"}, method=zipfile.ZIP_STORED))
        central = file.index(b"PK\x01\x02")
        file[central + 10 : central + 12] = struct.pack("<H", 7)  # "tokenized", no enum value
        assert Zip.data(bytes(file))["entries"][0]["compression"] == 255

    def test_a_prefixed_archive_and_trailing_bytes_are_zips(self) -> None:
        file = Archive.of({"manifest.json": b"{}"})
        assert Archive.paths(b"Cr24" + b"\x00" * 300 + file) == [b"manifest.json"]
        assert Archive.paths(file + b"trailing junk" * 10) == [b"manifest.json"]

    def test_a_comment_up_to_the_limit(self) -> None:
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            z.writestr("c", b"1")
            z.comment = b"x" * 0xFFFF
        assert Archive.paths(out.getvalue()) == [b"c"]

    def test_zip64_sizes(self) -> None:
        out = io.BytesIO()
        with (
            zipfile.ZipFile(out, "w", allowZip64=True) as z,
            z.open("big", "w", force_zip64=True) as f,
        ):
            f.write(b"z" * 1000)
        entry = Zip.data(out.getvalue())["entries"][0]
        assert (entry["file_path"], entry["uncompressed_size"]) == (b"big", 1000)

    def test_an_empty_archive(self) -> None:
        out = Zip.data(Archive.of({}))
        assert out["is_zip"] is True and len(out["entries"]) == 0

    def test_an_empty_record_after_other_bytes_is_not_a_zip(self) -> None:
        assert Zip.data(b"prefix" + Archive.of({}))["is_zip"] is False

    def test_the_listing_stops_at_the_first_entry_that_does_not_read(self) -> None:
        file = bytearray(Archive.of({"one": b"1", "two": b"2", "three": b"3"}))
        second = file.index(b"PK\x01\x02", file.index(b"PK\x01\x02") + 4)
        file[second + 8 : second + 10] = struct.pack("<H", 1 << 6)  # strong encryption
        assert Archive.paths(bytes(file)) == [b"one"]

    @pytest.mark.parametrize(
        "file", [b"", b"PK\x05\x06", b"not a zip at all", b"PK\x03\x04" + b"\x00" * 100]
    )
    def test_anything_else_is_not_a_zip(self, file: bytes) -> None:
        out = Zip.data(file)
        assert out["is_zip"] is False
        assert out["DEFLATED"] == 8  # the constants are there for every file

    def test_invalid_utf8_names_are_replaced(self) -> None:
        file = bytearray(Archive.of({"ab": b"1"}, method=zipfile.ZIP_STORED))
        central = file.index(b"PK\x01\x02")
        file[central + 46 : central + 48] = b"a\xff"
        assert Archive.paths(bytes(file)) == ["a�".encode()]

    def test_every_entry_is_listed_with_no_count_limit(self) -> None:
        # The reference stops at 100,000 entries; nothing is hidden behind a count here.
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as z:
            for i in range(150_000):
                z.writestr(zipfile.ZipInfo(f"f{i}"), b"")
        file = out.getvalue()
        started = time.process_time()
        entries = Zip.data(file)["entries"]
        assert len(entries) == 150_000
        assert entries[149_999]["file_path"] == b"f149999"
        assert time.process_time() - started < 5


class TestRules:
    def test_the_module_is_built_in(self) -> None:
        assert "zip" in Builtin.modules()

    @pytest.mark.parametrize(
        "condition",
        [
            "zip.is_zip",
            'for any e in zip.entries : (e.file_path == "dir/b.bin")',
            "zip.entries[0].compression == zip.DEFLATED",
            "zip.entries[0].uncompressed_size == 500",
        ],
    )
    def test_a_condition_reads_each_value(self, condition: str) -> None:
        file = Archive.of({"a.txt": b"hello" * 100, "dir/b.bin": b"\x00" * 10})
        assert Rules.compile(f'import "zip" rule r {{ condition: {condition} }}').match(file)

    def test_a_file_that_is_not_a_zip(self) -> None:
        rules = Rules.compile('import "zip" rule r { condition: not zip.is_zip }')
        assert rules.match(b"MZ plain")
