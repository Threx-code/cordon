"""The `vba` module (modules.formats.vba) on projects built here: the `dir` stream's project records
(name, version, code page, references, modules with their stream and offset), each module's decompressed
source, a project inside an Office zip, and the files that have no macros."""

from __future__ import annotations

import struct

from cordon_scanner.analysis.formats.ole import VbaDirectory
from cordon_scanner.detect.binary.modules.formats.vba import Vba
from cordon_scanner.detect.binary.modules.values import Data
from kits.formatkit import FormatKit


class Build:
    @staticmethod
    def record(record: int, value: bytes) -> bytes:
        return struct.pack("<HI", record, len(value)) + value

    @staticmethod
    def dir_stream(modules: list[tuple[bytes, bytes, int, int]], *, codepage: int = 1252) -> bytes:
        """A project's records: `modules` are (name, stream name, offset, kind record)."""
        body = (
            Build.record(0x0001, struct.pack("<I", 1))
            + Build.record(0x0002, struct.pack("<I", 0x409))
            + Build.record(0x0014, struct.pack("<I", 0x409))
            + Build.record(0x0003, struct.pack("<H", codepage))
            + Build.record(0x0004, b"VBAProject")
            + Build.record(0x0005, b"") + struct.pack("<H", 0x0040) + struct.pack("<I", 0)
            + Build.record(0x0006, b"") + struct.pack("<H", 0x003D) + struct.pack("<I", 0)
            + Build.record(0x0007, struct.pack("<I", 0))
            + Build.record(0x0008, struct.pack("<I", 0))
            + struct.pack("<HI", 0x0009, 4) + struct.pack("<IH", 1, 7)
            + Build.record(0x000C, b"") + struct.pack("<H", 0x003C) + struct.pack("<I", 0)
            + Build.record(0x0016, b"stdole") + struct.pack("<H", 0x003E) + Build.record(0, b"")[2:][:0]
        )  # fmt: skip
        body += struct.pack("<I", 12) + "stdole".encode(
            "utf-16-le"
        )  # the unicode name after 0x003E
        body += Build.record(0x000D, b"\x00" * 10)
        body += struct.pack("<HI", 0x000F, 2) + struct.pack("<H", len(modules))
        body += Build.record(0x0013, b"\xff\xff")
        for name, stream, offset, kind in modules:
            body += Build.record(0x0019, name)
            body += Build.record(0x0047, name.decode().encode("utf-16-le"))
            body += (
                Build.record(0x001A, stream)
                + struct.pack("<H", 0x0032)
                + Build.record(0, stream.decode().encode("utf-16-le"))[2:]
            )
            body += Build.record(0x0031, struct.pack("<I", offset))
            body += struct.pack("<HI", kind, 0)
            body += struct.pack("<HI", 0x002B, 0)
        body += struct.pack("<HI", 0x0010, 0)
        return FormatKit.ovba_literal(body)

    @staticmethod
    def project(source: str, *, kind: int = 0x0021) -> bytes:
        cache = b"\xcc" * 40
        code = FormatKit.ovba_literal(
            ('Attribute VB_Name = "Module1"\r\n' + source).encode("latin-1")
        )
        return FormatKit.compound({
            "VBA/dir": Build.dir_stream([(b"Module1", b"Module1", len(cache), kind)]),
            "VBA/Module1": cache + code,
        })  # fmt: skip


SOURCE = 'Sub AutoOpen()\r\n  Shell "calc"\r\nEnd Sub\r\n'


class TestProject:
    def test_macros_modules_and_project_info(self) -> None:
        d = Vba.data(Build.project(SOURCE))
        assert d["has_macros"] is True
        assert d["modules"] == {
            0: {
                "name": b"Module1",
                "type": 1,
                "code": ('Attribute VB_Name = "Module1"\r\n' + SOURCE).encode(),
            }
        }
        assert d["project_info"] == {
            "name": b"VBAProject", "version": b"1.7", "references": {0: b"stdole"}, "module_count": 1
        }  # fmt: skip
        assert d["MODULE_TYPE_CLASS"] == 2
        assert Data.conforms(Vba.SCHEMA, d) == []

    def test_a_class_module(self) -> None:
        assert Vba.data(Build.project(SOURCE, kind=0x0022))["modules"][0]["type"] == 2

    def test_inside_an_office_zip(self) -> None:
        d = Vba.data(FormatKit.ooxml({"word/vbaProject.bin": Build.project(SOURCE)}))
        assert d["has_macros"] is True and d["modules"][0]["name"] == b"Module1"

    def test_formatkits_minimal_project(self) -> None:
        """A `dir` stream holding only the module records: still a project with macros, its name
        unknown (YARA-X refuses the whole project without the records it expects)."""
        d = Vba.data(FormatKit.vba_project(SOURCE))
        assert d["has_macros"] is True and d["modules"][0]["code"].endswith(SOURCE.encode())
        assert "name" not in d["project_info"] and d["project_info"]["module_count"] == 1


class TestNoMacros:
    def test_files_without_macros(self) -> None:
        for data in (
            b"PK\x03\x04 not a zip",
            FormatKit.ooxml({"word/document.xml": "<w/>"}),
            FormatKit.compound({"WordDocument": b"w" * 10}),
            b"plain",
        ):
            d = Vba.data(data)
            assert d["has_macros"] is False and d["modules"] == {} and d["project_info"] == {}
            assert Data.conforms(Vba.SCHEMA, d) == []

    def test_a_module_without_source_is_left_out(self) -> None:
        raw = FormatKit.compound({"VBA/dir": Build.dir_stream([(b"Gone", b"Gone", 0, 0x0021)])})
        d = Vba.data(raw)
        assert (
            d["has_macros"] is True
            and d["modules"] == {}
            and d["project_info"]["module_count"] == 1
        )


class TestRecords:
    def test_the_project_records_are_read_in_any_order(self) -> None:
        data = (
            Build.record(0x0004, b"P")
            + struct.pack("<HI", 0x0009, 4)
            + struct.pack("<IH", 2, 3)
            + Build.record(0x0003, struct.pack("<H", 1251))
        )
        project = VbaDirectory.project(data)
        assert (project.name, project.version, project.codepage, project.modules) == (
            b"P",
            (2, 3),
            1251,
            [],
        )
