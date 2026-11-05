"""An import library's members are no name-versus-content mismatch (notes/75 fix 2).

An MSVC import library is an `ar` archive whose members are all named for the DLL they import from.
Its COFF descriptor objects read "named .dll, contents not a PE" (3 benign npm units: sharp's
libvips, npcap and tree-sitter). The archive is recognised whole and by structure, never by name,
and anything outside the linker's exact layout makes it an ordinary archive. Inert inputs only:
`kits.importlibkit` builds names and fixed-size tables, with no code.
"""

from __future__ import annotations

import io
import struct
import tarfile

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.sources.import_library import ImportLibrary
from kits.importlibkit import AMD64, DEBUG, IDATA, TEXT, ImportLibKit

POLYGLOT = "SUSPECT.POLYGLOT.MISMATCH.001"


class LibKit:
    @staticmethod
    def with_member(body: bytes, dll: str = "jc.dll") -> bytes:
        """The real library, one member replaced by `body`."""
        name = dll.encode() + b"/"
        members = [(name, b) for b in ImportLibKit.descriptors(dll)]
        members[1] = (name, body)
        members += [(name, ImportLibKit.stub("jc_open", dll))]
        return ImportLibKit.archive(members)

    @staticmethod
    def polyglot(tmp_path, name: str, data: bytes) -> int:
        (tmp_path / name).write_bytes(data)
        report = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            tmp_path
        )
        return sum(f.rule_id == POLYGLOT for f in report.findings)


class TestTheWholeLibrary:
    @pytest.mark.parametrize("machine", [0x14C, AMD64])
    def test_a_library_laid_out_as_the_linker_writes_it_is_one(self, machine: int) -> None:
        assert ImportLibrary.verify(ImportLibKit.library(machine=machine), Limits())

    def test_a_dll_with_a_long_name_is_read_through_the_long_name_table(self) -> None:
        assert ImportLibrary.verify(ImportLibKit.library("a-very-long-library-name.dll"), Limits())

    def test_a_static_library_of_ordinary_objects_is_not(self) -> None:
        obj = ImportLibKit.coff(0x14C, [(".text", b"\x00" * 16, 0, TEXT)], [(".text", 1, 3)])
        assert not ImportLibrary.verify(ImportLibKit.archive([(b"a.obj/", obj)]), Limits())

    def test_stubs_alone_with_no_descriptors_are_still_one(self) -> None:
        lib = ImportLibKit.archive([(b"jc.dll/", ImportLibKit.stub("jc_open", "jc.dll"))])
        assert ImportLibrary.verify(lib, Limits())

    def test_descriptors_without_a_stub_are_not(self) -> None:
        members = [(b"jc.dll/", b) for b in ImportLibKit.descriptors("jc.dll")]
        assert not ImportLibrary.verify(ImportLibKit.archive(members), Limits())


class TestAnythingElseMakesItOrdinary:
    def test_a_stub_with_one_trailing_byte(self) -> None:
        assert not ImportLibrary.verify(
            LibKit.with_member(ImportLibKit.stub("jc_open", "jc.dll", tail=b"\x00")), Limits()
        )

    def test_a_stub_whose_size_field_disagrees(self) -> None:
        stub = bytearray(ImportLibKit.stub("jc_open", "jc.dll"))
        struct.pack_into("<I", stub, 12, len(stub))
        assert not ImportLibrary.verify(LibKit.with_member(bytes(stub)), Limits())

    def test_a_stub_named_for_another_dll(self) -> None:
        lib = ImportLibKit.archive([(b"jc.dll/", ImportLibKit.stub("jc_open", "other.dll"))])
        assert not ImportLibrary.verify(lib, Limits())

    def test_a_descriptor_with_a_code_section(self) -> None:
        body = ImportLibKit.coff(
            0x14C,
            [(".idata$3", b"\x00" * 20, 0, IDATA), (".text", b"\x00" * 16, 0, TEXT)],
            [("__NULL_IMPORT_DESCRIPTOR", 1, 2)],
        )
        assert not ImportLibrary.verify(LibKit.with_member(body), Limits())

    def test_a_descriptor_with_an_extra_symbol(self) -> None:
        body = ImportLibKit.coff(
            0x14C,
            [(".idata$3", b"\x00" * 20, 0, IDATA)],
            [("__NULL_IMPORT_DESCRIPTOR", 1, 2), ("payload_entry", 1, 2)],
        )
        assert not ImportLibrary.verify(LibKit.with_member(body), Limits())

    def test_a_descriptor_with_an_oversized_debug_section(self) -> None:
        big = struct.pack("<I", 2) + b"\x00" * 4096
        body = ImportLibKit.coff(
            0x14C,
            [(".debug$S", big, 0, DEBUG), (".idata$3", b"\x00" * 20, 0, IDATA)],
            [("@comp.id", -1, 3), ("__NULL_IMPORT_DESCRIPTOR", 2, 2)],
        )
        assert not ImportLibrary.verify(LibKit.with_member(body), Limits())

    def test_a_debug_section_without_a_codeview_signature(self) -> None:
        body = ImportLibKit.coff(
            0x14C,
            [(".debug$S", b"\x07" * 60, 0, DEBUG), (".idata$3", b"\x00" * 20, 0, IDATA)],
            [("@comp.id", -1, 3), ("__NULL_IMPORT_DESCRIPTOR", 2, 2)],
        )
        assert not ImportLibrary.verify(LibKit.with_member(body), Limits())

    def test_a_descriptor_with_bytes_after_its_string_table(self) -> None:
        body = ImportLibKit.coff(
            0x14C,
            [(".idata$3", b"\x00" * 20, 0, IDATA)],
            [("__NULL_IMPORT_DESCRIPTOR", 1, 2)],
            tail=b"\x00" * 8,
        )
        assert not ImportLibrary.verify(LibKit.with_member(body), Limits())

    def test_an_extra_special_member(self) -> None:
        lib = ImportLibKit.library()
        extra = ImportLibKit.header(b"/SYM64/", 4) + b"\x00" * 4
        at = lib.index(b"jc.dll/")
        assert not ImportLibrary.verify(lib[:at] + extra + lib[at:], Limits())

    def test_a_linker_offset_that_points_at_no_member(self) -> None:
        lib = bytearray(ImportLibKit.library())
        struct.pack_into(">I", lib, 8 + 60 + 4, 9)  # the first linker member's first offset
        assert not ImportLibrary.verify(bytes(lib), Limits())

    def test_bytes_after_the_last_member(self) -> None:
        assert not ImportLibrary.verify(ImportLibKit.library() + b"tail", Limits())

    def test_a_truncated_archive(self) -> None:
        lib = ImportLibKit.library()
        assert not ImportLibrary.verify(lib[: len(lib) - 7], Limits())

    def test_a_debian_package_is_ordinary_and_does_not_raise(self) -> None:
        deb = ImportLibKit.archive(
            [(b"debian-binary", b"2.0\n"), (b"control.tar.gz", b"\x1f\x8b" + b"\x00" * 8)],
            linkers=0,
        )
        assert ImportLibrary.verify(deb, Limits()) is False

    @pytest.mark.parametrize("size", [0, 1, 4, 19, 20, 21, 59])
    def test_a_short_member_is_ordinary_and_does_not_raise(self, size: int) -> None:
        lib = ImportLibKit.archive([(b"jc.dll/", b"\x4c\x01" + b"\x00" * max(0, size - 2))])
        assert ImportLibrary.verify(lib, Limits()) is False

    def test_more_members_than_the_entry_bound(self) -> None:
        lib = ImportLibKit.library(functions=tuple(f"f{i}" for i in range(8)))
        assert not ImportLibrary.verify(lib, Limits(max_archive_entries=4))


class TestInAScan:
    def test_a_real_shaped_import_library_raises_no_mismatch(self, tmp_path) -> None:
        assert LibKit.polyglot(tmp_path, "parser.lib", ImportLibKit.library()) == 0

    def test_the_same_library_with_a_code_section_still_does(self, tmp_path) -> None:
        body = ImportLibKit.coff(
            0x14C,
            [(".idata$3", b"\x00" * 20, 0, IDATA), (".text", b"\x00" * 16, 0, TEXT)],
            [("__NULL_IMPORT_DESCRIPTOR", 1, 2)],
        )
        assert LibKit.polyglot(tmp_path, "parser.lib", LibKit.with_member(body)) > 0

    def test_the_mark_survives_the_expander_in_a_package_scan(self, tmp_path) -> None:
        # A package archive is expanded in a worker (item 56 (c)), and its members cross as spill
        # records: the import-library mark must cross with them.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, data in (
                ("package/package.json", b'{"name": "x", "version": "1.0.0"}'),
                ("package/parser.lib", ImportLibKit.library()),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        target = tmp_path / "x-1.0.0.tgz"
        target.write_bytes(buf.getvalue())
        scanner = Scanner(Config.default().with_overrides(use_cache=False, offline=True))
        assert not [f for f in scanner.scan(target).findings if f.rule_id == POLYGLOT]

    def test_a_descriptor_object_outside_an_archive_still_does(self, tmp_path) -> None:
        descriptor = ImportLibKit.descriptors("jc.dll")[0]
        assert LibKit.polyglot(tmp_path, "jc.dll", descriptor) > 0
