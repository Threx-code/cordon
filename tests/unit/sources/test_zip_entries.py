"""What a zip holds is what its local headers hold (item 76): bytes carrying zip signatures but no entry
any extractor finds are not an archive, and a zip whose directory will not open is read by its local
headers; bytes no header accounts for stay refused. Every fixture is built here from inert text."""

from __future__ import annotations

import io
import struct
import zipfile

import pytest

from cordon_scanner.foundation.errors import ArchiveError
from cordon_scanner.foundation.limits import DEFAULT_LIMITS
from cordon_scanner.sources.archive import ArchiveReader
from cordon_scanner.sources.archive_names import MemberNames
from cordon_scanner.sources.base import Rejection
from cordon_scanner.sources.signatures import ArchiveSignatures
from cordon_scanner.sources.zip_entries import ZipEntries, ZipRepair


class ZipKit:
    @staticmethod
    def zipped(entries: dict[str, bytes], method: int = zipfile.ZIP_DEFLATED) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", method) as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        return buf.getvalue()

    @staticmethod
    def streamed(entries: dict[str, bytes]) -> bytes:
        """A zip written to an unseekable stream: every entry behind a data descriptor (flag 3)."""

        class Unseekable(io.RawIOBase):
            def __init__(self) -> None:
                self.out = bytearray()

            def writable(self) -> bool:
                return True

            def write(self, data: bytes) -> int:  # type: ignore[override]
                self.out += data
                return len(data)

        sink = Unseekable()
        with zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries.items():
                with archive.open(name, "w") as handle:
                    handle.write(data)
        return bytes(sink.out)

    @staticmethod
    def directory_broken(data: bytes) -> bytes:
        """The zip with its end record's directory size one byte long: `zipfile` looks for the
        directory a byte early and refuses it ("Bad magic number for central directory", an XFL
        `.fla`'s error); the local headers and the directory itself are untouched."""
        end = data.rindex(b"PK\x05\x06")
        size = struct.unpack_from("<L", data, end + 12)[0]
        return data[: end + 12] + struct.pack("<L", size + 1) + data[end + 16 :]

    @staticmethod
    def library_source() -> bytes:
        """A zip library's source: every record signature as a constant, beside text."""
        return (
            b"var LOCAL = 'PK\x03\x04', CENTRAL = 'PK\x01\x02';\n"
            b"var END = 'PK\x05\x06"
            + b"\x00" * 16
            + b"\x00\x00';\nmodule.exports = {LOCAL, END};\n"
        )

    @staticmethod
    def read(data: bytes, path: str = "pkg.zip") -> tuple[dict[str, bytes], list[tuple[str, str]]]:
        result = ArchiveReader.extract(data, path=path, limits=DEFAULT_LIMITS)
        members = {m.name: bytes(m.data) for m in result.members}
        return members, [(r.name, r.reason) for r in result.rejected]


TEXT = {
    "a/readme.txt": b"plain words\n" * 40,
    "b/index.js": b"module.exports = 1;\n" * 30,
}


class TestWhatAZipHolds:
    def test_a_zip_librarys_constants_are_no_archive(self) -> None:
        source = ZipKit.library_source()
        assert not ZipEntries.present(source)
        assert not ArchiveSignatures.opens(source)
        assert MemberNames.not_an_archive(source) == "text"

    def test_a_real_zip_holds_its_entries(self) -> None:
        data = ZipKit.zipped(TEXT)
        assert ZipEntries.held(data) and ZipEntries.present(data) and ArchiveSignatures.opens(data)

    def test_a_cut_zip_still_holds_an_entry(self) -> None:
        """Its data runs past the end, yet it is a zip, refused as one, never passed as text."""
        data = ZipKit.zipped(TEXT, zipfile.ZIP_STORED)
        assert ZipEntries.held(data[: len(data) // 3])

    def test_headers_with_nonsense_fields_behind_a_directory_that_opens_are_a_zip(
        self,
    ) -> None:
        """A directory-reading extractor takes the method from the directory, so a zip whose local
        headers carry nonsense methods is still found (`listed`)."""
        data = bytearray(ZipKit.zipped(TEXT))
        at = data.find(b"PK\x03\x04")
        while at != -1:
            data[at + 8 : at + 10] = b"\xff\xff"
            at = data.find(b"PK\x03\x04", at + 1)
        assert not ZipEntries.held(bytes(data))
        assert ZipEntries.present(bytes(data))


class TestADirectoryThatWillNotOpen:
    def test_it_is_read_by_its_local_headers(self) -> None:
        broken = ZipKit.directory_broken(ZipKit.zipped(TEXT))
        with pytest.raises(zipfile.BadZipFile):
            zipfile.ZipFile(io.BytesIO(broken))
        members, rejected = ZipKit.read(broken)
        assert members == TEXT
        assert rejected == [("pkg.zip", Rejection.DIRECTORY_REBUILT)]

    def test_entries_behind_data_descriptors_are_read_too(self) -> None:
        broken = ZipKit.directory_broken(ZipKit.streamed(TEXT))
        members, rejected = ZipKit.read(broken)
        assert members == TEXT
        assert [r for _, r in rejected] == [Rejection.DIRECTORY_REBUILT]

    def test_bytes_no_header_accounts_for_stay_refused(self) -> None:
        """Garbage between the last entry and the directory may be anything: the zip stays the
        refused archive it was, a gap that blocks."""
        good = ZipKit.zipped(TEXT)
        cd = good.index(b"PK\x01\x02")
        hidden = good[:cd] + b"\x00SOMETHING ELSE" * 8 + good[cd:]
        broken = ZipKit.directory_broken(hidden)
        assert ZipRepair.rebuild(broken, DEFAULT_LIMITS) is None
        with pytest.raises(ArchiveError):
            ZipKit.read(broken)

    def test_a_cut_entry_stays_refused(self) -> None:
        good = ZipKit.zipped(TEXT, zipfile.ZIP_STORED)
        assert ZipRepair.rebuild(good[: len(good) // 3], DEFAULT_LIMITS) is None

    def test_an_apk_signing_block_before_the_directory_is_accounted_for(self) -> None:
        good = ZipKit.zipped(TEXT)
        cd = good.index(b"PK\x01\x02")
        body = b"\x00" * 24 + b"APK Sig Block 42"
        block = struct.pack("<Q", len(body)) + body
        broken = ZipKit.directory_broken(good[:cd] + block + good[cd:])
        members, _ = ZipKit.read(broken)
        assert members == TEXT

    def test_a_directory_naming_an_entry_the_walk_never_read_is_refused(self) -> None:
        """Two views: a lenient extractor may open the directory Python refused and install what it
        points at. A record pointing past the walked entries refuses the rebuild (modelling review
        of 2a006ecf, must-fix 2)."""
        good = ZipKit.zipped(TEXT)
        cd = good.index(b"PK\x01\x02")
        record = bytearray(good[cd : cd + 46 + len(b"a/readme.txt")])
        struct.pack_into("<L", record, 42, cd - 7)  # a local offset no walked entry starts at
        forged = (
            good[: good.rindex(b"PK\x05\x06")] + bytes(record) + good[good.rindex(b"PK\x05\x06") :]
        )
        broken = ZipKit.directory_broken(forged)
        assert ZipRepair.rebuild(broken, DEFAULT_LIMITS) is None

    def test_a_signing_block_holding_a_local_header_is_refused(self) -> None:
        good = ZipKit.zipped(TEXT)
        cd = good.index(b"PK\x01\x02")
        body = b"PK\x03\x04" + b"\x00" * 20 + b"APK Sig Block 42"
        block = struct.pack("<Q", len(body)) + body
        broken = ZipKit.directory_broken(good[:cd] + block + good[cd:])
        assert ZipRepair.rebuild(broken, DEFAULT_LIMITS) is None


class TestANameDifferingOnlyInItsSeparator:
    @staticmethod
    def windows_directory(data: bytes, old: bytes, new: bytes) -> bytes:
        cd = data.index(b"PK\x01\x02")
        return data[:cd] + data[cd:].replace(old, new, 1)

    def test_a_windows_writers_backslash_is_read_past(self) -> None:
        data = self.windows_directory(
            ZipKit.zipped({"FJCore/IJG.txt": b"notes\n"}), b"FJCore/", b"FJCore\\"
        )
        members, rejected = ZipKit.read(data)
        assert list(members.values()) == [b"notes\n"]
        assert not rejected

    def test_any_other_difference_stays_refused(self) -> None:
        data = self.windows_directory(
            ZipKit.zipped({"FJCore/IJG.txt": b"notes\n"}), b"FJCore/IJG", b"FJCore/XJG"
        )
        members, rejected = ZipKit.read(data)
        assert not members
        assert [r for _, r in rejected] == [Rejection.UNREADABLE]


class TestAGzipThatEndsAtItsHeader:
    def test_it_holds_nothing_and_leaves_nothing_unread(self) -> None:
        bare = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"
        members, rejected = ZipKit.read(bare, path="package.tgz.2898109829")
        assert not members
        assert [r for _, r in rejected] == [Rejection.COMPRESSED_TRUNCATED]

    def test_one_with_a_byte_past_its_header_is_still_a_stream_that_would_not_open(
        self,
    ) -> None:
        with pytest.raises(ArchiveError):
            ZipKit.read(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x00", path="x.gz")
