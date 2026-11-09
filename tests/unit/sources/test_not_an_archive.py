"""A member named as an archive that is nothing to open: 0 bytes are complete (class 8), text that
every archive reader declines is scanned as text (class 7), and anything a reader can open, even
behind a text prefix, stays an archive (item 27; outer-layer review)."""

from __future__ import annotations

import collections
import io
import os
import pickle
import struct
import tarfile
import zipfile

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.sources.archive import ArchiveReader
from kits.formatkit import Reduces

DECODE = "b64" + "decode"
PLANT = (
    "import base64, subprocess\nBLOB = 'ZWNobyBoZWxsbw=='\n"
    f"subprocess.run(base64.{DECODE}(BLOB).decode(), shell=True)\n"
).encode()


#: basedpyright's packages/pyright-internal/src/tests/samples/zipfs/corrupt.{egg,jar,zip}: a ZIP local
#: header and text. Valid UTF-8, so it passed as "text" (cordon-47, gate rerun on e1ebc0f7).
CORRUPT_ZIP = b"PK\x03\x04\x14\x00\x00\x00\x08\x00This is a corrupt zip file"


class NotAnArchiveKit:
    @staticmethod
    def zipped(entries: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        return buf.getvalue()

    @staticmethod
    def stored_text_zip() -> bytes:
        """A stored zip of one text entry, every header field an ASCII byte, so the whole is valid
        UTF-8; with no central directory Python's zipfile refuses it, while a streaming extractor
        (unzip reading local headers, a JAR loader) opens it. Its entry is harmless text."""
        body = b"print('hello')\n"
        name = b"pkg/run.py"
        header = (
            b"PK\x03\x04"
            + b"\x14\x00"  # version needed
            + b"\x00\x00"  # flags
            + b"\x00\x00"  # stored
            + b"\x21\x21\x21\x21"  # time, date
            + b"\x41\x41\x41\x41"  # crc (not checked by a reader that refuses first)
            + bytes([len(body), 0, 0, 0]) * 2  # sizes
            + bytes([len(name), 0])
            + b"\x00\x00"
        )
        return header + name + body

    @staticmethod
    def sdist(tmp_path, name: str, data: bytes):
        path = tmp_path / "pkg-1.0.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo(f"pkg-1.0/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(path)


class AnotherFormatKit:
    @staticmethod
    def apple_double(*, version: bytes = b"\x00\x02\x00\x00", entries: int = 1) -> bytes:
        """A macOS AppleDouble resource fork (`__MACOSX/._name`): magic, version, 16-byte filler,
        an entry count, 12-byte entry descriptors and the entries they point at. Its entries are
        binary, as a real fork's are, so it is never taken for text."""
        body = b"\x00\xff\xfe\x80" * 8
        start = 26 + 12 * entries
        table = b"".join(struct.pack(">III", 9, start + 32 * i, 32) for i in range(entries))
        return (
            b"\x00\x05\x16\x07"
            + version
            + b"Mac OS X        "
            + struct.pack(">H", entries)
            + table
            + body * entries
        )

    @staticmethod
    def rules(result) -> set[str]:
        return {f.rule_id for f in result.findings}

    @staticmethod
    def gapped(result) -> bool:
        return any(rule == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" for rule, _ in result.content_gaps)


class TestNamedAsAnArchiveButPositivelyAnotherFormat:
    """A member named `.tar`/`.zip` whose bytes are, by a full header, a format measured here --
    PyTorch's legacy pickle (cgcnn2's `*.pth.tar`), a macOS AppleDouble fork (bootstrapme's
    `__MACOSX/._*.zip`) -- is examined as that format, not refused unread (05-CENSUS C2, 08 7d)."""

    def test_an_appledouble_fork_named_as_a_zip_is_read_as_one(self, tmp_path) -> None:
        result = NotAnArchiveKit.sdist(
            tmp_path, "__MACOSX/._site.zip", AnotherFormatKit.apple_double()
        )
        assert not AnotherFormatKit.gapped(result), result.content_gaps
        assert "OPERATIONAL.ARCHIVE.NOT_AN_ARCHIVE" in AnotherFormatKit.rules(result)

    def test_a_pickle_named_as_a_tar_is_read_as_a_pickle(self, tmp_path) -> None:
        data = pickle.dumps(collections.OrderedDict(weights=[1.0, 2.0]), protocol=2)
        result = NotAnArchiveKit.sdist(tmp_path, "models/band-gap.pth.tar", data)
        assert not AnotherFormatKit.gapped(result), result.content_gaps

    def test_a_pickle_named_as_a_tar_that_runs_a_command_is_caught(self, tmp_path) -> None:
        """The one that matters: read as what it is, the pickle meets the pickle detector, which a
        `.tar` name kept it from before."""
        data = pickle.dumps(Reduces(os.system, "true"), protocol=2)
        result = NotAnArchiveKit.sdist(tmp_path, "models/band-gap.pth.tar", data)
        assert "MALWARE.MODEL.PICKLE_EXEC.001" in AnotherFormatKit.rules(result)

    @pytest.mark.parametrize(
        ("name", "data"),
        [
            pytest.param(
                "__MACOSX/._a.zip",
                AnotherFormatKit.apple_double(version=b"\x00\x01\x00\x00"),
                id="AppleDouble of another version",
            ),
            pytest.param(
                "__MACOSX/._a.zip",
                AnotherFormatKit.apple_double()[:20] + b"\xff",
                id="a short fork",
            ),
            pytest.param(
                "__MACOSX/._a.zip",
                AnotherFormatKit.apple_double(entries=40)[:200],
                id="entries past the end",
            ),
            pytest.param(
                "m.pth.tar", b"\x80\x02\xff" + bytes(range(200)), id="0x80 0x02 then no opcode"
            ),
        ],
    )
    def test_anything_short_of_the_full_format_is_still_refused(self, tmp_path, name, data) -> None:
        result = NotAnArchiveKit.sdist(tmp_path, name, data)
        assert AnotherFormatKit.gapped(result), result.content_gaps


class TestWhatIsNoArchive:
    def test_empty_and_text(self) -> None:
        assert ArchiveReader.not_an_archive(b"") == "empty"
        assert (
            ArchiveReader.not_an_archive(b"FROM continuumio/miniconda3\nRUN conda install x\n")
            == "text"
        )

    def test_anything_a_reader_opens_is_an_archive(self) -> None:
        real = NotAnArchiveKit.zipped({"info/index.json": b"{}"})
        assert ArchiveReader.not_an_archive(real) is None
        assert ArchiveReader.not_an_archive(b"a text line\n" + real) is None  # found from the tail
        assert ArchiveReader.not_an_archive(b"\x1f\x8b" + b"x" * 40) is None
        assert ArchiveReader.not_an_archive(bytes(range(256))) is None  # neither text nor archive


class TestASignatureIsAnArchive:
    """Text that carries an archive's signature is a corrupt archive, never text (class 7)."""

    def test_the_corrupt_zips_are_archives(self) -> None:
        assert ArchiveReader.not_an_archive(CORRUPT_ZIP) is None

    def test_a_utf8_stored_zip_python_refuses_is_an_archive(self) -> None:
        data = NotAnArchiveKit.stored_text_zip()
        data.decode("utf-8")  # the shape: it decodes
        assert not zipfile.is_zipfile(io.BytesIO(data))  # and Python's reader refuses it
        assert ArchiveReader.not_an_archive(data) is None

    def test_a_directory_record_anywhere_is_an_archive(self) -> None:
        """A directory that points at a local header, anywhere (item 76 keeps it): the archive."""
        data = b"some text\n" + NotAnArchiveKit.stored_text_zip()
        assert ArchiveReader.not_an_archive(data) is None

    def test_an_end_record_alone_in_text_is_text(self) -> None:
        """An end record with no local header anywhere holds no entry any extractor reaches (item
        76): a zip library's source carries the signature as a constant (`jszip.min.js`)."""
        assert ArchiveReader.not_an_archive(b"some text\nPK\x05\x06 and more text\n") == "text"

    def test_plain_text_named_as_a_zip_stays_text(self) -> None:
        """basedpyright's bad.{egg,jar,zip}."""
        assert ArchiveReader.not_an_archive(b"This file isn't a zip.") == "text"

    def test_the_corrupt_zip_blocks_in_a_scan(self, tmp_path) -> None:
        for data in (CORRUPT_ZIP, NotAnArchiveKit.stored_text_zip()):
            result = NotAnArchiveKit.sdist(tmp_path, "corrupt.jar", data)
            rules = {f.rule_id for f in result.findings}
            assert "OPERATIONAL.ARCHIVE.NOT_AN_ARCHIVE" not in rules
            assert any(
                rule == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" for rule, _ in result.content_gaps
            )
            assert PolicyGate.evaluate(result, Policy.default()).exit_code is ExitCode.INCOMPLETE


class TestInAScan:
    def test_text_named_as_an_archive_is_scanned_and_complete(self, tmp_path) -> None:
        result = NotAnArchiveKit.sdist(tmp_path, "Dockerfile.conda", b"FROM miniconda3\nRUN x\n")
        rules = {f.rule_id for f in result.findings}
        assert "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" not in rules
        assert "OPERATIONAL.ARCHIVE.NOT_AN_ARCHIVE" in rules
        assert result.content_complete

    def test_an_empty_member_named_as_an_archive_is_complete(self, tmp_path) -> None:
        result = NotAnArchiveKit.sdist(tmp_path, "rostest.docker.tar", b"")
        assert "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" not in {f.rule_id for f in result.findings}
        assert result.content_complete

    def test_in_a_directory_s_archive_too(self, tmp_path) -> None:
        """A directory scan expands its archives itself (units.expand_members): the same reasons
        that leave nothing unread (`ArchiveMembers.NOTHING_UNREAD`)."""
        tree = tmp_path / "repo"
        tree.mkdir()
        with tarfile.open(tree / "vendor.tar.gz", "w:gz") as tar:
            for name, data in (("Dockerfile.conda", b"FROM miniconda3\nRUN x\n"), ("x.tar", b"")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(tree)
        assert "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" not in {f.rule_id for f in result.findings}
        assert result.content_complete

    def test_a_text_prefix_does_not_hide_a_zip(self, tmp_path) -> None:
        inner = NotAnArchiveKit.zipped({"info/run.py": PLANT})
        result = NotAnArchiveKit.sdist(tmp_path, "evil.conda", b"a text line\n" + inner)
        paths = {f.location.path for f in result.findings}
        rules = {f.rule_id for f in result.findings}
        # read as the zip it is (its member named), or refused: never passed as text
        assert any("info/run.py" in p for p in paths) or (
            "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" in rules and not result.content_complete
        )
