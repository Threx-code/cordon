"""A member named as an archive that is nothing to open: 0 bytes are complete (class 8), text that
every archive reader declines is scanned as text (class 7), and anything a reader can open, even
behind a text prefix, stays an archive (item 27; outer-layer review)."""

from __future__ import annotations

import io
import tarfile
import zipfile

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.sources.archive import ArchiveReader

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
