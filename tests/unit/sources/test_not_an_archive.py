"""A member named as an archive that is nothing to open: 0 bytes are complete (class 8), text that
every archive reader declines is scanned as text (class 7), and anything a reader can open, even
behind a text prefix, stays an archive (item 27; outer-layer review)."""

from __future__ import annotations

import io
import tarfile
import zipfile

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.sources.archive import ArchiveReader

DECODE = "b64" + "decode"
PLANT = (
    "import base64, subprocess\nBLOB = 'ZWNobyBoZWxsbw=='\n"
    f"subprocess.run(base64.{DECODE}(BLOB).decode(), shell=True)\n"
).encode()


class NotAnArchiveKit:
    @staticmethod
    def zipped(entries: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        return buf.getvalue()

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

    def test_a_text_prefix_does_not_hide_a_zip(self, tmp_path) -> None:
        inner = NotAnArchiveKit.zipped({"info/run.py": PLANT})
        result = NotAnArchiveKit.sdist(tmp_path, "evil.conda", b"a text line\n" + inner)
        paths = {f.location.path for f in result.findings}
        rules = {f.rule_id for f in result.findings}
        # read as the zip it is (its member named), or refused: never passed as text
        assert any("info/run.py" in p for p in paths) or (
            "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" in rules and not result.content_complete
        )
