"""An archive is opened when its bytes are one, whatever it is called (items 36 and 30): a zip named
notes.txt or behind a PNG, and a lone compressed file (`install.py.gz`, `dump.sql.gz`) read as the
file it holds. A lone stream cut short is read to its end and complete with a note; a cut tar still
blocks; bytes that only start like a compressed stream are not opened and leave no gap."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.policy import PolicyGate
from cordon_scanner.foundation.config.policy import Policy
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.errors import ExitCode
from cordon_scanner.sources.signatures import ArchiveSignatures, CompressedHeader
from support import ROOT

DECODE = "b64" + "decode"  # spelled apart so this file is not itself a decode-then-run
PLANT = (
    "import base64, subprocess\nBLOB = 'ZWNobyBoZWxsbw=='\n"
    f"subprocess.run(base64.{DECODE}(BLOB).decode(), shell=True)\n"
).encode()
RULE = "SUSPECT.DECODE_EXEC.001"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 17


class TypedKit:
    @staticmethod
    def zipped(entries: dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        return buf.getvalue()

    @staticmethod
    def tarred(entries: dict[str, bytes], mode: str = "w") -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode=mode) as tar:
            for name, data in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    @staticmethod
    def sdist(tmp_path, members: dict[str, bytes]):
        path = tmp_path / "pkg-1.0.tar.gz"
        path.write_bytes(TypedKit.tarred({f"pkg-1.0/{n}": d for n, d in members.items()}, "w:gz"))
        config = Config.default().with_overrides(use_cache=False, offline=True)
        result = Scanner(config).scan(path)
        return result, PolicyGate.evaluate(result, Policy.default())

    @staticmethod
    def tree(tmp_path, members: dict[str, bytes]):
        root = tmp_path / "repo"
        for name, data in members.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(data)
        config = Config.default().with_overrides(use_cache=False, offline=True)
        return Scanner(config).scan(root)

    @staticmethod
    def planted_at(result, suffix: str) -> bool:
        return any(f.rule_id == RULE and f.location.path.endswith(suffix) for f in result.findings)


class TestTheHeaderIsReadWhole:
    """The magic alone is two to six bytes any file can start with: the full header decides."""

    @pytest.mark.parametrize(
        ("data", "kind"),
        [
            # mtime=0: a gzip header holds its write time, and a test id built from it differs
            # between xdist workers that collect a second apart
            (gzip.compress(PLANT, mtime=0), "gzip"),
            (bz2.compress(PLANT), "bzip2"),
            (bz2.compress(b""), "bzip2"),
            (lzma.compress(PLANT), "xz"),
        ],
        ids=["gzip", "bzip2", "bzip2-empty", "xz"],
    )
    def test_a_real_stream_is_its_format(self, data: bytes, kind: str) -> None:
        assert CompressedHeader.format_of(data) == kind

    @pytest.mark.parametrize(
        "data",
        [
            b"\x1f\x8b\x00\x00" + b"\x00" * 12,  # not deflate
            b"\x1f\x8b\x08\xe0" + b"\x00" * 12,  # reserved flag bits set
            b"BZh0" + b"\x31\x41\x59\x26\x53\x59",  # no block size
            b"BZh9 is how this line starts",
            b"\xfd7zXZ\x00\x00\x01" + b"\x00\x00\x00\x00",  # stream flags' CRC wrong
            b"\x28\xb5\x2f\xfd\x08",  # zstd descriptor's reserved bit
        ],
    )
    def test_a_magic_with_a_broken_header_is_none(self, data: bytes) -> None:
        assert CompressedHeader.format_of(data) is None

    def test_a_tar_header_is_its_checksum(self) -> None:
        block = TypedKit.tarred({"a.txt": b"x"})[:512]
        assert ArchiveSignatures.tar_header(block)
        assert not ArchiveSignatures.tar_header(block[:148] + b"0000001\x00" + block[156:])
        assert not ArchiveSignatures.tar_header(b"\x00" * 1024)

    def test_what_opens(self) -> None:
        zipped = TypedKit.zipped({"run.py": PLANT})
        assert ArchiveSignatures.opens(zipped)
        assert ArchiveSignatures.opens(PNG + zipped)  # the directory at the end
        assert ArchiveSignatures.opens(TypedKit.tarred({"a": b"x"}))
        assert not ArchiveSignatures.opens(PNG)
        assert not ArchiveSignatures.opens(b"PK is how this line starts\n")

    def test_the_inner_name_is_the_stream_s_less_its_suffix(self) -> None:
        assert ArchiveSignatures.inner_name("p.tgz!pkg/lib/install.js.gz") == "install.js"
        assert ArchiveSignatures.inner_name("dump.SQL.XZ") == "dump.SQL"
        assert ArchiveSignatures.inner_name("pkg/blob") == "blob"


class TestAnArchiveUnderAnotherName:
    @pytest.mark.parametrize("name", ["docs/notes.txt", "assets/logo.png"])
    def test_a_member_is_opened_by_its_bytes(self, tmp_path, name: str) -> None:
        zipped = TypedKit.zipped({"run.py": PLANT})
        data = PNG + zipped if name.endswith(".png") else zipped
        result, _ = TypedKit.sdist(tmp_path, {name: data})
        assert TypedKit.planted_at(result, f"{name}!run.py")

    def test_in_a_directory_too(self, tmp_path) -> None:
        result = TypedKit.tree(tmp_path, {"docs/notes.txt": TypedKit.zipped({"run.py": PLANT})})
        assert TypedKit.planted_at(result, "docs/notes.txt!run.py")

    def test_an_invalid_gzip_header_is_not_opened_and_leaves_no_gap(self, tmp_path) -> None:
        data = b"\x1f\x8b\x00\x00" + b"\x00" * 6 + b"some plain bytes after a look-alike start\n"
        result, verdict = TypedKit.sdist(tmp_path, {"data.bin": data})
        assert result.content_complete, result.content_gaps
        assert verdict.exit_code is ExitCode.CLEAN


class TestALoneCompressedFile:
    @pytest.mark.parametrize("pack", [gzip.compress, bz2.compress, lzma.compress])
    def test_it_is_read_as_the_file_it_holds(self, tmp_path, pack) -> None:
        result, _ = TypedKit.sdist(tmp_path, {"install.py.gz": pack(PLANT)})
        assert TypedKit.planted_at(result, "install.py.gz!install.py")

    def test_a_sql_dump_is_read_and_complete(self, tmp_path) -> None:
        """scr-database 1.0.0's scr-database.sql.gz, the screen's one real gap: an SQL dump."""
        dump = b"".join(b"INSERT INTO t VALUES (%d, 'row');\n" % i for i in range(2000))
        result, verdict = TypedKit.sdist(tmp_path, {"scr-database.sql.gz": gzip.compress(dump)})
        # read decompressed: before, its compressed bytes were scanned as opaque bytes, complete
        assert result.stats.bytes_scanned >= len(dump)
        assert result.content_complete, result.content_gaps
        assert verdict.exit_code is ExitCode.CLEAN

    def test_in_a_directory_too(self, tmp_path) -> None:
        result = TypedKit.tree(tmp_path, {"lib/install.py.gz": gzip.compress(PLANT)})
        assert TypedKit.planted_at(result, "lib/install.py.gz!install.py")


class TestACutStream:
    def test_a_cut_lone_stream_is_read_to_its_end_and_complete_with_a_note(self, tmp_path) -> None:
        filler = b"".join(b"# line %d of an ordinary comment block\n" % i for i in range(400))
        whole = gzip.compress(PLANT + filler)
        result, _ = TypedKit.sdist(tmp_path, {"install.py.gz": whole[: len(whole) - 40]})
        assert TypedKit.planted_at(result, "install.py.gz!install.py")
        rules = {f.rule_id for f in result.findings}
        assert "OPERATIONAL.ARCHIVE.COMPRESSED_TRUNCATED" in rules
        assert result.content_complete, result.content_gaps

    def test_a_stream_cut_before_its_first_byte_is_an_error_not_a_file(self) -> None:
        """A gzip header and nothing it can inflate (tests/integration/test_hostile.py's garbage case):
        no byte was read, so it is an archive that would not open, never an empty member read whole."""
        from cordon_scanner.foundation.errors import ArchiveError
        from cordon_scanner.sources.archive import ArchiveReader

        with pytest.raises(ArchiveError):
            ArchiveReader.extract(b"\x1f\x8b\x08" + b"\x00" * 10, path="junk.gz")

    def test_a_cut_tar_inside_still_blocks(self, tmp_path) -> None:
        big = b"".join(b"%08d some member text that is long enough\n" % i for i in range(4000))
        whole = TypedKit.tarred({"a.txt": big, "run.py": PLANT}, "w:gz")
        result, verdict = TypedKit.sdist(tmp_path, {"vendor.tgz": whole[: len(whole) // 2]})
        assert not result.content_complete
        assert verdict.exit_code is ExitCode.INCOMPLETE

    def test_bytes_after_the_end_marker_block(self, tmp_path) -> None:
        """What follows a stream's end was never decompressed: appended there, a payload must not
        pass as read."""
        data = gzip.compress(b"# an ordinary file\n") + b"appended after the end marker\n" * 20
        result, verdict = TypedKit.sdist(tmp_path, {"install.py.gz": data})
        assert not result.content_complete
        assert verdict.exit_code is ExitCode.INCOMPLETE

    def test_streams_back_to_back_are_read_as_one(self, tmp_path) -> None:
        data = gzip.compress(b"# a first part\n") + gzip.compress(PLANT) + b"\x00" * 16
        result, _ = TypedKit.sdist(tmp_path, {"install.py.gz": data})
        assert TypedKit.planted_at(result, "install.py.gz!install.py")
        assert result.content_complete, result.content_gaps

    def test_bytes_after_the_end_marker_block_in_a_directory_too(self, tmp_path) -> None:
        data = gzip.compress(b"# an ordinary file\n") + b"appended after the end marker\n" * 20
        result = TypedKit.tree(tmp_path, {"lib/install.py.gz": data})
        assert not result.content_complete


class TestOpeningByBytesTakesNothingAway:
    def test_a_member_opened_by_its_bytes_is_still_itself(self) -> None:
        """A gem's metadata.gz is read by name by the gem's readers: opened for what it holds, the
        member is still handed on as itself."""
        from cordon_scanner.sources.archive import ArchiveReader

        data = gzip.compress(b"--- !ruby/object:Gem::Specification\nname: demo\n")
        outer = TypedKit.tarred({"metadata.gz": data, "notes.txt": TypedKit.zipped({"a": b"x"})})
        names = [name for name, _ in ArchiveReader.walk_archive(outer, path="demo-0.1.0.gem")]
        assert "demo-0.1.0.gem!metadata.gz" in names
        assert "demo-0.1.0.gem!metadata.gz!metadata" in names
        assert "demo-0.1.0.gem!notes.txt" in names and "demo-0.1.0.gem!notes.txt!a" in names


class TestADocumentUnderAPrefix:
    """C-02 against the archive slice: a .docm with bytes put before it is still a zip (its end record),
    so it must still be read as the document it is, and a part is skipped as already read only when its
    container is one the document reader reads."""

    SAMPLE = ROOT / "corpus" / "malicious" / "document-macro-dropper" / "invoice.docm"
    RULE = "SUSPECT.DOCUMENT.AUTO_EXEC.001"

    @staticmethod
    def rules(path: Path) -> set[str]:
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(path)
        return {f.rule_id for f in result.findings}

    def test_a_prefixed_docm_is_still_a_document(self, tmp_path) -> None:
        from cordon_scanner.analysis.formats.documents import DocumentReader

        prefixed = b"/* \x00 */\n" + self.SAMPLE.read_bytes()
        assert DocumentReader.kind_of(prefixed, "invoice.docm") == "ooxml"
        target = tmp_path / "invoice.docm"
        target.write_bytes(prefixed)
        assert self.RULE in self.rules(target)

    def test_a_document_s_parts_under_another_name_are_read(self, tmp_path) -> None:
        with zipfile.ZipFile(io.BytesIO(self.SAMPLE.read_bytes())) as source:
            parts = {info.filename: source.read(info) for info in source.infolist()}
        target = tmp_path / "bundle.zip"
        target.write_bytes(TypedKit.zipped(parts))
        assert self.RULE in self.rules(target)

    @staticmethod
    def macro_part() -> bytes:
        """The sample's own VBA project (an OLE file whose macro runs on open)."""
        with zipfile.ZipFile(io.BytesIO(TestADocumentUnderAPrefix.SAMPLE.read_bytes())) as source:
            return source.read("word/vbaProject.bin")

    def test_an_opendocument_file_with_junk_before_it_keeps_its_macro_part(self, tmp_path) -> None:
        # OpenDocument is no document the Office reader reads: its parts are read as themselves.
        odf = TypedKit.zipped(
            {
                "mimetype": b"application/vnd.oasis.opendocument.text",
                "content.xml": b"<office:document-content/>",
                "Object 1/payload.bin": self.macro_part(),
            }
        )
        target = tmp_path / "letter.odt"
        target.write_bytes(b"/* \x00 */\n" + odf)
        assert self.RULE in self.rules(target)

    def test_a_docm_reports_its_macro_once(self, tmp_path) -> None:
        target = tmp_path / "invoice.docm"
        target.write_bytes(self.SAMPLE.read_bytes())
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            target
        )
        assert [f.location.path for f in result.findings if f.rule_id == self.RULE] == [
            "invoice.docm"
        ]
