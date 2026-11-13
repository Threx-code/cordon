"""An archive in a format no reader here opens is a blocking content gap at its path, whatever it is
called (item 53): rar, 7z, cab, ar/deb, cpio, xar/pkg, iso, lzip and lzma all passed as complete on
65f53833, as a package member and as a directory file, named or as .dat. Each blob here is that format's
header and inert filler text; nothing in it is an archive's content."""

from __future__ import annotations

import io
import lzma
import struct
import tarfile
import zipfile
from typing import ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.sources.signatures import CompressedHeader, UnopenedFormats

GAP = "OPERATIONAL.ARCHIVE.UNSUPPORTED_FORMAT"
FILL = b"inert filler bytes for a format test\n" * 40


class FormatKit:
    @staticmethod
    def iso() -> bytes:
        block = bytearray(0x8800)
        block[0x8000:0x8006] = b"\x01CD001"
        return bytes(block) + FILL

    @staticmethod
    def ar(members: list[tuple[bytes, bytes]]) -> bytes:
        """An ar archive: each member behind its 60-byte header, padded to an even offset."""
        out = b"!<arch>\n"
        for name, body in members:
            out += (
                name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8)
            )
            out += (
                str(len(body)).encode().ljust(10)
                + b"`\n"
                + body
                + (b"\n" if len(body) % 2 else b"")
            )
        return out

    #: format -> (bytes, its usual name)
    BLOBS: ClassVar[dict[str, tuple[bytes, str]]] = {
        "rar": (b"Rar!\x1a\x07\x00" + FILL, "payload.rar"),
        "rar5": (b"Rar!\x1a\x07\x01\x00" + FILL, "payload.rar"),
        "7z": (b"7z\xbc\xaf\x27\x1c\x00\x04" + FILL, "payload.7z"),
        "cab": (b"MSCF\x00\x00\x00\x00" + struct.pack("<I", 2000) + FILL, "payload.cab"),
        "cpio": (b"070701" + b"0" * 104 + FILL, "payload.cpio"),
        "xar": (b"xar!" + struct.pack(">HH", 28, 1) + b"\x00" * 20 + FILL, "payload.pkg"),
        "lzip": (b"LZIP\x01\x0c" + FILL, "payload.lz"),
    }

    @classmethod
    def blobs(cls) -> dict[str, tuple[bytes, str]]:
        return {**cls.BLOBS, "iso": (cls.iso(), "payload.iso")}

    @staticmethod
    def package(tmp_path, members: dict[str, bytes]):
        target = tmp_path / "probe-1.0.0.tgz"
        with tarfile.open(target, "w:gz") as tar:
            for name, data in {
                "package/package.json": b'{"name":"probe","version":"1.0.0"}',
                **members,
            }.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return FormatKit.scan(target)

    @staticmethod
    def tree(tmp_path, members: dict[str, bytes]):
        root = tmp_path / "tree"
        for name, data in members.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(data)
        return FormatKit.scan(root)

    @staticmethod
    def scan(target):
        return Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(target)

    @staticmethod
    def gapped(result, suffix: str) -> bool:
        return any(rule == GAP and path.endswith(suffix) for rule, path in result.content_gaps)


FORMATS = sorted(FormatKit.blobs())


class TestEachFormatIsKnown:
    @pytest.mark.parametrize("fmt", FORMATS)
    def test_by_its_header(self, fmt: str) -> None:
        data, _ = FormatKit.blobs()[fmt]
        assert UnopenedFormats.format_of(data) == fmt.rstrip("5")

    @pytest.mark.parametrize(
        "data",
        [
            b"Rar! is how this line of text starts\n",
            b"7z is a format; this is a sentence about it\n",
            b"MSCF is an acronym in this text\n",
            b"LZIP is a name in this sentence\n",
        ],
        ids=["rar", "7z", "cab", "lzip"],
    )
    def test_a_near_miss_is_not_an_archive(self, data: bytes) -> None:
        assert UnopenedFormats.format_of(data) is None


class TestItIsAGap:
    @pytest.mark.parametrize("fmt", FORMATS)
    @pytest.mark.parametrize("named", [True, False], ids=["named", "as-dat"])
    def test_as_a_package_member(self, tmp_path, fmt: str, named: bool) -> None:
        data, name = FormatKit.blobs()[fmt]
        member = f"package/vendor/{name if named else 'payload.dat'}"
        result = FormatKit.package(tmp_path, {member: data})
        assert not result.content_complete
        assert FormatKit.gapped(result, member)

    @pytest.mark.parametrize("fmt", FORMATS)
    def test_as_a_file_in_a_directory(self, tmp_path, fmt: str) -> None:
        data, name = FormatKit.blobs()[fmt]
        result = FormatKit.tree(tmp_path, {f"vendor/{name}": data, "README": b"a project\n"})
        assert not result.content_complete
        assert FormatKit.gapped(result, f"vendor/{name}")

    def test_under_an_archive_s_name(self, tmp_path) -> None:
        """marked-cs 1.5.0's shape: rar bytes at lib/main.tar.gz."""
        result = FormatKit.package(tmp_path, {"package/lib/main.tar.gz": FormatKit.BLOBS["rar"][0]})
        assert FormatKit.gapped(result, "package/lib/main.tar.gz")

    def test_nested_inside_a_zip(self, tmp_path) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("inner/payload.7z", FormatKit.BLOBS["7z"][0])
        result = FormatKit.package(tmp_path, {"package/bundle.zip": buffer.getvalue()})
        assert FormatKit.gapped(result, "package/bundle.zip!inner/payload.7z")

    def test_text_that_starts_like_one_is_no_gap(self, tmp_path) -> None:
        result = FormatKit.package(
            tmp_path, {"package/NOTES.txt": b"Rar! is how this note starts\n"}
        )
        assert result.content_complete, result.content_gaps


class TestLzmaIsReadNotGapped:
    """The stdlib decodes lzma-alone, so it is a compressed layer like xz (modelling team's review)."""

    DECODE = "b64" + "decode"  # spelled apart so this file is not itself a decode-then-run
    PLANT = (
        "import base64, subprocess\nBLOB = 'ZWNobyBoZWxsbw=='\n"
        f"subprocess.run(base64.{DECODE}(BLOB).decode(), shell=True)\n"
    ).encode()

    def test_a_real_lzma_member_is_expanded_and_read(self, tmp_path) -> None:
        data = lzma.compress(self.PLANT, format=lzma.FORMAT_ALONE)
        result = FormatKit.package(tmp_path, {"package/install.py.lzma": data})
        assert any(
            f.rule_id == "SUSPECT.DECODE_EXEC.001"
            and f.location.path.endswith("install.py.lzma!install.py")
            for f in result.findings
        )

    @pytest.mark.parametrize(
        "data",
        [
            # CASA's table.f0i: a properties byte, a 2^28 dictionary, size 0, three bytes (spotless,
            # lsmtool; 05-CENSUS C2, 08 7d).
            pytest.param(
                b"\x01" + struct.pack("<I", 1 << 28) + struct.pack("<Q", 0) + b"\x00\x00\x00",
                id="a 16-byte table index",
            ),
            # CoreML's weight.bin: the same header shape, size 0, then the weights (pipersr).
            pytest.param(
                b"\x1c"
                + struct.pack("<I", 1 << 25)
                + struct.pack("<Q", 0)
                + bytes(range(256)) * 40,
                id="a weights blob",
            ),
        ],
    )
    def test_a_header_that_declares_nothing_and_has_more_bytes_is_no_stream(self, data) -> None:
        """A decoder with 0 bytes to produce succeeds at once, so "the first block decodes" proved
        nothing: the proof is that it decodes something, or ends exactly where the input ends."""
        assert CompressedHeader.format_of(data) is None

    @pytest.mark.parametrize(
        "plain", [b"", b"hello\n" * 100, b"\x00" * 100_000], ids=["empty", "text", "zeros"]
    )
    def test_a_real_lzma_stream_is_still_one(self, plain: bytes) -> None:
        assert CompressedHeader.format_of(lzma.compress(plain, format=lzma.FORMAT_ALONE)) == "lzma"

    def test_a_header_that_does_not_decode_is_no_gap(self, tmp_path) -> None:
        data = b"\x5d\x00\x00\x80\x00" + b"\xff" * 8 + FILL
        assert UnopenedFormats.format_of(data) is None
        result = FormatKit.package(tmp_path, {"package/vendor/blob.bin": data})
        assert result.content_complete, result.content_gaps


class TestNotExpandedIsTheOperatorsChoice:
    def test_an_unopenable_format_is_not_also_a_gap_with_archives_off(self, tmp_path) -> None:
        root = tmp_path / "tree"
        (root / "vendor").mkdir(parents=True)
        (root / "vendor" / "payload.dat").write_bytes(FormatKit.BLOBS["7z"][0])
        config = Config.default().with_overrides(
            use_cache=False, offline=True, expand_archives=False
        )
        result = Scanner(config).scan(root)
        assert not any(rule == GAP for rule, _ in result.content_gaps)


class TestArIsRead:
    """ar is read, not gapped: 22 of the 29 benign npm units with an unopenable-looking member ship a
    static library (the benign cost, 1 Nov), and a .deb is ar around tars the readers open."""

    PLANT = TestLzmaIsReadNotGapped.PLANT

    def test_a_static_library_is_read_and_complete(self, tmp_path) -> None:
        library = FormatKit.ar(
            [
                (b"/", b"\x00" * 8),
                (b"a.o/", b"\x7fELF" + b"\x00" * 60),
                (b"b.o/", b"\x7fELF" + b"\x00" * 61),
            ]
        )
        result = FormatKit.package(tmp_path, {"package/lib/libdemo.a": library})
        assert result.content_complete, result.content_gaps

    def test_a_deb_s_data_tar_is_reached(self, tmp_path) -> None:
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as tar:
            info = tarfile.TarInfo("./usr/lib/demo/install.py")
            info.size = len(self.PLANT)
            tar.addfile(info, io.BytesIO(self.PLANT))
        deb = FormatKit.ar([(b"debian-binary/", b"2.0\n"), (b"data.tar.gz/", data.getvalue())])
        result = FormatKit.package(tmp_path, {"package/vendor/demo.deb": deb})
        paths = sorted(
            {f.location.path for f in result.findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"}
        )
        # The scan's own account when the member is missed: an intermittent CI miss showed only `[]`.
        notes = [
            (f.rule_id, f.location.path, f.message[:160])
            for f in result.findings
            if f.rule_id.startswith("OPERATIONAL")
        ]
        assert any(p.endswith("demo.deb!data.tar.gz!usr/lib/demo/install.py") for p in paths), (
            paths,
            notes,
            result.complete,
        )

    def test_a_long_name_is_read(self, tmp_path) -> None:
        table = b"a_member_name_longer_than_sixteen.py/\n"
        archive = FormatKit.ar([(b"//", table), (b"/0", self.PLANT)])
        result = FormatKit.package(tmp_path, {"package/lib/libdemo.a": archive})
        paths = {f.location.path for f in result.findings}
        assert any(p.endswith("libdemo.a!a_member_name_longer_than_sixteen.py") for p in paths), (
            paths
        )

    def test_an_msvc_long_name_table_is_read_to_its_nul(self, tmp_path) -> None:
        # Microsoft's lib.exe ends each long name with a NUL, not GNU's "/\n": read to "/\n", a
        # static library's members were named with the NUL and the next name, and the NUL made a
        # path escape (4 benign npm units: logitech-led, wasapi-audio-capture, getkeystate,
        # v8-heap-info).
        first, second = b"x64\\Release\\stdafx.obj", b"x64\\Release\\long_member_name.py"
        table = first + b"\x00" + second + b"\x00"
        offset = str(len(first) + 1).encode()
        archive = FormatKit.ar(
            [(b"//", table), (b"/0", b"\x7fELF" + b"\x00" * 60), (b"/" + offset, self.PLANT)]
        )
        result = FormatKit.package(tmp_path, {"package/lib/demo.lib": archive})
        rules = {f.rule_id for f in result.findings}
        assert "SUSPECT.ARCHIVE.PATH_ESCAPE.001" not in rules
        paths = {f.location.path for f in result.findings if f.rule_id == "SUSPECT.DECODE_EXEC.001"}
        assert any(p.endswith("long_member_name.py") and "\x00" not in p for p in paths), paths

    def test_a_member_name_that_climbs_and_stays_inside_is_a_build_path(self, tmp_path) -> None:
        # An object file's name is the path it was built from: `a/b/../c/x.obj`. The tar and zip
        # readers resolve a `..` that stays inside the archive; an ar archive has no links, so the
        # same rule holds (reviews/pypi-98/26: 11 names in one benign wheel's import libraries).
        table = b"a/b/c/../d/x.obj/\n"
        archive = FormatKit.ar([(b"//", table), (b"/0", self.PLANT)])
        result = FormatKit.package(tmp_path, {"package/core/native.lib": archive})
        assert "SUSPECT.ARCHIVE.PATH_ESCAPE.001" not in {f.rule_id for f in result.findings}

    @pytest.mark.parametrize("name", [b"../x.py/", b"a/../../x.py/", b"/etc/x.py/"])
    def test_a_member_name_that_leaves_the_root_is_refused(self, tmp_path, name: bytes) -> None:
        archive = FormatKit.ar([(name, self.PLANT)])
        result = FormatKit.package(tmp_path, {"package/core/native.lib": archive})
        assert "SUSPECT.ARCHIVE.PATH_ESCAPE.001" in {f.rule_id for f in result.findings}

    def test_a_damaged_header_is_a_gap(self, tmp_path) -> None:
        archive = FormatKit.ar([(b"a.o/", b"\x7fELF" + b"\x00" * 60)]) + b"broken member header" * 4
        result = FormatKit.package(tmp_path, {"package/lib/libdemo.a": archive})
        assert not result.content_complete


class TestArKeepsTheBounds:
    """The modelling team's review of note 53's ar change."""

    def test_nesting_through_ar_meets_the_depth_limit(self, tmp_path) -> None:
        inner = TestArIsRead.PLANT
        for level in range(10):  # past max_archive_depth (8)
            inner = FormatKit.ar([(f"l{level}.a/".encode(), inner)])
        result = FormatKit.package(tmp_path, {"package/lib/deep.a": inner})
        assert not result.content_complete
        assert any(rule == "OPERATIONAL.ARCHIVE.MEMBER_REJECTED" for rule, _ in result.content_gaps)

    def test_a_thin_archive_is_scanned_as_the_file_it_is(self, tmp_path) -> None:
        """A thin archive holds only paths to object files elsewhere: no member to open and nothing
        unread here; it is scanned as itself, never reported as an archive that opened."""
        thin = (
            b"!<thin>\n"
            + b"/".ljust(16)
            + b"0".ljust(12)
            + b"0".ljust(6) * 2
            + b"644".ljust(8)
            + b"0".ljust(10)
            + b"`\n"
        )
        result = FormatKit.package(tmp_path, {"package/lib/libthin.a": thin})
        assert result.content_complete, result.content_gaps
        assert not any("libthin.a!" in f.location.path for f in result.findings)
