"""Binary metadata on files that are cut short, damaged or carry what they should not: each reads as no package, never an exception (`images/binmeta.py`)."""

from __future__ import annotations

import io
import json
import struct
import zipfile
import zlib

import pytest

from cordon_scanner.images.binmeta import GO_MAGIC, BinaryMetadata


class _Kit:
    @staticmethod
    def elf(sections: dict[bytes, bytes]) -> bytes:
        """A little-endian 64-bit ELF holding these named sections."""
        names = b"\x00"
        offsets = {}
        for name in [*sections, b".shstrtab"]:
            offsets[name] = len(names)
            names += name + b"\x00"
        body = b""
        placed = {}
        position = 64
        for name, payload in [*sections.items(), (b".shstrtab", names)]:
            placed[name] = (position + len(body), len(payload))
            body += payload
        shoff = 64 + len(body)
        headers = bytes(64)
        for name in [*sections, b".shstrtab"]:
            offset, size = placed[name]
            headers += struct.pack("<IIQQQQIIQQ", offsets[name], 1, 0, 0, offset, size, 0, 0, 1, 0)
        header = bytearray(64)
        header[:4] = b"\x7fELF"
        header[4], header[5] = 2, 1
        struct.pack_into("<Q", header, 0x28, shoff)
        count = len(sections) + 2
        struct.pack_into("<HHH", header, 0x3A, 64, count, count - 1)
        return bytes(header) + body + headers


class TestGo:
    def test_a_binary_whose_build_information_holds_no_inline_strings_is_left_alone(self) -> None:
        data = b"\x7fELF" + bytes(60) + GO_MAGIC + bytes([8, 0]) + bytes(40)
        assert BinaryMetadata.go("bin/app", data) == []

    def test_a_length_that_never_ends_is_a_truncated_varint_and_reads_as_nothing(self) -> None:
        data = b"\x7fELF" + bytes(60) + GO_MAGIC + bytes([8, 2]) + bytes(16) + b"\x80" * 40
        assert BinaryMetadata.go("bin/app", data) == []

    def test_a_varint_with_no_end_is_refused_by_name(self) -> None:
        with pytest.raises(ValueError, match="truncated varint"):
            BinaryMetadata._uvarint(b"\x80\x80", 0)


class TestRust:
    def test_a_file_that_is_not_an_elf_or_whose_headers_point_outside_it_has_no_section(
        self,
    ) -> None:
        assert BinaryMetadata._elf_section(b"MZ" + bytes(100), b".dep-v0") is None
        header = bytearray(_Kit.elf({b".dep-v0": b"x"}))
        struct.pack_into("<Q", header, 0x28, 1 << 20)
        assert BinaryMetadata._elf_section(bytes(header), b".dep-v0") is None

    def test_a_dependency_section_that_is_not_compressed_json_reads_as_nothing(self) -> None:
        assert BinaryMetadata.rust("bin/app", _Kit.elf({b".dep-v0": b"not zlib"})) == []

    def test_a_dependency_section_that_is_compressed_json_lists_its_runtime_crates(self) -> None:
        document = {
            "packages": [
                {"name": "serde", "version": "1.0.0", "source": "crates.io"},
                {"name": "dev-only", "version": "1", "kind": "build"},
                {"name": "git-dep", "version": "1", "source": "git"},
            ]
        }
        section = zlib.compress(json.dumps(document).encode())
        found = BinaryMetadata.rust("bin/app", _Kit.elf({b".dep-v0": section}))
        assert [(p.name, p.version) for p in found] == [("serde", "1.0.0")]


class TestDotnet:
    def test_a_deps_file_that_is_not_json_or_has_no_libraries_reads_as_nothing(self) -> None:
        assert BinaryMetadata.dotnet("app.deps.json", b"{nope") == []
        assert BinaryMetadata.dotnet("app.deps.json", b'{"libraries": []}') == []


class TestJars:
    def jar(self, files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        return buffer.getvalue()

    def test_a_file_that_is_not_a_zip_has_no_packages(self) -> None:
        assert BinaryMetadata.java("lib/x.jar", b"not a zip") == []

    def test_a_jar_named_by_its_file_with_no_readable_manifest_takes_its_version_from_the_name(
        self,
    ) -> None:
        found = BinaryMetadata._jar_by_name("lib/guava-33.0.0.jar", b"not a zip")
        assert [(p.name.split(":")[-1], p.version) for p in found] == [("guava", "33.0.0")]

    def test_a_jar_with_no_version_anywhere_names_nothing(self) -> None:
        assert BinaryMetadata._jar_by_name("lib/unversioned.jar", self.jar({"a.txt": b"x"})) == []

    def test_a_pom_properties_past_the_size_limit_is_not_read(self) -> None:
        big = self.jar({"META-INF/maven/g/a/pom.properties": b"x" * ((1 << 20) + 1)})
        assert [p.name for p in BinaryMetadata.java("lib/a-1.0.jar", big)] == ["a:a"]


class _Unseekable(io.RawIOBase):
    """A write-only stream that cannot seek, so a zip written to it uses data descriptors."""

    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def writable(self) -> bool:
        return True

    def write(self, data: bytes) -> int:  # type: ignore[override]
        return self.buffer.write(data)


class TestStreamedJars:
    POM = b"groupId=g\nartifactId=lib\nversion=1.0\n"

    def streamed(self, method: int = zipfile.ZIP_DEFLATED) -> bytes:
        sink = _Unseekable()
        with zipfile.ZipFile(sink, "w", compression=method) as archive:
            archive.writestr("META-INF/maven/g/lib/pom.properties", self.POM)
            archive.writestr("README.txt", b"hello")
        return sink.buffer.getvalue()

    def read(self, raw: bytes, size: int | None = None) -> list:
        from cordon_scanner.images.binmeta import StreamedJar

        return StreamedJar.read("big.jar", io.BytesIO(raw), len(raw) if size is None else size)

    def test_entries_whose_sizes_trail_them_in_a_descriptor_are_walked_and_the_pom_is_read(
        self,
    ) -> None:
        found = self.read(self.streamed())
        assert [(p.name, p.version) for p in found] == [("g:lib", "1.0")]

    def test_a_stored_entry_with_a_descriptor_stops_the_walk(self) -> None:
        assert self.read(self.streamed(zipfile.ZIP_STORED)) == []

    def test_a_stream_cut_inside_an_entry_or_its_header_ends_the_walk_without_a_package(
        self,
    ) -> None:
        raw = self.streamed()
        assert self.read(raw[: len(raw) // 4]) == []
        assert self.read(raw[:20]) == []

    def test_a_deflate_entry_that_is_not_valid_deflate_is_passed_over(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("META-INF/maven/g/lib/pom.properties", self.POM)
        raw = bytearray(buffer.getvalue())
        raw[raw.index(b"pom.properties") + len(b"pom.properties") + 2] ^= 0xFF
        assert self.read(bytes(raw)) == []

    def test_a_size_given_in_a_zip64_extra_field_is_followed(self) -> None:
        name = b"META-INF/maven/g/lib/pom.properties"
        extra = struct.pack("<HHQQ", 1, 16, len(self.POM), len(self.POM))
        header = struct.pack(
            "<HHHHHIIIHH", 45, 0, 0, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF, len(name), len(extra)
        )
        raw = b"PK\x03\x04" + header + name + extra + self.POM
        assert [(p.name, p.version) for p in self.read(raw)] == [("g:lib", "1.0")]


class TestStreamedBinaries:
    def go(self) -> bytes:
        from kits.imagekit import ImageKit

        return ImageKit.go_binary("dep\tgolang.org/x/net\tv0.17.0\th1:a=\n")

    def read(self, data: bytes, *, chunk: int, size: int | None = None, **limits: int):
        from cordon_scanner.images import binmeta

        original = binmeta.StreamedBinary.CHUNK
        binmeta.StreamedBinary.CHUNK = chunk
        try:
            return binmeta.StreamedBinary.read(
                "bin/app", io.BytesIO(data), len(data) if size is None else size, **limits
            )
        finally:
            binmeta.StreamedBinary.CHUNK = original

    def test_build_information_split_across_chunks_is_still_found_and_the_whole_file_is_hashed(
        self,
    ) -> None:
        packages, _, _ = self.read(self.go(), chunk=37)
        assert "golang.org/x/net" in {p.name for p in packages}
        assert any("binary sha256:" in fact for fact in packages[0].platform)

    def test_a_file_shorter_than_its_stated_size_is_said_not_read_to_its_end(self) -> None:
        data = self.go()
        packages, _, _ = self.read(data, chunk=64, size=len(data) + 1000)
        assert any("not read to its end" in fact for fact in packages[0].platform)

    def test_strings_cut_by_a_chunk_edge_are_read_whole_and_a_total_limit_ends_them(self) -> None:
        text = b"\x00".join(b"printable-run-number-%d" % n for n in range(50))
        _, parts, complete = self.read(text, chunk=30, total=10_000, part=200)
        assert complete is True
        assert b"printable-run-number-49" in b"".join(parts)
        _, _, limited = self.read(text, chunk=30, total=60, part=50)
        assert limited is False


class TestSmallHelpers:
    def test_a_go_marker_with_too_little_after_it_reads_as_nothing(self) -> None:
        assert BinaryMetadata.go("bin/app", GO_MAGIC + b"x") == []

    def test_a_32_bit_elf_has_its_sections_read_too(self) -> None:
        names = b"\x00.dep-v0\x00.shstrtab\x00"
        payload = zlib.compress(json.dumps({"packages": [{"name": "a", "version": "1"}]}).encode())
        body = payload + names
        shoff = 52 + len(body)
        header = bytearray(52)
        header[:4] = b"\x7fELF"
        header[4], header[5] = 1, 1
        struct.pack_into("<I", header, 0x20, shoff)
        struct.pack_into("<HHH", header, 0x2E, 40, 3, 2)
        sections = bytes(40)
        sections += struct.pack("<10I", 1, 1, 0, 0, 52, len(payload), 0, 0, 1, 0)
        sections += struct.pack("<10I", 9, 3, 0, 0, 52 + len(payload), len(names), 0, 0, 1, 0)
        data = bytes(header) + body + sections
        assert [(p.name, p.version) for p in BinaryMetadata.rust("bin/app", data)] == [("a", "1")]

    def test_the_zstd_program_is_named_only_when_its_own_banner_is_in_the_file(self) -> None:
        from cordon_scanner.images.binmeta import KnownBinaries

        assert KnownBinaries.identify("usr/bin/zstd", b"no banner here") == []

    def test_a_stream_that_ends_early_hands_back_what_it_had_and_then_nothing(self) -> None:
        from cordon_scanner.images.binmeta import _Pushback

        reader = _Pushback(io.BytesIO(b"ab"), 10)
        assert reader.read(5) == b"ab"
        assert reader.read(5) == b""

    def test_binary_headers_are_recognised_and_text_is_not(self) -> None:
        from cordon_scanner.images.binmeta import BinaryStrings

        assert BinaryStrings.is_binary(b"\x7fELF\x02\x01") is True
        assert BinaryStrings.is_binary(b"#!/bin/sh\n") is False


class TestStreamedJarEdges:
    def read(self, raw: bytes) -> list:
        from cordon_scanner.images.binmeta import StreamedJar

        return StreamedJar.read("big.jar", io.BytesIO(raw), len(raw))

    def entry(
        self, name: bytes, data: bytes, *, method: int, extra: bytes = b"", size: int | None = None
    ) -> bytes:
        header = struct.pack(
            "<HHHHHIIIHH",
            20,
            0,
            method,
            0,
            0,
            0,
            len(data) if size is None else size,
            len(data),
            len(name),
            len(extra),
        )
        return b"PK\x03\x04" + header + name + extra + data

    def test_an_entry_larger_than_the_stream_that_holds_it_ends_the_walk(self) -> None:
        assert self.read(self.entry(b"a.txt", b"short", method=0, size=500)) == []

    def test_a_deflated_pom_that_is_not_valid_deflate_is_passed_over(self) -> None:
        name = b"META-INF/maven/g/lib/pom.properties"
        assert self.read(self.entry(name, b"\xff\xfe garbage", method=8)) == []

    def test_other_extra_fields_are_stepped_over_to_find_the_zip64_one(self) -> None:
        pom = b"groupId=g\nartifactId=lib\nversion=1.0\n"
        name = b"META-INF/maven/g/lib/pom.properties"
        extra = (
            struct.pack("<HH", 0xCAFE, 2) + b"xx" + struct.pack("<HHQQ", 1, 16, len(pom), len(pom))
        )
        raw = self.entry(name, pom, method=0, extra=extra, size=0xFFFFFFFF)
        assert [(p.name, p.version) for p in self.read(raw)] == [("g:lib", "1.0")]

    def test_a_descriptor_without_its_signature_is_skipped_and_an_entry_over_the_limit_is_not_kept(
        self,
    ) -> None:
        from cordon_scanner.images.binmeta import StreamedJar, _Pushback

        deflater = zlib.compressobj(wbits=-15)
        compressed = deflater.compress(b"x" * 5000) + deflater.flush()
        reader = _Pushback(io.BytesIO(compressed + bytes(12) + b"PK\x03\x04"), 1 << 20)
        assert StreamedJar._inflate(reader, 100) == (None, True)
        StreamedJar._skip_descriptor(reader)
        assert reader.read(4) == b"PK\x03\x04"
        broken = _Pushback(io.BytesIO(b"\xff\xff\xff\xff"), 100)
        assert StreamedJar._inflate(broken, 100) == (None, False)
