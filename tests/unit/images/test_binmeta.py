"""L4: what a compiled artefact records about its build, and binaries past the content limit.

Every fixture is metadata only: a buildinfo blob, an ELF header with one section, a deps.json,
a JAR holding a pom.properties. None contains code.
"""

from __future__ import annotations

import io
import json
import struct
import zipfile
import zlib

from cordon_scanner.images import oci
from cordon_scanner.images.binmeta import GO_MAGIC, BinaryMetadata, BinaryStrings
from imagekit import DEBIAN_RELEASE, ImageKit


class BinaryFixtures:
    @staticmethod
    def varint(value: int) -> bytes:
        out = b""
        while True:
            byte = value & 0x7F
            value >>= 7
            out += bytes([byte | (0x80 if value else 0)])
            if not value:
                return out

    @staticmethod
    def go_binary(modules: str, version: str = "go1.21.5") -> bytes:
        modinfo = b"0" * 16 + modules.encode() + b"0" * 16
        header = GO_MAGIC + bytes([8, 2]) + b"\x00" * 16
        blob = (
            header
            + BinaryFixtures.varint(len(version))
            + version.encode()
            + BinaryFixtures.varint(len(modinfo))
            + modinfo
        )
        return b"\x7fELF" + b"\x00" * 60 + blob + b"\x00" * 64

    @staticmethod
    def elf_with_section(name: bytes, payload: bytes) -> bytes:
        shstrtab = b"\x00.shstrtab\x00" + name + b"\x00"
        body_offset = 64
        shstr_offset = body_offset
        payload_offset = shstr_offset + len(shstrtab)
        shoff = payload_offset + len(payload)
        header = bytearray(64)
        header[:4] = b"\x7fELF"
        header[4], header[5] = 2, 1
        struct.pack_into("<Q", header, 0x28, shoff)
        struct.pack_into("<HHH", header, 0x3A, 64, 3, 1)

        def section(name_index: int, offset: int, size: int) -> bytes:
            return struct.pack("<IIQQQQIIQQ", name_index, 1, 0, 0, offset, size, 0, 0, 1, 0)

        sections = (
            b"\x00" * 64
            + section(1, shstr_offset, len(shstrtab))
            + section(11, payload_offset, len(payload))
        )
        return bytes(header) + shstrtab + payload + sections

    @staticmethod
    def jar(entries: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        return buffer.getvalue()


class TestGo:
    def test_modules_and_the_toolchain(self) -> None:
        data = BinaryFixtures.go_binary(
            "path\texample.com/app\nmod\texample.com/app\t(devel)\t\n"
            "dep\tgolang.org/x/net\tv0.17.0\th1:abc=\n"
            "dep\tgithub.com/gin-gonic/gin\tv1.9.0\th1:def=\n"
        )
        found = {(p.ecosystem, p.name, p.version) for p in BinaryMetadata.extract("app", data)}
        assert found == {
            ("gomod", "stdlib", "1.21.5"),
            ("gomod", "golang.org/x/net", "0.17.0"),
            ("gomod", "github.com/gin-gonic/gin", "1.9.0"),
        }

    def test_a_replacement_is_what_was_built(self) -> None:
        data = BinaryFixtures.go_binary(
            "dep\tgolang.org/x/net\tv0.17.0\th1:abc=\n=>\tgolang.org/x/net\tv0.23.0\th1:xyz=\n"
        )
        names = {
            (p.name, p.version) for p in BinaryMetadata.extract("app", data) if p.name != "stdlib"
        }
        assert names == {("golang.org/x/net", "0.23.0")}


class TestRust:
    def test_cargo_auditable(self) -> None:
        document = {
            "packages": [
                {"name": "app", "version": "0.1.0", "source": "local", "kind": "runtime"},
                {"name": "serde", "version": "1.0.190", "source": "crates.io", "kind": "runtime"},
                {"name": "cc", "version": "1.0.83", "source": "crates.io", "kind": "build"},
            ]
        }
        data = BinaryFixtures.elf_with_section(
            b".dep-v0", zlib.compress(json.dumps(document).encode())
        )
        assert [(p.name, p.version) for p in BinaryMetadata.extract("app", data)] == [
            ("serde", "1.0.190")
        ]

    def test_an_elf_without_the_section(self) -> None:
        assert (
            BinaryMetadata.extract("app", BinaryFixtures.elf_with_section(b".text", b"\x90" * 8))
            == []
        )


class TestDotnetAndJava:
    def test_deps_json(self) -> None:
        document = {
            "libraries": {
                "App/1.0.0": {"type": "project"},
                "Newtonsoft.Json/13.0.1": {"type": "package"},
            }
        }
        found = BinaryMetadata.extract("app/App.deps.json", json.dumps(document).encode())
        assert [(p.ecosystem, p.name, p.version) for p in found] == [
            ("nuget", "Newtonsoft.Json", "13.0.1")
        ]

    def test_a_fat_jar_and_its_nested_jars(self) -> None:
        inner = BinaryFixtures.jar(
            {
                "META-INF/maven/org.yaml/snakeyaml/pom.properties": b"groupId=org.yaml\nartifactId=snakeyaml\nversion=1.33\n"
            }
        )
        outer = BinaryFixtures.jar(
            {
                "META-INF/maven/com.example/app/pom.properties": b"groupId=com.example\nartifactId=app\nversion=1.0\n",
                "BOOT-INF/lib/snakeyaml-1.33.jar": inner,
            }
        )
        found = {(p.ecosystem, p.name, p.version) for p in BinaryMetadata.extract("app.jar", outer)}
        assert found == {
            ("maven", "com.example:app", "1.0"),
            ("maven", "org.yaml:snakeyaml", "1.33"),
        }


class TestStrings:
    def test_printable_runs(self) -> None:
        strings, complete = BinaryStrings.extract(
            b"\x00\x01https://api.example.invalid/v1\x00ab\x00token_value_here\x00"
        )
        assert strings == b"https://api.example.invalid/v1\ntoken_value_here\n" and complete

    def test_the_limit_is_reported(self) -> None:
        strings, complete = BinaryStrings.extract(b"abcdefgh\x00" * 100, limit=40)
        assert not complete and len(strings) <= 40


class TestAnImageBinaryPastTheLimit:
    def test_it_is_inventoried_and_its_strings_scanned(self) -> None:
        binary = (
            BinaryFixtures.go_binary("dep\tgolang.org/x/net\tv0.17.0\th1:abc=\n")
            + b"\x00embedded-config-url https://cfg.example.invalid/app\x00"
            + b"\x00" * 4096
        )
        data = ImageKit.docker_save(
            [
                ImageKit.layer(
                    {
                        "etc/os-release": DEBIAN_RELEASE,
                        "var/lib/dpkg/status": b"",
                        "app/server": binary,
                    }
                )
            ]
        )
        inventory = oci.ImageLayers.read_image(data)
        added = dict(
            oci.ImageLayers.added_files(
                data, inventory, max_file_bytes=1024, max_total_bytes=1 << 26
            )
        )
        assert b"https://cfg.example.invalid/app" in added["app/server"]
        assert b"\x00" not in added["app/server"], "scanned as its strings, not its bytes"
        assert ("gomod", "golang.org/x/net", "0.17.0") in {
            (p.ecosystem, p.name, p.version) for p in inventory.language_packages
        }
        assert oci.OVERSIZE not in inventory.skipped
        assert inventory.binaries_as_strings == 1


class TestAStreamedBinary:
    def test_buildinfo_across_a_chunk_boundary_and_strings_carried(self, monkeypatch) -> None:
        from cordon_scanner.images.binmeta import StreamedBinary

        monkeypatch.setattr(StreamedBinary, "CHUNK", 64)
        binary = (
            b"\x00" * 50
            + b"https://cfg.example.invalid/app-config-endpoint\x00"
            + BinaryFixtures.go_binary("dep\tgolang.org/x/net\tv0.17.0\th1:abc=\n")
            + b"\x00" * 100
        )
        packages, parts, complete = StreamedBinary.read("app", io.BytesIO(binary), len(binary))
        assert ("golang.org/x/net", "0.17.0") in {(p.name, p.version) for p in packages}
        assert b"https://cfg.example.invalid/app-config-endpoint" in b"".join(parts).split(b"\n")
        assert complete


class TestStringsPastOnePart:
    """Grafana's server binary carries more text than one scanned file holds: every string is
    still read, in parts, and only what passes the total is reported as cut short."""

    def test_every_string_is_kept_across_parts(self) -> None:
        from cordon_scanner.images.binmeta import StringParts

        runs = [f"config-entry-{n:05d}-value".encode() for n in range(200)]
        strings = StringParts(total=1 << 20, part=256)
        strings.add(b"\x00".join(runs))
        parts = strings.finish()
        assert strings.complete and len(parts) > 1
        assert all(len(p) <= 256 for p in parts)
        assert b"".join(parts).split(b"\n")[:-1] == runs, "no run split or lost at a boundary"

    def test_past_the_total_it_says_so(self) -> None:
        from cordon_scanner.images.binmeta import StringParts

        strings = StringParts(total=100, part=40)
        strings.add(b"\x00".join([b"abcdefghij"] * 50))
        assert not strings.complete and sum(len(p) for p in strings.finish()) <= 100

    def test_an_image_names_the_later_parts(self) -> None:
        binary = (
            b"\x7fELF"
            + b"\x00" * 60
            + b"\x00".join(f"https://cfg{n}.example.invalid/path".encode() for n in range(20))
        )
        peek = oci.Peek(max_file_bytes=16, part=64)
        peek.read("app/server", binary)
        names = [name for name, _ in peek.files()]
        assert names[0] == "app/server" and "app/server!strings-2" in names
        assert peek.truncated == 0

    def test_the_image_budget_is_shared(self) -> None:
        peek = oci.Peek(max_file_bytes=16, budget=50)
        text = b"\x00".join([b"abcdefghijklmnop"] * 10)
        peek.read("a", text)
        peek.read("b", text)
        assert peek.truncated == 2
