"""A jar too large to hold is walked front to back for the Maven artifacts it records
(`images/binmeta.py` StreamedJar), and finds what the in-memory reader finds."""

from __future__ import annotations

import io
import zipfile

import pytest

from cordon_scanner.images.binmeta import BinaryMetadata, StreamedJar


class Unseekable(io.RawIOBase):
    """A write-only stream that cannot seek, so zipfile writes trailing data descriptors."""

    def __init__(self) -> None:
        self.buffer = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:  # type: ignore[override]
        self.buffer += b
        return len(b)


class Jars:
    @staticmethod
    def pom(group: str, artifact: str, version: str) -> str:
        return f"groupId={group}\nartifactId={artifact}\nversion={version}\n"

    @staticmethod
    def build(
        entries: dict[str, bytes], *, streamed: bool, method: int = zipfile.ZIP_DEFLATED
    ) -> bytes:
        sink: io.BytesIO | Unseekable = Unseekable() if streamed else io.BytesIO()
        with zipfile.ZipFile(sink, "w", compression=method) as archive:  # type: ignore[arg-type]
            for name, data in entries.items():
                archive.writestr(name, data)
        return bytes(sink.buffer) if isinstance(sink, Unseekable) else sink.getvalue()

    @staticmethod
    def uberjar(*, streamed: bool) -> bytes:
        inner = Jars.build(
            {
                "META-INF/maven/org.inner/lib/pom.properties": Jars.pom(
                    "org.inner", "lib", "2.0"
                ).encode()
            },
            streamed=False,
        )
        entries = {
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
            "metabase/core.clj": b"(ns metabase.core)\n" * 2000,
            "META-INF/maven/amalloy/ring-buffer/pom.properties": Jars.pom(
                "amalloy", "ring-buffer", "1.3.1"
            ).encode(),
            "META-INF/maven/buddy/buddy-core/pom.properties": Jars.pom(
                "buddy", "buddy-core", "1.11.423"
            ).encode(),
            "lib/inner.jar": inner,
        }
        return Jars.build(entries, streamed=streamed)

    @staticmethod
    def found(packages) -> set[tuple[str, str, str]]:
        return {(p.name, p.version, p.path) for p in packages}


class TestStreamedJar:
    @pytest.mark.parametrize(
        "streamed", [False, True], ids=["sizes-in-headers", "trailing-descriptors"]
    )
    def test_it_finds_what_the_in_memory_reader_finds(self, streamed) -> None:
        data = Jars.uberjar(streamed=streamed)
        walked = StreamedJar.read("opt/app.jar", io.BytesIO(data), len(data))
        held = BinaryMetadata.java("opt/app.jar", data)
        expected = {
            ("amalloy:ring-buffer", "1.3.1", "opt/app.jar"),
            ("buddy:buddy-core", "1.11.423", "opt/app.jar"),
            ("org.inner:lib", "2.0", "opt/app.jar!lib/inner.jar"),
        }
        assert Jars.found(walked) == expected
        assert Jars.found(walked) <= Jars.found(held)

    def test_stored_entries_are_read_too(self) -> None:
        data = Jars.build(
            {"META-INF/maven/a/b/pom.properties": Jars.pom("a", "b", "1").encode()},
            streamed=False,
            method=zipfile.ZIP_STORED,
        )
        assert Jars.found(StreamedJar.read("x.jar", io.BytesIO(data), len(data))) == {
            ("a:b", "1", "x.jar")
        }

    def test_a_truncated_or_foreign_file_gives_what_was_read_and_never_raises(self) -> None:
        data = Jars.uberjar(streamed=True)
        assert (
            StreamedJar.read("x.jar", io.BytesIO(data[: len(data) // 3]), len(data) // 3)
            is not None
        )
        assert StreamedJar.read("x.jar", io.BytesIO(b"not a zip at all"), 16) == []
