"""The detection model's features (`cordon_scanner.model.features`): read in memory under hard limits,
whatever an archive's headers say, deterministic, and never following a link out of a directory."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile
from pathlib import Path
from typing import ClassVar

import pytest

from cordon_scanner.model.features import (
    FILE_DENSE,
    MAX_FILE,
    PACKAGE_DENSE,
    PER_PACKAGE_FILES,
    TOKEN_DIM,
    FileFeatures,
    PackageArchive,
    PackageFeatures,
)


class Archives:
    @staticmethod
    def zipped(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, body in files.items():
                archive.writestr(name, body)
        return buffer.getvalue()

    @staticmethod
    def tarred(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, body in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return buffer.getvalue()


class TestReading:
    def test_zip_and_tar_give_the_same_files(self) -> None:
        files = {"package/index.js": b"console.log(1)\n", "package/package.json": b"{}"}
        assert sorted(PackageArchive.members(Archives.zipped(files))) == sorted(
            PackageArchive.members(Archives.tarred(files))
        )

    def test_a_member_larger_than_the_limit_is_skipped(self) -> None:
        files = {"big.js": b"a" * (MAX_FILE + 1), "small.js": b"b"}
        assert [n for n, _ in PackageArchive.members(Archives.zipped(files))] == ["small.js"]

    def test_a_zip_that_lies_about_a_member_size_reads_no_more_than_the_limit(self) -> None:
        data = bytearray(Archives.zipped({"bomb.js": b"a" * (MAX_FILE + 5000)}))
        # Rewrite the declared uncompressed size in the central directory to 1 byte.
        central = data.rfind(b"PK\x01\x02")
        data[central + 24 : central + 28] = (1).to_bytes(4, "little")
        assert all(len(body) <= MAX_FILE for _, body in PackageArchive.members(bytes(data)))

    def test_garbage_is_no_files(self) -> None:
        assert PackageArchive.members(b"not an archive") == []
        assert PackageArchive.members(b"PK\x03\x04broken") == []

    def test_an_archive_holding_one_package_archive_is_that_package(self) -> None:
        inner = Archives.tarred({"package/index.js": b"x"})
        outer = Archives.zipped({"pkg-1.0.0.tgz": inner, "package_info-1.json": b"{}"})
        assert [n for n, _ in PackageArchive.members(outer)] == ["package/index.js"]

    def test_a_directory_never_follows_a_link_out(self, tmp_path: Path) -> None:
        (tmp_path / "index.js").write_text("x", encoding="utf-8")
        outside = tmp_path.parent / "outside-secret.txt"
        outside.write_text("secret", encoding="utf-8")
        (tmp_path / "link.txt").symlink_to(outside)
        assert [n for n, _ in PackageArchive.directory(tmp_path)] == ["index.js"]


class TestFeatures:
    def test_shapes_and_ranges(self) -> None:
        files = [
            (
                "package/package.json",
                json.dumps({"scripts": {"postinstall": "node setup.js"}}).encode(),
            ),
            ("package/setup.js", b"require('child_process').exec(process.env.X)\n"),
        ]
        dense, tokens = PackageFeatures.extract(files)
        assert len(dense) == len(PACKAGE_DENSE)
        assert tokens == sorted(set(tokens)) and all(0 <= t < TOKEN_DIM for t in tokens)
        assert dense[PACKAGE_DENSE.index("has_install_hook")] == 1.0
        rows = FileFeatures.rows(files)
        assert len(rows) == 1 and len(rows[0]) == len(FILE_DENSE)
        assert rows[0][FILE_DENSE.index("is_hook_target")] == 1.0

    def test_the_same_input_gives_the_same_features(self) -> None:
        files = [("a.py", b"import os\nos.system('x')\n"), ("b.js", b"eval(atob('eA=='))\n")]
        assert PackageFeatures.extract(files) == PackageFeatures.extract(list(files))
        assert FileFeatures.rows(files) == FileFeatures.rows(list(files))

    def test_file_rows_are_capped_and_keep_the_hook_target(self) -> None:
        files = [(f"package/f{i}.js", b"fetch('x')\n" * (i % 7)) for i in range(300)]
        files.append(
            ("package/package.json", json.dumps({"scripts": {"install": "node f299.js"}}).encode())
        )
        rows = FileFeatures.rows(files)
        assert len(rows) == PER_PACKAGE_FILES
        assert any(r[FILE_DENSE.index("is_hook_target")] == 1.0 for r in rows)

    @pytest.mark.parametrize("name", ["x.exe", "x.dll", "x.so"])
    def test_binaries_have_no_file_row(self, name: str) -> None:
        assert FileFeatures.rows([(name, b"MZ" + b"\x00" * 100)]) == []


class TestHowAPackageWasPackedDoesNotShow:
    """The same files under `package/`, under a dataset's wrapper, or from the package's own
    directory: identical features. A model must learn what a package does, never how it was packed."""

    FILES: ClassVar[list[tuple[str, bytes]]] = [
        (
            "package.json",
            b'{"name": "x", "scripts": {"postinstall": "node setup.js"}, "main": "index.js"}',
        ),
        ("setup.js", b"require('child_process').exec('id');\n"),
        ("index.js", b"module.exports = 1;\n"),
        ("lib/util.js", b"exports.f = () => 2;\n"),
    ]

    @staticmethod
    def under(prefix: str) -> list[tuple[str, bytes]]:
        return [(prefix + name, body) for name, body in TestHowAPackageWasPackedDoesNotShow.FILES]

    def test_the_wrapper_is_invisible_to_package_features(self) -> None:
        plain = PackageFeatures.extract(self.under(""))
        assert PackageFeatures.extract(self.under("package/")) == plain
        assert PackageFeatures.extract(self.under("tmp/tmpab12/x/package/")) == plain

    def test_the_wrapper_is_invisible_to_file_features(self) -> None:
        plain = FileFeatures.rows(self.under(""))
        assert FileFeatures.rows(self.under("tmp/tmpab12/x/package/")) == plain

    def test_the_manifest_is_read_however_deep_the_wrapper(self) -> None:
        dense, _ = PackageFeatures.extract(self.under("tmp/tmpab12/x/package/"))
        assert dense[PACKAGE_DENSE.index("has_install_hook")] == 1

    def test_a_wheel_with_no_shared_root_is_left_alone(self) -> None:
        files = [("x/__init__.py", b""), ("x-1.0.dist-info/METADATA", b"Name: x")]
        assert PackageArchive.rooted(files) == files
