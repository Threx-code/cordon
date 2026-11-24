"""A bundled copy of a known package is identical, modified or unknown by its bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cordon_scanner.ecosystems.vendored.vendored_copies import VendoredCopies

PURL = "pkg:npm/left-pad@1.3.0"


class Files:
    @staticmethod
    def tree(index_js: str) -> dict[str, bytes]:
        manifest = json.dumps({"name": "left-pad", "version": "1.3.0"}).encode()
        return {
            "package.json": json.dumps({"name": "host", "version": "2.0.0"}).encode(),
            "src/main.js": b"require('../vendor/left-pad');\n",
            "vendor/left-pad/package.json": manifest,
            "vendor/left-pad/index.js": index_js.encode(),
        }


class TestVendoredCopies:
    def original(self) -> str:
        return VendoredCopies.digest(Files.tree("module.exports = pad;\n"), "vendor/left-pad")

    def test_a_byte_identical_copy_is_identical(self) -> None:
        (copy,) = VendoredCopies.of(Files.tree("module.exports = pad;\n"), {PURL: self.original()})
        assert (copy.path, copy.purl, copy.state) == ("vendor/left-pad", PURL, "identical")

    def test_a_changed_copy_is_modified(self) -> None:
        (copy,) = VendoredCopies.of(Files.tree("module.exports = evil;\n"), {PURL: self.original()})
        assert copy.state == "modified" and copy.digest != self.original()

    def test_a_package_the_caller_has_no_digest_for_is_unknown_never_identical(self) -> None:
        (copy,) = VendoredCopies.of(Files.tree("module.exports = pad;\n"), {})
        assert copy.state == "unknown"

    def test_the_hosts_own_manifest_and_an_install_are_not_copies(self) -> None:
        files = {
            **Files.tree("x"),
            "node_modules/dep/package.json": b'{"name":"dep","version":"1.0.0"}',
        }
        assert [c.path for c in VendoredCopies.of(files)] == ["vendor/left-pad"]

    def test_a_manifest_that_names_no_package_is_not_a_copy(self) -> None:
        assert VendoredCopies.of({"a/package.json": b"{not json", "b/package.json": b"{}"}) == ()

    def test_a_scoped_name_is_written_as_a_package_url(self) -> None:
        files = {"v/s/package.json": b'{"name":"@acme/util","version":"1.0.0"}'}
        assert VendoredCopies.of(files)[0].purl == "pkg:npm/%40acme%2Futil@1.0.0"


class TestADirectoryReadPastItsBounds:
    def write(self, root: Path) -> str:
        base = root / "vendor" / "left-pad"
        base.mkdir(parents=True)
        (base / "package.json").write_text(
            '{"name":"left-pad","version":"1.3.0"}', encoding="utf-8"
        )
        (base / "index.js").write_text("module.exports = pad;\n" + "// " * 100, encoding="utf-8")
        return "pkg:npm/left-pad@1.3.0"

    def whole(self, root: Path) -> str:
        return VendoredCopies.of_directory(root)[0].digest

    def test_a_copy_read_whole_is_compared(self, tmp_path: Path) -> None:
        purl = self.write(tmp_path)
        known = {purl: self.whole(tmp_path)}
        assert VendoredCopies.of_directory(tmp_path, known)[0].state == "identical"

    def test_the_file_count_bound_makes_the_copy_partial_not_identical(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        purl = self.write(tmp_path)
        known = {purl: self.whole(tmp_path)}
        monkeypatch.setattr(VendoredCopies, "MAX_FILES", 1)
        assert VendoredCopies.of_directory(tmp_path, known)[0].state == "partial"

    def test_a_file_past_the_size_bound_makes_the_copy_partial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.write(tmp_path)
        monkeypatch.setattr(VendoredCopies, "MAX_BYTES", 100)
        assert VendoredCopies.of_directory(tmp_path)[0].state == "partial"

    def test_a_link_inside_the_copy_makes_it_partial(self, tmp_path: Path) -> None:
        self.write(tmp_path)
        (tmp_path / "vendor" / "left-pad" / "link.js").symlink_to(
            tmp_path / "vendor" / "left-pad" / "index.js"
        )
        assert VendoredCopies.of_directory(tmp_path)[0].state == "partial"


class TestTheDigestAndThePackageUrl:
    def digest_of(self, files: dict[str, bytes]) -> str:
        return VendoredCopies.of({"v/package.json": b'{"name":"p","version":"1.0.0"}', **files})[
            0
        ].digest

    def test_a_file_name_with_a_newline_cannot_pass_for_two_files(self) -> None:
        two = self.digest_of({"v/a": b"1", "v/b": b"2"})
        forged = self.digest_of({f"v/a\0{hashlib.sha256(b'1').hexdigest()}\nb": b"2"})
        assert forged != two

    def test_a_version_is_quoted_and_a_long_name_or_version_names_no_package(self) -> None:
        odd = {"v/package.json": b'{"name":"p","version":"1.0.0+a b/c"}'}
        assert VendoredCopies.of(odd)[0].purl == "pkg:npm/p@1.0.0%2Ba%20b%2Fc"
        long_name = {"v/package.json": json.dumps({"name": "n" * 300, "version": "1"}).encode()}
        long_version = {"v/package.json": json.dumps({"name": "n", "version": "1" * 100}).encode()}
        assert VendoredCopies.of(long_name) == () and VendoredCopies.of(long_version) == ()

    def test_the_upload_form_carries_no_state_but_marks_a_partial_copy(self) -> None:
        files = {"v/package.json": b'{"name":"p","version":"1.0.0"}'}
        whole = VendoredCopies.of(files)[0].to_dict()
        cut = VendoredCopies.of(files, partial=frozenset({"v"}))[0].to_dict()
        assert "state" not in whole and "partial" not in whole and cut["partial"] is True
