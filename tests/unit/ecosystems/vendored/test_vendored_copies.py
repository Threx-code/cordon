"""A bundled copy of a known package is identical, modified or unknown by its bytes."""

from __future__ import annotations

import json

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
