"""The last small branches of the ecosystem readers: renamed npm archives, cabal source stanzas, stack extra deps and dune forms (`archive_shapes.py`, `haskell/*`, `ocaml/dune.py`)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from cordon_scanner.ecosystems.archive_shapes import NpmRenamedArchive
from cordon_scanner.ecosystems.packages.haskell.cabal import CabalLayout
from cordon_scanner.ecosystems.packages.haskell.cabal_project import CabalProject
from cordon_scanner.ecosystems.packages.ocaml.dune import Sexp
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())


class TestRenamedNpmArchive:
    def test_an_archive_with_no_unit_for_its_package_json_is_not_one(self) -> None:
        levels = SimpleNamespace(
            roots={"pkg": {"package.json"}},
            top=["pkg/a.js"],
            units=[SimpleNamespace(path="x.tgz!pkg/other.js")],
        )
        assert NpmRenamedArchive().matches(levels) is False


class TestCabal:
    def test_a_layout_is_read_whole_whatever_its_indentation(self) -> None:
        nodes = CabalLayout.parse("library\n  build-depends: base\n   odd\nexecutable x\n")
        assert [n.head for n in nodes if not n.is_field]


class TestCabalProject:
    def test_a_source_repository_with_no_location_names_no_source(self) -> None:
        assert CabalProject.git_source(CabalLayout.parse("type: git\ntag: v1\n")) is None


class TestStack:
    def test_an_extra_dep_that_is_neither_text_nor_a_table_is_skipped(self) -> None:
        text = "resolver: lts-22.0\npackages: []\nextra-deps:\n  - 5\n  - acme-1.0@sha256:abc,1\n"
        manifest = EcosystemRegistry.BY_ID["hackage"].parse_manifest(_Kit.fc("stack.yaml", text))
        assert not manifest.parse_error


class TestDune:
    def test_atoms_end_at_whitespace_brackets_quotes_and_comments(self) -> None:
        assert Sexp.parse('(a;c\nb"x"(d)) e') == [["a", "b", "x", ["d"]], "e"]

    def test_a_depends_entry_that_is_an_empty_list_names_no_package(self) -> None:
        manifest: Any = EcosystemRegistry.BY_ID["opam"].parse_manifest(
            _Kit.fc("dune-project", "(lang dune 3.0)\n(package (name p) (depends () ocaml))\n")
        )
        assert [d.name for d in manifest.dependencies] == ["ocaml"]
