"""Hackage's less common inputs: hpack dependency forms and flags, a custom setup, packages listed by a project file, and the refusals (`ecosystems/packages/hackage.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from cordon_scanner.ecosystems.packages.hackage import CabalFile, HackageEcosystem, Hpack
from cordon_scanner.ecosystems.packages.haskell.cabal import CabalLayout
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["hackage"]

    @staticmethod
    def read(path: str, text: str, **others: str) -> Any:
        files = {path: _Kit.fc(path, text), **{p: _Kit.fc(p, t) for p, t in others.items()}}
        return _Kit.adapter().parse_in_tree(files[path], files)


class TestCabal:
    def test_a_cabal_file_with_no_name_or_version_is_refused(self) -> None:
        manifest = _Kit.read("p.cabal", "cabal-version: 3.0\nname: p\n")
        assert manifest.parse_error

    def test_a_dependency_hidden_past_the_nesting_limit_is_not_followed(self) -> None:
        nodes = CabalLayout.parse("library\n  build-depends: base\n")
        assert CabalFile._declares(nodes, {}, 0) is True
        assert CabalFile._declares(nodes, {}, CabalLayout.MAX_DEPTH + 1) is False

    def test_a_dependency_under_a_conditional_makes_the_component_declare_one(self) -> None:
        nodes = CabalLayout.parse("library\n  if flag(x)\n    build-depends: base\n")
        assert CabalFile._declares(nodes, {}, 0) is True


class TestHpack:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (
                {"base": ">=4", "containers": {"version": "0.6"}, "other": {}},
                [("base", ">=4"), ("containers", "0.6"), ("other", "*")],
            ),
        ],
    )
    def test_dependencies_written_as_a_mapping_name_their_version_or_any(
        self, value: Any, expected: list[tuple[str, str]]
    ) -> None:
        assert list(Hpack.entries(value)) == expected

    def test_a_package_yaml_that_is_pnpms_is_not_hpacks(self) -> None:
        assert Hpack.is_hpack({"scripts": {}, "dependencies": ["a"]}, True) is False
        assert Hpack.is_hpack({"dependencies": ["base"]}, False) is True

    def test_flags_custom_setup_and_internal_libraries_are_read(self) -> None:
        text = (
            "name: p\n"
            "flags:\n  fast:\n    default: false\n  safe: {}\n"
            "library:\n  dependencies: [aeson]\n"
            "custom-setup:\n  dependencies: [Cabal]\n"
        )
        manifest = _Kit.read("package.yaml", text, **{"stack.yaml": "resolver: lts-22.0\n"})
        scopes = {d.name: d.scope for d in manifest.dependencies}
        assert scopes["aeson"] is Scope.RUNTIME
        assert scopes["Cabal"] is Scope.BUILD
        assert "flag fast (default off)" in manifest.sources
        assert "flag safe (default on)" in manifest.sources

    def test_a_package_yaml_beside_stack_that_cannot_be_read_is_an_error(self) -> None:
        manifest = _Kit.read("package.yaml", "name: [unclosed\n", **{"stack.yaml": "resolver: x\n"})
        assert manifest.parse_error.startswith("invalid package.yaml")

    def test_a_package_yaml_that_cannot_be_read_and_is_not_beside_stack_is_not_judged(self) -> None:
        manifest = _Kit.read("package.yaml", "name: [unclosed\n")
        assert not manifest.parse_error and manifest.dependencies == ()

    def test_a_non_hpack_package_yaml_beside_stack_is_an_error_and_elsewhere_is_empty(self) -> None:
        beside = _Kit.read("package.yaml", "scripts: {}\n", **{"stack.yaml": "resolver: x\n"})
        assert "not an hpack package description" in beside.parse_error
        alone = _Kit.read("package.yaml", "scripts: {}\n")
        assert not alone.parse_error

    def test_an_hpack_file_beside_stack_with_no_name_is_refused(self) -> None:
        manifest = _Kit.read(
            "package.yaml", "library:\n  dependencies: [base]\n", **{"stack.yaml": "resolver: x\n"}
        )
        assert "without a `name`" in manifest.parse_error


class TestOwningProject:
    def test_a_package_listed_by_a_cabal_project_is_owned_by_its_directory(self) -> None:
        files = {
            "cabal.project": _Kit.fc("cabal.project", "packages: pkgs/a\n  pkgs/b/b.cabal\n"),
            "pkgs/a/a.cabal": _Kit.fc("pkgs/a/a.cabal", "name: a\n"),
        }
        assert HackageEcosystem.owning_project("pkgs/a/a.cabal", files) == ""
        assert HackageEcosystem.listed_packages(files["cabal.project"], "pkgs/b") == {"pkgs/b"}

    def test_a_cabal_project_nested_past_the_limit_lists_nothing(self) -> None:
        deep = "\n".join(" " * n + f"s{n}" for n in range(40)) + "\n"
        broken = _Kit.fc("cabal.project", deep)
        assert HackageEcosystem.listed_packages(broken, "a") == set()

    def test_a_stack_yaml_lists_packages_by_directory_or_glob(self) -> None:
        stack = _Kit.fc("stack.yaml", "resolver: lts-22.0\npackages:\n  - libs/*\n  - ./app/\n")
        assert HackageEcosystem.listed_packages(stack, "libs/core") == {"libs/core"}
        assert HackageEcosystem.listed_packages(stack, "app") == {"app"}
        assert HackageEcosystem.listed_packages(stack, "other") == set()

    def test_a_stack_yaml_that_cannot_be_read_lists_nothing(self) -> None:
        assert (
            HackageEcosystem.listed_packages(_Kit.fc("stack.yaml", ":: bad ::\n  - ["), "a")
            == set()
        )


class TestMalformedDependency:
    def test_a_dependency_that_is_not_a_package_and_constraint_is_an_error_for_the_file(
        self,
    ) -> None:
        manifest = _Kit.read(
            "package.yaml",
            "name: p\nlibrary:\n  dependencies: ['!!!']\n",
            **{"stack.yaml": "resolver: x\n"},
        )
        assert manifest.parse_error.startswith("not a readable package.yaml")


class TestMoreHackage:
    def test_a_top_level_line_that_is_neither_a_field_nor_a_section_is_refused(self) -> None:
        manifest = _Kit.read(
            "p.cabal",
            "cabal-version: 3.0\nname: p\nversion: 1\nlibrary\n  build-depends: base\nweird-section\n  field: x\n",
        )
        assert manifest.parse_error

    def test_a_stack_yaml_that_is_not_a_mapping_governs_nothing(self) -> None:
        files = {"stack.yaml": _Kit.fc("stack.yaml", "- a\n")}
        assert HackageEcosystem.governing_stack("p/p.cabal", files) is None
