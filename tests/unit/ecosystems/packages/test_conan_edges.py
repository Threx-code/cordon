"""Conan's text, recipe, lock, remotes and workspace files on the shapes that are odd or broken (`ecosystems/packages/conan.py`)."""

from __future__ import annotations

import ast
import json
from typing import Any

import pytest

from cordon_scanner.ecosystems.packages.conan import ConanRecipe
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["conan"]

    @staticmethod
    def manifest(path: str, text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc(path, text))

    @staticmethod
    def lock(data: Any) -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc("conan.lock", json.dumps(data)))

    @staticmethod
    def computed(source: str, attributes: dict[str, str] | None = None) -> str | None:
        node = ast.parse(source, mode="eval").body
        return ConanRecipe.computed(node, attributes or {})


class TestConanfileText:
    def test_a_section_conanfile_txt_does_not_have_is_refused(self) -> None:
        assert _Kit.manifest("conanfile.txt", "[nonsense]\nx\n").parse_error == (
            "a section conanfile.txt does not have"
        )

    def test_a_file_that_requires_nothing_is_refused(self) -> None:
        manifest = _Kit.manifest("conanfile.txt", "[generators]\nCMakeDeps\n")
        assert "requires nothing" in manifest.parse_error

    def test_a_tool_requires_line_that_is_no_reference_is_named(self) -> None:
        manifest = _Kit.manifest("conanfile.txt", "[tool_requires]\nnot a reference\n")
        assert manifest.parse_error == "a [tool_requires] line that is not a Conan reference"


class TestRecipe:
    def test_a_recipe_larger_than_the_limit_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ConanRecipe, "MAX_BYTES", 10)
        manifest = _Kit.manifest("conanfile.py", "x = 1  # " + "a" * 50 + "\n")
        assert manifest.parse_error == "a recipe larger than a recipe is"

    def test_a_string_alone_is_its_own_value(self) -> None:
        assert _Kit.computed('"zlib/1.3.1"') == "zlib/1.3.1"

    def test_a_format_call_fills_positional_numbered_and_named_fields(self) -> None:
        assert _Kit.computed('"zlib/{}".format("1.3")') == "zlib/1.3"
        assert _Kit.computed('"{1}/{0}".format("a", "b")') == "b/a"
        assert _Kit.computed('"zlib/{v}".format(v="2")') == "zlib/2"
        unknown = _Kit.computed('"zlib/{v}".format(w="2")')
        assert unknown is not None and ConanRecipe.UNKNOWN in unknown

    def test_a_reference_built_too_deeply_is_not_followed(self) -> None:
        source = "x" + " + 'a'" * 12
        assert ConanRecipe.UNKNOWN in (_Kit.computed(source) or "")


class TestLocks:
    def test_a_conan2_lock_entry_that_is_not_a_reference_is_refused(self) -> None:
        graph = _Kit.lock({"version": "0.5", "requires": ["not a ref"]})
        assert graph.parse_error == "a requires entry that is not a Conan reference"

    def test_a_conan1_graph_skips_nodes_without_a_ref_and_refuses_a_bad_one(self) -> None:
        ok = _Kit.lock(
            {"graph_lock": {"nodes": {"0": {}, "1": {"ref": "zlib/1.3.1"}, "2": "text"}}}
        )
        assert [e.name for e in ok.entries] == ["zlib"]
        bad = _Kit.lock({"graph_lock": {"nodes": {"1": {"ref": "not a ref"}}}})
        assert bad.parse_error == "a node whose ref is not a Conan reference"


class TestRemotesAndWorkspaces:
    def test_remotes_that_are_not_json_or_have_no_list_are_refused(self) -> None:
        assert _Kit.manifest("remotes.json", "{nope").parse_error.startswith("invalid JSON")
        assert (
            _Kit.manifest("remotes.json", "{}").parse_error
            == "a remotes.json without a remotes list"
        )

    def test_a_workspace_that_cannot_be_read_or_lists_no_packages_is_refused(self) -> None:
        assert _Kit.manifest("conanws.yml", "a: [unclosed\n").parse_error.startswith(
            "invalid conanws.yml"
        )
        assert (
            _Kit.manifest("conanws.yml", "a: 1\n").parse_error
            == "a conanws.yml without a packages list"
        )


class TestMoreConan:
    def test_a_profile_tool_requires_line_that_is_no_reference_is_named(self) -> None:
        manifest = _Kit.manifest("profiles/default", "[tool_requires]\nnot a reference\n")
        assert manifest.parse_error == "a [tool_requires] line that is not a Conan reference"

    def test_a_lock_with_neither_requires_nor_a_graph_is_refused(self) -> None:
        graph = _Kit.lock({"version": "0.5"})
        assert graph.parse_error == "a conan.lock with neither requires nor a graph_lock"

    def test_a_workspace_that_cannot_be_read_has_no_members(self) -> None:
        from cordon_scanner.ecosystems.packages.conan import ConanWorkspace

        assert ConanWorkspace.members(_Kit.fc("conanws.yml", "a: [unclosed\n")) == set()

    def test_something_that_is_not_a_string_or_a_list_holds_no_strings(self) -> None:
        assert ConanRecipe.strings(ast.parse("x", mode="eval").body) == []
