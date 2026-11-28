"""Bazel's less common shapes: Starlark values and statements the reader passes over, override kinds, a repository rule's label, and a legacy WORKSPACE (`ecosystems/infra/bazel.py`)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from cordon_scanner.ecosystems.infra.bazel import ModuleLock, Starlark, StarlarkError
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["bazel"]

    @staticmethod
    def manifest(path: str, text: str):
        return _Kit.adapter().parse_manifest(_Kit.fc(path, text))


class TestStarlark:
    def test_a_statement_that_is_not_a_call_is_passed_over_to_its_own_end_across_lines(
        self,
    ) -> None:
        calls = Starlark.calls('X = [\n  "a",\n]\nfoo(a = "1")\n')
        assert [(c.name, c.keywords) for c in calls] == [("foo", {"a": "1"})]

    def test_a_dictionary_argument_is_read_into_a_mapping_with_numeric_keys_as_text(self) -> None:
        [call] = Starlark.calls('foo(a = {"k": "v", 3: "x", "n": ["y"]})\n')
        assert call.keywords["a"] == {"k": "v", "3": "x", "n": ["y"]}

    def test_a_value_followed_by_an_operator_is_not_read_and_the_next_argument_is(self) -> None:
        [call] = Starlark.calls('foo(a = ["x"] + ["y"], b = "kept")\n')
        assert call.keywords["b"] == "kept"
        assert call.keywords["a"] != ["x"]

    def test_text_that_is_not_starlark_is_refused_by_a_parse_error(self) -> None:
        manifest = _Kit.manifest("BUILD.bazel", 'foo("unterminated\n')
        assert manifest.parse_error.startswith("not readable Starlark")


class TestWorkspace:
    def test_a_git_repository_with_a_computed_remote_declares_nothing(self) -> None:
        manifest = _Kit.manifest("WORKSPACE", "git_repository(name = 'x', remote = REMOTE)\n")
        assert manifest.dependencies == ()

    def test_a_maven_install_artifact_that_is_not_a_string_is_skipped(self) -> None:
        manifest = _Kit.manifest(
            "WORKSPACE",
            'maven_install(artifacts = ["g:a:1", maven.artifact("g", "b", "2")])\n',
        )
        assert [(d.name, d.spec) for d in manifest.dependencies] == [("g:a", "1")]


class TestModule:
    def test_a_single_version_override_names_its_registry_and_pins_the_version(self) -> None:
        manifest = _Kit.manifest(
            "MODULE.bazel",
            'bazel_dep(name = "m", version = "1.0")\n'
            'single_version_override(module_name = "m", version = "1.1", registry = "https://r.example.invalid")\n',
        )
        assert "registry for m: https://r.example.invalid" in manifest.sources
        assert manifest.overrides == {"m": "1.1"}

    def test_a_repository_rule_from_the_bazel_tools_is_not_a_hook_and_one_from_elsewhere_is(
        self,
    ) -> None:
        manifest = _Kit.manifest(
            "MODULE.bazel",
            'http = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")\n'
            'mine = use_repo_rule("//tools:fetch.bzl", "fetch_things")\n',
        )
        assert [(h.name, h.command) for h in manifest.hooks] == [
            ("repository rule fetch_things", "//tools:fetch.bzl")
        ]


class TestLock:
    def lock(self, **fields: Any):
        return ModuleLock.parse(_Kit.fc("MODULE.bazel.lock", json.dumps(fields)), "bazel")

    def test_a_lock_with_neither_a_graph_nor_registry_hashes_is_refused(self) -> None:
        assert (
            "neither a module graph nor registry file hashes"
            in self.lock(lockFileVersion=3).parse_error
        )


class TestLegacyWorkspace:
    WORKSPACE = _Kit.fc(
        "WORKSPACE", 'http_archive(name = "x", urls = ["https://example.invalid/x.tgz"])\n'
    )

    def read(self, files: dict[str, Any]):
        return _Kit.adapter().parse_in_tree(self.WORKSPACE, {"WORKSPACE": self.WORKSPACE, **files})

    def test_with_bazel_8_and_no_flag_the_workspace_is_said_not_to_be_read(self) -> None:
        manifest = self.read(
            {
                "MODULE.bazel": _Kit.fc("MODULE.bazel", ""),
                ".bazelversion": _Kit.fc(".bazelversion", "8.0.0\n"),
            }
        )
        assert any("reads no WORKSPACE" in str(d.note) for d in manifest.dependencies)

    def test_the_flag_in_bazelrc_keeps_it_read(self) -> None:
        manifest = self.read(
            {
                "MODULE.bazel": _Kit.fc("MODULE.bazel", ""),
                ".bazelversion": _Kit.fc(".bazelversion", "8.0.0\n"),
                ".bazelrc": _Kit.fc(".bazelrc", "common --enable_workspace\n"),
            }
        )
        assert not any("reads no WORKSPACE" in str(d.note) for d in manifest.dependencies)

    def test_a_workspace_bzlmod_beside_it_replaces_it(self) -> None:
        manifest = self.read({"WORKSPACE.bzlmod": _Kit.fc("WORKSPACE.bzlmod", "")})
        assert "WORKSPACE.bzlmod replaces it" in " ".join(manifest.sources)

    def test_text_given_as_a_plain_string_is_read_too(self) -> None:
        manifest = self.read({"MODULE.bazel": "", ".bazelversion": "9.1\n"})
        assert any("reads no WORKSPACE" in str(d.note) for d in manifest.dependencies)


class TestRefusals:
    def test_a_closing_bracket_with_nothing_open_is_refused(self) -> None:
        with pytest.raises(StarlarkError, match="closing bracket with nothing open"):
            Starlark.calls(")")

    def test_an_argument_with_no_value_is_refused(self) -> None:
        with pytest.raises(StarlarkError, match="argument with no value"):
            Starlark.calls("foo(a=)\n")

    def test_brackets_that_balance_by_count_but_not_by_kind_are_refused_not_looped_on(self) -> None:
        with pytest.raises(StarlarkError):
            Starlark.calls("foo(a = [1)]\n")

    def test_a_bazel_dep_without_a_name_is_an_error(self) -> None:
        manifest = _Kit.manifest("MODULE.bazel", 'bazel_dep(version = "1.0")\n')
        assert manifest.parse_error == "a bazel_dep without its name"

    def test_a_lock_without_its_version_is_refused(self) -> None:
        graph = ModuleLock.parse(_Kit.fc("MODULE.bazel.lock", "{}"), "bazel")
        assert "without its lockFileVersion" in graph.parse_error
