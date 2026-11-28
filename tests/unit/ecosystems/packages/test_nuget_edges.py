"""NuGet's less common inputs: exact version ranges, framework monikers, the restore file's hooks, a broken config, conditional properties and global references (`ecosystems/packages/nuget.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from cordon_scanner.ecosystems.packages.nuget import Frameworks, NuGetEcosystem, NuGetVersions
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
        return EcosystemRegistry.BY_ID["nuget"]


class TestVersionsAndFrameworks:
    def test_a_version_in_square_brackets_is_exact_and_a_range_is_not(self) -> None:
        assert NuGetVersions.exact(" [1.2.3] ") == "1.2.3"
        assert NuGetVersions.exact("[1.0,2.0)") is None

    @pytest.mark.parametrize(
        ("name", "moniker"),
        [
            (".NETStandard,Version=v2.0", "netstandard2.0"),
            (".NETFramework,Version=v4.7.2", "net472"),
            (".NETFramework,Version=v4.8", "net48"),
            (".NETCoreApp,Version=v8.0", "net8.0"),
            (".NETCoreApp,Version=v3.1", "netcoreapp3.1"),
            ("net6.0", "net6.0"),
        ],
    )
    def test_restore_spellings_become_the_names_projects_write(
        self, name: str, moniker: str
    ) -> None:
        assert Frameworks.moniker(name) == moniker


class TestRestoreFile:
    PATH = "obj/project.assets.json"

    def test_text_that_is_not_json_is_an_error_as_a_manifest_and_as_a_lock(self) -> None:
        content = _Kit.fc(self.PATH, "{nope")
        assert _Kit.adapter().parse_manifest(content).parse_error.startswith("invalid JSON")
        assert _Kit.adapter().parse_lockfile(content).parse_error.startswith("invalid JSON")

    def test_a_package_that_imports_build_files_is_a_build_hook_and_placeholders_are_not(
        self,
    ) -> None:
        text = (
            '{"targets": {"net8.0": {"Gen/1.0": {"build": {"build/Gen.targets": {}}},'
            ' "Empty/1.0": {"build": {"build/_._": {}}}, "Odd/1.0": "text"}, "other": "text"}}'
        )
        manifest = _Kit.adapter().parse_manifest(_Kit.fc(self.PATH, text))
        assert [(h.name, h.command) for h in manifest.hooks] == [
            ("Gen", "msbuild imports build/Gen.targets")
        ]


class TestConfigAndProps:
    def test_a_nuget_config_that_cannot_be_read_is_an_error(self) -> None:
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("NuGet.Config", "<configuration>"))
        assert manifest.parse_error.startswith("not a readable NuGet.Config")

    def test_a_conditional_property_group_is_not_guessed_and_an_unconditional_one_is_used(
        self,
    ) -> None:
        files = {
            "Directory.Build.props": _Kit.fc(
                "Directory.Build.props",
                "<Project><PropertyGroup Condition=\"'$(CI)' == 'true'\"><V>9.9</V></PropertyGroup>"
                "<PropertyGroup><V>1.0</V></PropertyGroup></Project>",
            ),
            "a/a.csproj": _Kit.fc(
                "a/a.csproj",
                '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
                '<PackageReference Include="X" Version="$(V)" /></ItemGroup></Project>',
            ),
        }
        manifest = _Kit.adapter().parse_in_tree(files["a/a.csproj"], files)
        assert [(d.name, d.spec) for d in manifest.dependencies] == [("X", "1.0")]

    def test_central_package_management_adds_each_global_reference_as_a_build_dependency(
        self,
    ) -> None:
        files = {
            "Directory.Packages.props": _Kit.fc(
                "Directory.Packages.props",
                "<Project><PropertyGroup><ManagePackageVersionsCentrally>true"
                "</ManagePackageVersionsCentrally></PropertyGroup><ItemGroup>"
                '<GlobalPackageReference Include="Analyzer" Version="2.0" />'
                '<PackageVersion Include="X" Version="1.0" /></ItemGroup></Project>',
            ),
            "a/a.csproj": _Kit.fc(
                "a/a.csproj",
                '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="X" /></ItemGroup></Project>',
            ),
        }
        manifest = _Kit.adapter().parse_in_tree(files["a/a.csproj"], files)
        globals_ = [d for d in manifest.dependencies if d.name == "Analyzer"]
        assert [(d.spec, d.scope) for d in globals_] == [("2.0", Scope.BUILD)]


class TestDocumentsThatAreNotTheirKind:
    def test_a_config_whose_root_is_not_configuration_is_refused(self) -> None:
        manifest = _Kit.adapter().parse_manifest(_Kit.fc("NuGet.Config", "<other/>"))
        assert manifest.parse_error == "not a NuGet <configuration>"

    def test_a_packages_config_whose_root_is_not_packages_is_refused_and_an_unnamed_package_skipped(
        self,
    ) -> None:
        refused = _Kit.adapter().parse_manifest(_Kit.fc("packages.config", "<other/>"))
        assert refused.parse_error == "not a <packages> document"
        text = '<packages><package version="1.0"/><package id="A" version="2.0"/></packages>'
        kept = _Kit.adapter().parse_manifest(_Kit.fc("packages.config", text))
        assert [(d.name, d.spec) for d in kept.dependencies] == [("A", "[2.0]")]


class TestLockFiles:
    def test_a_lock_without_a_dependencies_object_is_refused(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("packages.lock.json", '{"version": 1}'))
        assert graph.parse_error == "no `dependencies` object"

    def test_a_framework_or_package_that_is_not_an_object_is_skipped(self) -> None:
        text = (
            '{"version": 1, "dependencies": {"net8.0": {"A": {"type": "Direct", "resolved": "1.0.0"},'
            ' "B": "text"}, "net6.0": "text"}}'
        )
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("packages.lock.json", text))
        assert [e.name for e in graph.entries] == ["A"]

    def test_a_restore_file_skips_what_it_cannot_read_and_says_where_a_package_is_only_in_some_frameworks(
        self,
    ) -> None:
        text = (
            '{"targets": {"net8.0": {"Both/1.0": {}, "OnlyNew/2.0": {}, "/3.0": {}},'
            ' "net6.0": {"Both/1.0": {}}, "bad": "text"},'
            ' "libraries": {"Both/1.0": {}, "OnlyNew/2.0": {}, "/3.0": {}}}'
        )
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("obj/project.assets.json", text))
        by_name = {e.name: e for e in graph.entries}
        assert set(by_name) == {"Both", "OnlyNew"}
        assert "target framework net6.0" not in by_name["OnlyNew"].platform
        assert "target framework net8.0" in by_name["OnlyNew"].platform


class TestMoreNuGet:
    def test_a_floating_version_has_a_star(self) -> None:
        assert NuGetVersions.floating("1.*") is True
        assert NuGetVersions.floating("1.0") is False

    def test_a_props_file_that_cannot_be_read_is_ignored_for_the_project(self) -> None:
        files = {
            "Directory.Build.props": _Kit.fc("Directory.Build.props", "<Project>"),
            "a.csproj": _Kit.fc(
                "a.csproj",
                '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
                '<PackageReference Include="X" Version="1.0" /></ItemGroup></Project>',
            ),
        }
        manifest = _Kit.adapter().parse_in_tree(files["a.csproj"], files)
        assert [(d.name, d.spec) for d in manifest.dependencies] == [("X", "1.0")]

    def test_the_nearest_props_file_is_looked_for_only_so_far_up(self) -> None:
        deep = "/".join(["d"] * 70) + "/a.csproj"
        assert NuGetEcosystem._nearest(deep, "Directory.Build.props", {}) is None

    def test_an_item_that_is_not_a_package_reference_is_not_a_dependency(self) -> None:
        text = (
            '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageVersion Include="Z" Version="9" />'
            '<PackageReference Include="X" Version="1.0" /></ItemGroup></Project>'
        )
        content = _Kit.fc("a.csproj", text)
        manifest = _Kit.adapter().parse_in_tree(content, {"a.csproj": content})
        assert [d.name for d in manifest.dependencies] == ["X"]

    def test_central_management_with_no_version_for_a_package_says_so(self) -> None:
        files = {
            "Directory.Packages.props": _Kit.fc(
                "Directory.Packages.props",
                "<Project><PropertyGroup><ManagePackageVersionsCentrally>true"
                "</ManagePackageVersionsCentrally></PropertyGroup></Project>",
            ),
            "a/a.csproj": _Kit.fc(
                "a/a.csproj",
                '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
                '<PackageReference Include="Missing" /></ItemGroup></Project>',
            ),
        }
        manifest = _Kit.adapter().parse_in_tree(files["a/a.csproj"], files)
        [dependency] = manifest.dependencies
        assert "has no PackageVersion for it" in str(dependency.note)
