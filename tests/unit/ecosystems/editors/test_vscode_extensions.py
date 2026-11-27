"""Editor extensions as an ecosystem: the files that name them, read as the editor reads them."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.editors.vscode import ExtensionId, VsCodeEcosystem
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent


class Kit:
    @staticmethod
    def parsed(path: str, text: str):
        return VsCodeEcosystem().parse_manifest(FileContent.from_bytes(path, text.encode()))


class TestItIsARegisteredEcosystem:
    def test_the_registry_holds_it_and_finds_its_files(self) -> None:
        assert "vscode" in EcosystemRegistry.BY_ID
        for path in (
            ".vscode/extensions.json",
            ".devcontainer/devcontainer.json",
            ".devcontainer.json",
        ):
            assert EcosystemRegistry.manifest_ecosystem(path) == "vscode", path

    def test_a_package_json_stays_npms(self) -> None:
        assert EcosystemRegistry.manifest_ecosystem("package.json") == "npm"


class TestTheFilesThatNameExtensions:
    def test_recommendations_are_ids_with_no_version(self) -> None:
        text = '{\n  // what the team uses\n  "recommendations": ["ms-python.Python", "dbaeumer.vscode-eslint",],\n}'
        names = {d.name: d.spec for d in Kit.parsed(".vscode/extensions.json", text).dependencies}
        assert names == {"ms-python.python": "*", "dbaeumer.vscode-eslint": "*"}

    def test_a_devcontainer_pin_carries_its_version(self) -> None:
        text = '{"customizations": {"vscode": {"extensions": ["ms-python.python@2024.1.0", "golang.go"]}}}'
        names = {
            d.name: d.spec for d in Kit.parsed(".devcontainer/devcontainer.json", text).dependencies
        }
        assert names == {"ms-python.python": "2024.1.0", "golang.go": "*"}

    def test_the_older_top_level_list_is_read(self) -> None:
        names = [
            d.name for d in Kit.parsed(".devcontainer.json", '{"extensions": ["a.b"]}').dependencies
        ]
        assert names == ["a.b"]

    def test_a_vsixmanifest_names_the_extension_and_what_it_depends_on(self) -> None:
        text = (
            '<?xml version="1.0" encoding="utf-8"?><PackageManifest Version="2.0.0">'
            '<Metadata><Identity Language="en-US" Id="theme-dracula" Version="2.25.1" Publisher="dracula-theme"/>'
            '<Properties><Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="a.b,c.d"/>'
            '<Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="e.f"/>'
            '<Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.13.0"/></Properties></Metadata>'
            "</PackageManifest>"
        )
        manifest = Kit.parsed("extension.vsixmanifest", text)
        assert (manifest.name, manifest.version) == ("dracula-theme.theme-dracula", "2.25.1")
        assert sorted(d.name for d in manifest.dependencies) == ["a.b", "c.d", "e.f"]

    def test_a_file_that_is_not_json_is_a_parse_error(self) -> None:
        assert Kit.parsed(".vscode/extensions.json", "not json").parse_error

    def test_extensions_have_no_lock_file(self) -> None:
        graph = VsCodeEcosystem().parse_lockfile(FileContent.from_bytes("x", b""))
        assert graph.parse_error


class TestAnExtensionId:
    @pytest.mark.parametrize(
        ("value", "parsed"),
        [("Ms-Python.Python", ("ms-python.python", "")), ("a.b@1.2.3", ("a.b", "1.2.3"))],
    )
    def test_it_reads_as_the_editor_does(self, value: str, parsed: tuple[str, str]) -> None:
        assert ExtensionId.parse(value) == parsed

    @pytest.mark.parametrize(
        "value", ["", "nodot", "a.b.c", "a/b.c", "a b.c", "../x.y", 7, None, "x" * 300]
    )
    def test_anything_else_is_not_one(self, value: object) -> None:
        assert ExtensionId.parse(value) is None
