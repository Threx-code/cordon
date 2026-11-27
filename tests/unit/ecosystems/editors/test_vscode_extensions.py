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

    def test_an_excluded_extension_is_not_a_dependency(self) -> None:
        text = '{"customizations": {"vscode": {"extensions": ["-ms-python.python", "golang.go"]}}}'
        names = [d.name for d in Kit.parsed(".devcontainer/devcontainer.json", text).dependencies]
        assert names == ["golang.go"]

    def test_unwanted_recommendations_are_not_dependencies(self) -> None:
        text = '{"recommendations": ["a.b"], "unwantedRecommendations": ["c.d"]}'
        assert [d.name for d in Kit.parsed(".vscode/extensions.json", text).dependencies] == ["a.b"]

    def test_a_named_devcontainer_configuration_is_found(self) -> None:
        for path in (".devcontainer/python/devcontainer.json", "app.code-workspace", ".gitpod.yml"):
            assert EcosystemRegistry.manifest_ecosystem(path) == "vscode", path

    def test_a_multi_root_workspace_recommends_extensions(self) -> None:
        text = '{"folders": [{"path": "."}], "extensions": {"recommendations": ["Rust-Lang.rust-analyzer"]}}'
        names = [d.name for d in Kit.parsed("app.code-workspace", text).dependencies]
        assert names == ["rust-lang.rust-analyzer"]

    def test_a_gitpod_configuration_names_ids_pins_and_archives(self) -> None:
        text = (
            "image: gitpod/workspace-full\nvscode:\n  extensions:\n    - svelte.svelte-vscode\n"
            "    - bradlc.vscode-tailwindcss@0.6.11\n"
            "    - https://example.com/releases/download/v1/acme-tools.vsix\n"
        )
        found = {d.name: (d.spec, d.source) for d in Kit.parsed(".gitpod.yml", text).dependencies}
        assert found == {
            "svelte.svelte-vscode": ("*", None),
            "bradlc.vscode-tailwindcss": ("0.6.11", None),
            "acme-tools": ("*", "https://example.com/releases/download/v1/acme-tools.vsix"),
        }

    @pytest.mark.parametrize(
        "url", ["http://example.com/a.vsix", "https://example.com/a.zip", "file:///tmp/a.vsix"]
    )
    def test_only_an_https_vsix_is_an_archive(self, url: str) -> None:
        text = f"vscode:\n  extensions:\n    - {url}\n"
        assert not Kit.parsed(".gitpod.yml", text).dependencies

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


class TestWhatTheEditorRuns:
    """An extension's activation entry runs as an install hook's does: the editor starts it, unasked, on every
    start. Its bundled manifests' lifecycle scripts do not run: no package manager runs inside an extension."""

    ROOT = "acme.tool-1.0.0.vsix!extension/"

    @staticmethod
    def unit(path: str, text: str):
        from cordon_scanner.detect.base import FileUnit

        return FileUnit(content=FileContent.from_bytes(path, text.encode()))

    @pytest.mark.conformance("vscode", "UNI-18")
    def test_the_activation_entry_is_the_hook_and_bundled_scripts_are_not(self) -> None:
        from cordon_scanner.engine.pipeline.hooks import Hooks

        root = self.ROOT
        setup = root + "node_modules/lib/setup.js"
        units = [
            self.unit(
                root + "package.json",
                '{"name": "tool", "publisher": "acme", "engines": {"vscode": "^1.80.0"}, '
                '"main": "./dist/extension"}',
            ),
            self.unit(root + "dist/extension.js", "exports.activate = () => {};"),
            self.unit(
                root + "node_modules/lib/package.json",
                '{"name": "lib", "scripts": {"postinstall": "node setup.js"}}',
            ),
            self.unit(setup, "1;"),
        ]
        hooks, entries, _ = Hooks.outside_extensions(units, {setup}, frozenset({setup}), set())
        assert hooks == {root + "dist/extension.js"}
        assert entries == frozenset({root + "dist/extension.js"})

    def test_a_manifest_that_is_not_an_extensions_names_no_entry(self) -> None:
        from cordon_scanner.engine.pipeline.hooks import Hooks

        units = [
            self.unit(self.ROOT + "package.json", '{"name": "tool", "main": "./dist/extension"}'),
            self.unit(self.ROOT + "dist/extension.js", "1;"),
        ]
        assert Hooks.extension_entries(units) == set()
