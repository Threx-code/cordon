"""An editor extension is unpacked and started by the editor, never installed by npm."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.secrets import SourcePaths

MANIFEST = {
    "name": "theme",
    "version": "1.0.0",
    "engines": {"vscode": "^1.90.0"},
    "main": "./out/extension.js",
    "scripts": {"postinstall": "node ./scripts/setup.js"},
}


class ExtensionKit:
    @staticmethod
    def rules(root: Path) -> set[str]:
        return {f.rule_id for f in Scanner().scan(root).findings}

    @staticmethod
    def vsix(path: Path) -> Path:
        with zipfile.ZipFile(path, "w") as package:
            package.writestr("extension/package.json", json.dumps(MANIFEST))
            package.writestr("extension/scripts/setup.js", "console.log('ready');\n")
            package.writestr("extension/out/extension.js", "exports.activate = () => {};\n")
        return path


class TestWhereAnExtensionIs:
    def test_a_vsix_member_and_an_installed_extension_are_extensions(self) -> None:
        assert SourcePaths.is_editor_extension("theme.vsix!extension/package.json")
        assert SourcePaths.is_editor_extension(
            "/home/a/.vscode/extensions/pub.theme-1.0.0/package.json"
        )
        assert SourcePaths.is_editor_extension(".cursor/extensions/pub.theme-1.0.0/out/x.js")

    def test_a_project_is_not(self) -> None:
        assert not SourcePaths.is_editor_extension("package.json")
        assert not SourcePaths.is_editor_extension("src/extensions/registry.ts")


class TestLifecycleScripts:
    def test_an_extensions_npm_scripts_are_not_install_scripts(self, tmp_path: Path) -> None:
        """npm never runs in a packaged extension: the postinstall cannot run on this machine."""
        ExtensionKit.vsix(tmp_path / "theme.vsix")
        assert "SUSPECT.INSTALL.SCRIPT.001" not in ExtensionKit.rules(tmp_path)

    def test_the_same_manifest_in_a_project_still_is(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(json.dumps(MANIFEST), encoding="utf-8")
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "setup.js").write_text("console.log('ready');\n", encoding="utf-8")
        assert "SUSPECT.INSTALL.SCRIPT.001" in ExtensionKit.rules(tmp_path)


class TestRecognisedInstallSteps:
    """What an install script may run without review: a native build, or a message."""

    def test_the_prebuilt_binary_loader_and_a_message_are_build_steps(self) -> None:
        from cordon_scanner.detect.manifest import ManifestScripts

        assert ManifestScripts._is_safe_lifecycle("node-gyp-build")
        assert ManifestScripts._is_safe_lifecycle("echo Installing native bindings")
        assert ManifestScripts._is_safe_lifecycle("node-gyp-build || echo optional build skipped")

    def test_an_echo_that_writes_or_runs_is_not(self) -> None:
        from cordon_scanner.detect.manifest import ManifestScripts

        assert not ManifestScripts._is_safe_lifecycle("echo x >> ~/.bashrc")
        assert not ManifestScripts._is_safe_lifecycle("echo $(curl -s https://example.invalid)")
        assert not ManifestScripts._is_safe_lifecycle("echo `id`")
        assert not ManifestScripts._is_safe_lifecycle("echo ok && node ./scripts/setup.js")
