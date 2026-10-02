"""The VS Code extension's manifest: its version, and the settings that keep a workspace from
choosing what it runs."""

from __future__ import annotations

import json
from pathlib import Path

from cordon_scanner.version import __version__

MANIFEST = json.loads(
    (Path(__file__).resolve().parents[2] / "editors" / "vscode" / "package.json").read_text("utf-8")
)


class TestVscodeExtension:
    """The tests of test_vscode_extension.py that stood alone."""

    def test_it_ships_with_the_package_version(self) -> None:
        assert MANIFEST["version"] == __version__

    def test_a_workspace_cannot_choose_the_executable(self) -> None:
        assert (
            MANIFEST["contributes"]["configuration"]["properties"]["cordon.path"]["scope"]
            == "machine"
        )

    def test_it_does_not_run_in_an_untrusted_workspace(self) -> None:
        assert MANIFEST["capabilities"]["untrustedWorkspaces"]["supported"] is False

    def test_it_has_no_runtime_dependencies(self) -> None:
        assert "dependencies" not in MANIFEST
