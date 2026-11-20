"""A dependency whose name mixes Latin letters with Cyrillic or Greek ones is reported whatever it imitates."""

from __future__ import annotations

import json
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

RULE = "SUSPECT.DEPENDENCY.TYPOSQUAT.001"
CYRILLIC_O = chr(0x043E)


class MixedScriptKit:
    @staticmethod
    def findings(target: Path) -> list:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(target)
        return [f for f in result.findings if f.rule_id == RULE]

    @staticmethod
    def go_mod(tmp_path: Path, module: str) -> Path:
        (tmp_path / "go.mod").write_text(
            f"module example.invalid/notes\n\ngo 1.22\n\nrequire (\n\t{module} v0.32.0\n)\n",
            encoding="utf-8",
        )
        return tmp_path

    @staticmethod
    def package_json(tmp_path: Path, name: str) -> Path:
        manifest = {"name": "notes", "version": "1.0.0", "dependencies": {name: "^1.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        return tmp_path


class TestMixedScriptDependency:
    def test_a_go_module_with_a_cyrillic_letter_is_high(self, tmp_path: Path) -> None:
        found = MixedScriptKit.findings(
            MixedScriptKit.go_mod(tmp_path, f"github.com/mark3labs/mcp-g{CYRILLIC_O}")
        )
        assert [(f.severity.name, f.confidence.name) for f in found] == [("HIGH", "HIGH")]

    def test_an_npm_name_no_list_knows_is_still_reported(self, tmp_path: Path) -> None:
        found = MixedScriptKit.findings(
            MixedScriptKit.package_json(tmp_path, f"n{CYRILLIC_O}tes-core-helper")
        )
        assert [f.severity.name for f in found] == ["HIGH"]

    def test_a_name_wholly_in_another_script_is_not_this(self, tmp_path: Path) -> None:
        assert not MixedScriptKit.findings(MixedScriptKit.package_json(tmp_path, "заметки"))

    def test_an_unknown_ascii_name_is_not_this(self, tmp_path: Path) -> None:
        assert not MixedScriptKit.findings(
            MixedScriptKit.package_json(tmp_path, "notes-core-helper")
        )
