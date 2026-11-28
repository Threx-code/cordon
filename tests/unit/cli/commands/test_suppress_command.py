"""`suppress list | add | prune` through the command's own entry point: where the file is found, and what each action prints (`cli/commands/suppressions.py`)."""

from __future__ import annotations

import argparse
import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cli.commands.suppressions import (
    SuppressCommand,
    SuppressionFile,
    SuppressionRules,
)
from cordon_scanner.foundation.errors import ExitCode

TODAY = date(2026, 11, 28)
WHY = "the script is the vendor's own installer and runs only in our build image"
FILE = (
    "version: 1\n"
    "suppressions:\n"
    "  - rule: SUSPECT.SPAWN.001\n"
    "    path: scripts/old.mjs\n"
    f'    justification: "{WHY}"\n'
    '    expires: "2020-01-01"\n'
    '    approved_by: "sec-team"\n'
    "  - rule: SUSPECT.DROPPER.001\n"
    "    path: scripts/fetch.sh\n"
    f'    justification: "{WHY}"\n'
    '    expires: "2027-03-01"\n'
)


class _Base:
    @staticmethod
    def run(action: str, root: Path, **over: Any) -> int:
        base: dict[str, Any] = {
            "root": str(root),
            "config": None,
            "policy": None,
            "format": "text",
            "dry_run": False,
        }
        return SuppressCommand.run(
            argparse.Namespace(suppress_command=action, **{**base, **over}), today=TODAY
        )

    @staticmethod
    def write(root: Path, name: str = "cordon.yaml", text: str = FILE) -> Path:
        path = root / name
        path.write_text(text, encoding="utf-8")
        return path


class TestLocate(_Base):
    def test_an_explicit_file_is_used_wherever_it_is(self, tmp_path: Path) -> None:
        path = self.write(tmp_path, "elsewhere.yaml")
        assert SuppressionFile.locate(tmp_path, str(path)).path == path

    def test_the_first_known_file_name_in_the_root_is_found(self, tmp_path: Path) -> None:
        found = SuppressionFile.locate(tmp_path, None)
        assert found.path.parent == tmp_path
        path = self.write(tmp_path)
        assert SuppressionFile.locate(tmp_path, None).path == path

    def test_with_no_file_the_default_name_is_where_an_add_would_write(
        self, tmp_path: Path
    ) -> None:
        assert SuppressionFile.locate(tmp_path, None).suppressions() == ()


class TestList(_Base):
    def test_text_names_each_entry_its_state_and_who_approved_it(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self.write(tmp_path)
        assert self.run("list", tmp_path) == int(ExitCode.CLEAN)
        out = capsys.readouterr().out
        assert "2 suppression(s) in" in out
        assert "[0] EXPIRED  SUSPECT.SPAWN.001  scripts/old.mjs" in out
        assert "approved by sec-team" in out
        assert "[1] ACTIVE   SUSPECT.DROPPER.001  scripts/fetch.sh" in out

    def test_a_file_with_none_says_so(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self.write(tmp_path, text="version: 1\n")
        assert self.run("list", tmp_path) == int(ExitCode.CLEAN)
        assert "no suppressions in" in capsys.readouterr().out

    def test_json_carries_the_file_and_each_entry(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = self.write(tmp_path)
        assert self.run("list", tmp_path, format="json") == int(ExitCode.CLEAN)
        data = json.loads(capsys.readouterr().out)
        assert data["file"] == str(path)
        assert [s["rule"] for s in data["suppressions"]] == [
            "SUSPECT.SPAWN.001",
            "SUSPECT.DROPPER.001",
        ]

    def test_an_organisation_policy_is_read_for_the_rules_it_sets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        policy = self.write(
            tmp_path,
            "policy.yaml",
            "version: 1\nname: p\nsuppressions:\n  max_duration_days: 30\n",
        )
        loaded = SuppressionRules.load(str(policy))
        assert loaded.constraints.max_suppression_days == 30


class TestPrune(_Base):
    def test_nothing_expired_is_said_and_the_file_is_left_alone(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        text = FILE.replace("2020-01-01", "2027-01-01")
        path = self.write(tmp_path, text=text)
        assert self.run("prune", tmp_path) == int(ExitCode.CLEAN)
        assert "nothing to prune in" in capsys.readouterr().out
        assert path.read_text(encoding="utf-8") == text

    def test_dropping_nothing_returns_the_text_unchanged(self, tmp_path: Path) -> None:
        path = self.write(tmp_path)
        file = SuppressionFile(path)
        assert file.without(set()) == FILE
