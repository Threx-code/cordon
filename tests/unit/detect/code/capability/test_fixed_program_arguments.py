"""A spawn of a program whose arguments are data does not stand for "something unknown runs" in the
co-occurrence composites (note 44, release item 44): `taskkill` with a pid beside a fetch is a CLI
stopping its own child, while the same fetch beside `node` with a variable still is a dropper's pair.
Inert fixtures: the fetch is to a placeholder host and nothing runs."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config

#: What reads a spawn beside a fetch and a decode as "something unknown runs".
RULES = {"SUSPECT.DROPPER.001", "MALWARE.DROPPER.001", "SUSPECT.DECODE_EXEC.001"}


class FixedProgramKit:
    HEAD = (
        'const cp = require("child_process");\n'
        "async function go(child, script) {\n"
        '  const r = await fetch("https://h.invalid/v");\n'
        "  const body = await r.text();\n"
        '  const note = Buffer.from(body, "base64").toString();\n'
    )

    @staticmethod
    def rules(tmp_path: Path, spawn: str) -> set[str]:
        (tmp_path / "cli.js").write_text(
            FixedProgramKit.HEAD + "  " + spawn + "\n  return note;\n}\nmodule.exports = go;\n",
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(tmp_path)
        return {f.rule_id for f in result.findings}


class TestTheCoOccurrenceComposites:
    def test_taskkill_with_a_pid_is_not_a_dropper(self, tmp_path) -> None:
        spawn = 'cp.spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true });'
        assert not RULES & FixedProgramKit.rules(tmp_path, spawn)

    @pytest.mark.parametrize(
        "spawn",
        [
            'cp.spawnSync("node", [script]);',
            'cp.spawnSync("tar", ["xf", script, "-C", "out"]);',
            "cp.execSync(`taskkill /PID ${child.pid}`);",
        ],
    )
    def test_a_runner_or_an_unguarded_argument_still_is(self, tmp_path, spawn: str) -> None:
        assert RULES & FixedProgramKit.rules(tmp_path, spawn)
