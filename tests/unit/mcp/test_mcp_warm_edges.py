"""The warm scanner's reader and its helper process on the messages and exits that are rarely sent (`mcp/warm.py`)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.mcp.warm import LOST, WarmScanner

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="the warm scanner forks; Windows runs cold"
)


class _Fake:
    """Stands in for the helper's process: its stdout is the lines the reader will see."""

    def __init__(self, lines: list[str]) -> None:
        self.stdout = iter(lines)
        self.stdin = None


class TestReader:
    def scanner(self, lines: list[str]) -> WarmScanner:
        scanner = WarmScanner({})
        scanner._process = _Fake(lines)  # type: ignore[assignment]
        scanner._calls[1] = {
            "pid": None,
            "exit": None,
            "started": threading.Event(),
            "done": threading.Event(),
        }
        return scanner

    def test_lines_that_are_not_json_or_name_no_waiting_call_are_ignored(self) -> None:
        scanner = self.scanner(
            [
                "not json\n",
                json.dumps({"ready": True}) + "\n",
                json.dumps({"id": 9, "pid": 5}) + "\n",
            ]
        )
        scanner._read()
        assert scanner._ready.is_set()
        assert scanner._calls[1]["pid"] is None

    def test_a_pid_and_an_exit_are_recorded_for_the_call_that_asked(self) -> None:
        scanner = self.scanner(
            [json.dumps({"id": 1, "pid": 42}) + "\n", json.dumps({"id": 1, "exit": 3}) + "\n"]
        )
        scanner._read()
        assert scanner._calls[1]["pid"] == 42
        assert scanner.exit_code(1) == 3

    def test_when_the_helper_goes_every_waiting_call_is_released_as_lost(self) -> None:
        scanner = self.scanner([])
        scanner._read()
        assert scanner._dead.is_set()
        assert scanner.finished(1)
        assert scanner.exit_code(1) == LOST

    def test_a_call_cannot_be_submitted_when_the_helper_is_not_ready(self) -> None:
        with pytest.raises(OSError, match="not available"):
            WarmScanner({}).submit(["scan"], cwd=".", out="o", err="e")

    def test_ending_a_call_that_never_started_or_closing_a_helper_never_started_does_nothing(
        self,
    ) -> None:
        scanner = self.scanner([])
        scanner._calls[1]["started"].set()
        scanner.end(1)
        WarmScanner({}).close()


class TestHelperProcess:
    def run_helper(self, tmp_path: Path, requests: list[Any]) -> list[dict[str, Any]]:
        env = dict(os.environ)
        process = subprocess.Popen(  # our own interpreter and module
            [sys.executable, "-P", "-m", "cordon_scanner.mcp.warm"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=str(tmp_path),
            env=env,
            text=True,
        )
        data = "".join(
            (request if isinstance(request, str) else json.dumps(request)) + "\n"
            for request in requests
        )
        out, _ = process.communicate(input=data, timeout=600)
        return [json.loads(line) for line in out.splitlines() if line.strip()]

    def call(self, ident: int, tmp_path: Path, argv: list[Any]) -> dict[str, Any]:
        return {
            "id": ident,
            "argv": argv,
            "cwd": str(tmp_path),
            "out": str(tmp_path / f"out{ident}"),
            "err": str(tmp_path / f"err{ident}"),
        }

    def test_a_line_that_is_not_json_is_skipped_and_the_exits_of_a_clean_and_a_failing_call_are_reported(
        self, tmp_path: Path
    ) -> None:
        for name in ("out1", "err1", "out2", "err2"):
            (tmp_path / name).write_text("", encoding="utf-8")
        messages = self.run_helper(
            tmp_path,
            ["not json", self.call(1, tmp_path, ["--version"]), self.call(2, tmp_path, [5])],
        )
        assert messages[0] == {"ready": True}
        exits = {m["id"]: m["exit"] for m in messages if "exit" in m}
        assert exits[1] == 0
        assert exits[2] == LOST
