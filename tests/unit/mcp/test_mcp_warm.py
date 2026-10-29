"""The MCP server's warm scanner: faster calls, the same results and the same limits as cold."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from cordon_scanner.mcp.runner import Cancelled, CancelToken, Runner, TimedOut

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="the warm scanner forks; Windows runs cold"
)


class WarmKit:
    @staticmethod
    def project(tmp_path: Path) -> Path:
        root = tmp_path / "project"
        root.mkdir()
        (root / "package.json").write_text(
            json.dumps({"name": "x", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}}),
            encoding="utf-8",
        )
        return root

    @staticmethod
    def runner(**environment: str) -> Runner:
        env = dict(os.environ)
        env.update(environment)
        return Runner(offline=True, environment=env)

    @staticmethod
    def ready(runner: Runner, seconds: float = 600) -> None:
        """Wait until the helper is ready. Polled against a generous deadline, since a loaded
        machine slows the helper's start; a helper that exited fails at once instead."""
        runner.start_warm()
        deadline = time.monotonic() + seconds
        while not (runner.warm and runner.warm.ready):
            warm = runner.warm
            process = warm._process if warm is not None else None
            dead = warm is not None and (
                warm._dead.is_set() or (process is not None and process.poll() is not None)
            )
            assert not dead, "the warm helper exited before it was ready"
            assert time.monotonic() < deadline, "the warm scanner never became ready"
            time.sleep(0.1)

    @staticmethod
    def best(runner: Runner, args: list[str], runs: int) -> float:
        """The fastest of `runs` calls, in wall-clock seconds."""
        fastest = float("inf")
        for _ in range(runs):
            started = time.monotonic()
            runner.run(args, timeout=120, token=CancelToken())
            fastest = min(fastest, time.monotonic() - started)
        return fastest

    @staticmethod
    def findings(stdout: str) -> list[tuple[str, str]]:
        return sorted(
            (f["rule_id"], f["location"].get("path", "")) for f in json.loads(stdout)["findings"]
        )

    @staticmethod
    def alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True


class TestWarmScanner:
    ARGS = ("scan", "{root}", "--offline", "--format", "json")

    def args(self, root: Path) -> list[str]:
        return [a.format(root=root) for a in self.ARGS]

    def test_a_warm_call_reports_exactly_what_a_cold_one_does(self, tmp_path):
        root = WarmKit.project(tmp_path)
        cold = WarmKit.runner(CORDON_MCP_WARM="off")
        warm = WarmKit.runner()
        try:
            cold.start_warm()
            assert cold.warm is None
            WarmKit.ready(warm)
            a = cold.run(self.args(root), timeout=120, token=CancelToken())
            b = warm.run(self.args(root), timeout=120, token=CancelToken())
        finally:
            warm.close()
        assert a.exit_code == b.exit_code
        assert WarmKit.findings(a.stdout) == WarmKit.findings(b.stdout)

    def test_a_warm_call_is_faster(self, tmp_path):
        root = WarmKit.project(tmp_path)
        runner = WarmKit.runner()
        try:
            WarmKit.ready(runner)
            runner.run(self.args(root), timeout=120, token=CancelToken())
            warm_seconds = WarmKit.best(runner, self.args(root), runs=3)
        finally:
            runner.close()
        # Best of several each: the calls run in child processes, which process_time cannot see,
        # and a single wall-clock pair on a loaded machine measured the machine, not the helper.
        cold_seconds = WarmKit.best(WarmKit.runner(CORDON_MCP_WARM="off"), self.args(root), runs=2)
        assert warm_seconds < cold_seconds, f"warm {warm_seconds:.2f}s, cold {cold_seconds:.2f}s"

    def test_the_deadline_ends_the_child(self, tmp_path):
        root = WarmKit.project(tmp_path)
        runner = WarmKit.runner()
        try:
            WarmKit.ready(runner)
            token = CancelToken()
            with pytest.raises(TimedOut):
                runner.run(self.args(root), timeout=0.001, token=token)
            assert runner.warm is not None and runner.warm._calls == {}
        finally:
            runner.close()

    def test_a_cancelled_call_ends_its_child(self, tmp_path):
        root = WarmKit.project(tmp_path)
        runner = WarmKit.runner()
        try:
            WarmKit.ready(runner)
            token = CancelToken()
            token.cancel()
            with pytest.raises(Cancelled):
                runner.run(self.args(root), timeout=120, token=token)
            assert runner.warm is not None and runner.warm._calls == {}
        finally:
            runner.close()

    def test_a_dead_helper_means_cold_calls_not_failures(self, tmp_path):
        root = WarmKit.project(tmp_path)
        runner = WarmKit.runner()
        try:
            WarmKit.ready(runner)
            assert runner.warm is not None and runner.warm._process is not None
            runner.warm._process.kill()
            deadline = time.monotonic() + 10
            while runner.warm.ready:
                assert time.monotonic() < deadline
                time.sleep(0.05)
            result = runner.run(self.args(root), timeout=120, token=CancelToken())
        finally:
            runner.close()
        assert result.exit_code in (0, 1)
        assert "findings" in json.loads(result.stdout)

    def test_closing_the_server_ends_the_helper(self):
        runner = WarmKit.runner()
        WarmKit.ready(runner)
        assert runner.warm is not None and runner.warm._process is not None
        process = runner.warm._process
        runner.close()
        pid = process.pid
        assert not WarmKit.alive(pid)
