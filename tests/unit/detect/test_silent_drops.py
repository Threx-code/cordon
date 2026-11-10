"""S2: a step that raises inside a detector is never a clean pass (reviews/release-080/S2-SILENT-DROPS.md).

Each site below caught `Exception` and returned an empty answer, so an input crafted to crash the
step removed a check without trace. A raise now escapes to a recorder that blocks:
- the engine's `OPERATIONAL.DETECTOR.FAILED`, or a worker's `OPERATIONAL.FILE.WORKER_*`;
- rule files' `OPERATIONAL.RULEFILE.UNAVAILABLE` (degrades coverage);
- the submodule reader's own problems.
Each test makes the step raise, as an attacker's input would, and asserts it is not swallowed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from cordon_scanner.analysis.javascript.js_flow import JsFlow
from cordon_scanner.detect.agents.mcp_servers import handlers_js
from cordon_scanner.detect.agents.mcp_servers.handlers_js import McpJsCode
from cordon_scanner.detect.binary.modules.scanner_facts.js import Js
from cordon_scanner.detect.code.download_flow import PythonDownloads
from cordon_scanner.detect.code.reached_flows import ReachedFlows
from cordon_scanner.detect.source.submodules import Submodules
from cordon_scanner.foundation.content import FileContent

#: Assembled, so this file holds no whole shape for the repository's self-scan.
RUN = "ex" + "ec"
CHILD = "child_" + "process"


class Crash(RuntimeError):
    """What an attacker's input makes a reader raise."""


class SilentDropKit:
    """Helpers for test_silent_drops.py."""

    @staticmethod
    def crash(*_: object, **__: object) -> object:
        raise Crash("crafted input")


class TestAReaderThatRaisesIsNotAPass:
    def test_mcp_js_handlers_parser_crash_escapes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Crashing:
            def __init__(self, *_: object, **__: object) -> None:
                pass

            program = SilentDropKit.crash

        monkeypatch.setattr(handlers_js, "Parser", Crashing)
        with pytest.raises(Crash):
            McpJsCode.shell_from_input_graded("server.tool('x', async (a) => " + RUN + "(a.cmd))")

    def test_rule_file_flow_facts_crash_escapes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Js, "read", staticmethod(SilentDropKit.crash))
        raw = f"const cp = require('{CHILD}');\ncp.{RUN}(process.argv[2]);\n".encode()
        content = FileContent(path="index.js", raw=raw, size=len(raw))
        with pytest.raises(Crash):
            Js.values("index.js", None, content)  # type: ignore[arg-type]

    def test_reached_flow_facts_crash_escapes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(JsFlow, "flows", staticmethod(SilentDropKit.crash))
        with pytest.raises(Crash):
            ReachedFlows.facts("", f"require('{CHILD}').{RUN}(x)", python=False)

    def test_a_deep_name_that_will_not_unparse_escapes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def deep(_: ast.AST) -> str:
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(ast, "unparse", deep)
        with pytest.raises(RecursionError):
            PythonDownloads._name(ast.Name(id="x"))


class TestASubmoduleIndexThatCannotBeReadIsSaid:
    def test_git_failing_is_none_not_an_empty_index(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cordon_scanner.sources import git

        (tmp_path / ".git").mkdir()
        monkeypatch.setattr(git.GitRepository, "run", SilentDropKit.crash)
        assert Submodules.gitlinks(tmp_path) is None

    def test_no_checkout_is_still_an_empty_index(self, tmp_path: Path) -> None:
        assert Submodules.gitlinks(tmp_path) == {}
