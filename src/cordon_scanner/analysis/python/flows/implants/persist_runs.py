"""A file that registers itself to run again and runs something it brings, in one place.

An implant installs its payload and arranges for it to start again: it downloads or decodes a program,
runs it, and writes the Run key, the scheduled task, the LaunchAgent or the
crontab line that starts it next time. The three facts in one file mean little (a library with a
scheduler and a downloader); in one function, or one function and the helpers it calls, they are one
act. This module relates the lines: a persistence write (`py_persist.py`) and a run of something the
package downloaded or decoded (the analyser's own facts) that sit in the same function, or one
helper hop from each other.

`lines` returns the line of each persistence write that has such a run beside it.
"""

from __future__ import annotations

import ast
import re
from typing import Final

from cordon_scanner.analysis.python.py_persist import PythonPersistence

#: The analyser's details for a run of a program the package got by download or decoding. A program
#: the package ships is not here: 8% of the benign long tail runs one (a wrapper for its own binary).
RUN_DETAILS: Final = ("runs a downloaded", "runs a decoded file", "makes a decoded file runnable")


#: The places a program is registered to start by itself: what `autostart hidden` reads. A shell profile
#: or a service enabled is persistence, but not the registration of a program the user would see.
AUTOSTART_WORD: Final = re.compile(
    r"(?i)currentversion|launchagents|launchdaemons|\.config/autostart|schtasks|launchctl|crontab|/etc/cron"
    r"|@reboot|\bsc(?:\.exe)?\W{1,8}create|start[ _]menu|shell:startup|systemctl|wantedby"
)


class PersistRuns:
    """The persistence writes with a brought program's run beside them."""

    @classmethod
    def lines(
        cls,
        tree: ast.AST,
        run_lines: frozenset[int],
        source: str | None = None,
        only: re.Pattern[str] | None = None,
    ) -> list[int]:
        """`only` narrows which persistence writes count: those whose function (or the module, at
        module level) names a place that pattern matches, in `source`."""
        if not run_lines or not isinstance(tree, ast.Module):
            return []
        written = PythonPersistence.written_lines(tree)
        if written and only is not None and source is not None:
            written = frozenset(line for line in written if only.search(cls._scope_text(tree, source, line)))
        if not written:
            return []
        functions = {
            n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        calls = {name: cls._called(fn.body, functions) for name, fn in functions.items()}
        callers: dict[str, set[str]] = {}
        for name, called in calls.items():
            for target in called:
                callers.setdefault(target, set()).add(name)
        spans = {name: (fn.lineno, fn.end_lineno or fn.lineno) for name, fn in functions.items()}

        def inside(line: int) -> str | None:
            best = None
            for name, (start, end) in spans.items():
                if start <= line <= end and (best is None or start >= spans[best][0]):
                    best = name
            return best

        top_calls = cls._called(tree.body, functions)
        out: list[int] = []
        for line in sorted(written):
            where = inside(line)
            near: set[str | None] = {where}
            if where is not None:
                near |= set(calls.get(where, ())) | callers.get(where, set())
                # a sibling the same caller starts: `install()` calls both `plant()` and `persist()`
                for parent in callers.get(where, ()):
                    near |= set(calls.get(parent, ()))
            else:
                near |= top_calls
            if any(inside(run) in near for run in run_lines):
                out.append(line)
        return out

    @staticmethod
    def _scope_text(tree: ast.Module, source: str, line: int) -> str:
        """The text of the innermost function holding `line`, or of the whole module."""
        best: ast.AST | None = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.lineno <= line <= (node.end_lineno or node.lineno):
                if best is None or node.lineno >= best.lineno:  # type: ignore[attr-defined]
                    best = node
        if best is None:
            return source
        lines = source.splitlines()
        return "\n".join(lines[best.lineno - 1 : best.end_lineno])  # type: ignore[attr-defined]

    @classmethod
    def _called(cls, body: list[ast.stmt], functions: dict[str, ast.AST]) -> set[str]:
        out: set[str] = set()
        stack: list[ast.AST] = list(body)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
                if name in functions:
                    out.add(name)
            stack.extend(ast.iter_child_nodes(node))
        return out


__all__ = ["RUN_DETAILS", "PersistRuns"]
