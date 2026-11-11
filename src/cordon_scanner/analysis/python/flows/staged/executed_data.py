"""Data run as code: files dropped into a directory and executed from it, and bytes decoded and run.

scrapetools2 0.2.0's `downloader.py` fetches a tar, decrypts each line of a file in it, and writes
the results as files under a fixed directory (`run_update`); another function lists that directory
and runs `exec(compile(open(f"{dir}/{x}").read(), x, "exec"))` over every file (`run_modules`). No
single function both receives and runs, so no download-and-run pairing sees it, but the directory
joins the two: whatever is written there is run.

rasterkit_demo 0.1.0's `_apply_window(samples: bytes)` runs `exec(samples.decode(...))`, a thread
per "window", and the windows are bytes another package's module returns. Text decoded out of
bytes and executed is data run as code, whatever the bytes are called.

`dropped into a directory and executed: <call>`: a file written with content that is not a literal
to a path under a fixed directory, and, in the same file, exec/eval/compile of a file read from a
listing (`os.listdir`, `os.scandir`, `glob`, `Path.iterdir`/`glob`) of that directory.

`bytes decoded and executed: <call>`: exec/eval/compile of `<parameter>.decode(...)` in the
function the parameter belongs to (directly or through one binding there). A decoder's output
(`zlib.decompress`, `b64decode`) run as code is the decode-exec rules' (forensic-scan's fixture,
dbzy-tools' sandbox: the two benign units of the 1,063 the wider cut raised).
"""

from __future__ import annotations

import ast
from collections.abc import Callable
from typing import Any, ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PythonFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class ExecutedData(AnalyzerCore):
    """`_data_executed` and what it needs."""

    RUNNERS: ClassVar[frozenset[str]] = frozenset({"exec", "eval", "compile"})
    LISTINGS: ClassVar[frozenset[str]] = frozenset(
        {"os.listdir", "os.scandir", "glob.glob", "glob.iglob", "iterdir", "glob", "rglob"}
    )

    def _data_executed(self, tree: ast.AST) -> None:
        written = self._written_directories(tree)
        calls = list(PythonSyntax.of(tree, ast.Call))
        # `exec(compile(...))` is one run: the inner runner is the outer one's argument.
        inner = {
            id(a) for c in calls if (self._dotted(c.func) or "") in self.RUNNERS for a in c.args
        }
        for call in calls:
            runner = self._dotted(call.func) or ""
            if runner not in self.RUNNERS or not call.args or id(call) in inner:
                continue
            if self._listed_directories(tree, call) & written:
                self._record(
                    Capability.EXECUTE, call, f"dropped into a directory and executed: {runner}"
                )
            elif self._handed_bytes(tree, call):
                self._record(Capability.EXECUTE, call, f"bytes decoded and executed: {runner}")

    #: Where each kind of path expression keeps its literal head.
    _HEADS: ClassVar[dict[type, Callable[[Any], ast.AST | None]]] = {
        ast.JoinedStr: lambda p: p.values[0] if p.values else None,
        ast.BinOp: lambda p: p.left,
        ast.Call: lambda p: p.args[0] if len(p.args) > 1 else None,
        ast.Constant: lambda p: p,
    }

    @classmethod
    def _directory(cls, path: ast.AST) -> str | None:
        """The fixed directory a path names: the literal head of an f-string, join or `+`."""
        step = cls._HEADS.get(type(path))
        literal = step(path) if step is not None else None
        if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
            return None
        head = literal.value
        head = (
            head.rsplit("/", 1)[0] if "/" in head.rstrip("/") and not head.endswith("/") else head
        )
        return head.strip("/").strip("./") or None

    def _written_directories(self, tree: ast.AST) -> set[str]:
        """Directories files are written into with content that is not a literal."""
        found: set[str] = set()
        for node in PythonSyntax.of(tree, ast.With):
            for item in node.items:
                opened = item.context_expr
                if not (
                    isinstance(opened, ast.Call)
                    and (self._dotted(opened.func) or "") in ("open", "io.open")
                    and len(opened.args) > 1
                    and isinstance(opened.args[1], ast.Constant)
                    and any(m in str(opened.args[1].value) for m in "wa")
                    and isinstance(item.optional_vars, ast.Name)
                ):
                    continue
                handle = item.optional_vars.id
                directory = self._directory(opened.args[0])
                if directory is None:
                    continue
                for call in PythonSyntax.within(node, ast.Call):
                    if (
                        isinstance(call.func, ast.Attribute)
                        and call.func.attr == "write"
                        and isinstance(call.func.value, ast.Name)
                        and call.func.value.id == handle
                        and call.args
                        and PythonFacts.constant(call.args[0]) is None
                        and not isinstance(call.args[0], ast.Constant)
                    ):
                        found.add(directory)
        return found

    def _listed_directories(self, tree: ast.AST, runner: ast.Call) -> set[str]:
        """The directories whose listings a loop around the runner walks."""
        found: set[str] = set()
        loops = [
            loop
            for loop in PythonSyntax.of(tree, ast.For)
            if any(node is runner for node in PythonSyntax.within(loop, ast.Call))
        ]
        for loop in loops:
            iterator = loop.iter
            if not isinstance(iterator, ast.Call):
                continue
            name = self._dotted(iterator.func) or ""
            if name in self.LISTINGS or name.rsplit(".", 1)[-1] in self.LISTINGS:
                source = (
                    iterator.args[0] if iterator.args else getattr(iterator.func, "value", None)
                )
                if source is not None:
                    directory = self._directory(source)
                    if directory is not None:
                        found.add(directory)
        return found

    @staticmethod
    def _handed_bytes(tree: ast.AST, call: ast.Call) -> bool:
        """Whether the run text is `<parameter>.decode(...)` of the function the run sits in,
        directly or through one binding there: bytes a caller hands in, run as code
        (rasterkit_demo's `_apply_window(samples: bytes)`). A decoder's output
        (`zlib.decompress(...)`, `b64decode(...)`) is the decode-exec rules'."""
        for function in [
            *PythonSyntax.of(tree, ast.FunctionDef),
            *PythonSyntax.of(tree, ast.AsyncFunctionDef),
        ]:
            if not any(node is call for node in PythonSyntax.within(function, ast.Call)):
                continue
            args = function.args
            params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)} - {
                "self",
                "cls",
            }
            value = call.args[0]
            if isinstance(value, ast.Name):
                bound = [
                    a.value
                    for a in PythonSyntax.within(function, ast.Assign)
                    if len(a.targets) == 1
                    and isinstance(a.targets[0], ast.Name)
                    and a.targets[0].id == value.id
                ]
                if len(bound) != 1:
                    return False
                value = bound[0]
            return (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr == "decode"
                and isinstance(value.func.value, ast.Name)
                and value.func.value.id in params
            )
        return False


__all__ = ["ExecutedData"]
