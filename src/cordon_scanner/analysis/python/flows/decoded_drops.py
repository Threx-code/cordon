"""A payload the file carries encoded, written out and then made runnable or run (group C).

Moved out of `ExecutionFlows` whole (its method limit); the join reuses its download helpers.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.execution_flows import ExecutionFlows
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES, PythonFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class DecodedDrops(ExecutionFlows):
    """`_decoded_dropped_and_run` and what it needs."""

    #: Capabilities whose call yields bytes the file carried hidden: what a dropper writes out.
    _DECODING: ClassVar[frozenset[Capability]] = frozenset(
        {Capability.DECODE, Capability.DECOMPRESS}
    )
    #: `stat` bits that let a file run.
    _EXEC_BITS: ClassVar[frozenset[str]] = frozenset(
        {"S_IXUSR", "S_IXGRP", "S_IXOTH", "S_IRWXU", "S_IRWXG", "S_IRWXO", "S_IEXEC"}
    )

    def _decoded_dropped_and_run(self, tree: ast.AST) -> None:
        """A payload the file carries encoded, written out and then made runnable or run.

        `p = b64decode(BLOB)`, `open(P, "wb").write(p)`, then `os.chmod(P, 0o777)` or
        `Popen([P])`: the same join as a download written and run (`_downloaded_and_run`), with
        the bytes decoded from the package instead of fetched (group C: data_harvester 0.3.1 and
        defi_tools 0.8.0 drop an agent from a 657 KB base64 module, make it executable and install
        a crontab line for it, at import). Decoding a resource and writing it is ordinary; making
        what was written executable, or starting it, is the dropper."""

        def decoding(part: ast.AST) -> bool:
            return (
                isinstance(part, ast.Call)
                and (resolved := self._resolve_callee(part)) is not None
                and PRIMITIVES.get(resolved[0]) in self._DECODING
            )

        decoded: set[str] = set()
        for _ in range(3):
            for node in PythonSyntax.of(tree, ast.Assign):
                if any(
                    (isinstance(part, ast.Name) and part.id in decoded) or decoding(part)
                    for part in PythonSyntax.within(node.value, ast.Name, ast.Call)
                ):
                    decoded.update(t.id for t in node.targets if isinstance(t, ast.Name))
        if not decoded and not any(decoding(n) for n in PythonSyntax.of(tree, ast.Call)):
            return
        writers: dict[str, str] = {}
        for node in PythonSyntax.of(tree, ast.Call):
            if self._dotted(node.func) == "open" and node.args:
                mode = PythonFacts.constant(node.args[1]) if len(node.args) > 1 else None
                key = self._file_key(node.args[0])
                if key and mode and ("w" in mode or "a" in mode):
                    writers[f"{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}"] = key
        dropped: set[str] = set()
        self._run_on_downloaded(tree, decoded, writers, dropped, decoding)
        if not dropped:
            return
        self._compiled_from(tree, dropped)
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None:
                continue
            call = resolved[1]
            if resolved[0] in ("os.chmod", "pathlib.Path.chmod") or (
                isinstance(node.func, ast.Attribute) and node.func.attr == "chmod"
            ):
                path = call.args[0] if resolved[0] == "os.chmod" and call.args else node.func
                path = path.value if isinstance(path, ast.Attribute) else path
                bits = (
                    call.args[1]
                    if resolved[0] == "os.chmod" and len(call.args) > 1
                    else (call.args[0] if call.args else None)
                )
                if self._file_key(path) in dropped and self._executable_mode(bits):
                    self._record(
                        Capability.FETCH_EXEC, node, f"{resolved[0]} makes a decoded file runnable"
                    )
            elif PRIMITIVES.get(resolved[0]) is Capability.SPAWN and call.args:
                if self._runs_one_of(call.args[0], dropped):
                    self._record(Capability.FETCH_EXEC, node, f"{resolved[0]} runs a decoded file")
            elif resolved[0].rsplit(".", 1)[-1] in self._MODULE_LOADERS and call.args:
                # `spec_from_file_location(name, P)`, `runpy.run_path(P)`, `SourceFileLoader(n, P)`:
                # the file is imported, so its top level runs (pyenvprep 1.0.0).
                place = call.args[-1] if len(call.args) > 1 else call.args[0]
                if self._file_key(self._unwrapped(place)) in dropped:
                    self._record(
                        Capability.FETCH_EXEC, node, f"{resolved[0]} runs a decoded file as code"
                    )

    #: Calls that import or run a file by its path.
    _MODULE_LOADERS: ClassVar[frozenset[str]] = frozenset(
        {"spec_from_file_location", "run_path", "SourceFileLoader", "SourcelessFileLoader"}
    )

    @staticmethod
    def _unwrapped(node: ast.AST) -> ast.AST:
        """`str(p)`, `os.fspath(p)`, `p.resolve()`: the path itself."""
        while isinstance(node, ast.Call):
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            if name in ("str", "fspath") and node.args:
                node = node.args[0]
            elif isinstance(node.func, ast.Attribute) and name in ("resolve", "absolute"):
                node = node.func.value
            else:
                break
        return node

    def _compiled_from(self, tree: ast.AST, dropped: set[str]) -> None:
        """A file compiled from a dropped one is dropped too: `py_compile.compile(str(src),
        cfile=str(pyc))` makes `pyc` the decoded source in another form."""
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or resolved[0] not in (
                "py_compile.compile",
                "compileall.compile_file",
            ):
                continue
            call = resolved[1]
            if not call.args or self._file_key(self._unwrapped(call.args[0])) not in dropped:
                continue
            target = next((k.value for k in call.keywords if k.arg == "cfile"), None)
            if target is None and len(call.args) > 1:
                target = call.args[1]
            key = self._file_key(self._unwrapped(target)) if target is not None else None
            if key:
                dropped.add(key)

    def _executable_mode(self, mode: ast.AST | None) -> bool:
        """A chmod mode that sets an execute bit: a number with 0o111 in it, or `stat` names that
        include one."""
        if isinstance(mode, ast.Constant) and isinstance(mode.value, int):
            return bool(mode.value & 0o111)
        if mode is None:
            return False
        names = {
            part.attr if isinstance(part, ast.Attribute) else part.id
            for part in PythonSyntax.within(mode, ast.Attribute, ast.Name)
            if isinstance(part, ast.Attribute | ast.Name)
        }
        return bool(names & self._EXEC_BITS)


__all__ = ["DecodedDrops"]
