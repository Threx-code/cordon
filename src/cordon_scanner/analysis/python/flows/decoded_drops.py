"""A payload the file carries encoded, written out and then made runnable or run (group C).

Moved out of `ExecutionFlows` whole (its method limit); the join reuses its download helpers.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.execution_flows import ExecutionFlows
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES, PythonFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.scoped_taint import BindingForms
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
        what was written executable, or starting it, is the dropper.

        Only what the file carries: a decode of a function's parameter decodes what a caller hands
        it (bee-mesh 1.0.0's batch worker runs the executable a task sends, by design), which is
        received data, not a payload in the package."""
        received = self._parameter_reads(tree, self._carried_calls)

        def decoding(part: ast.AST) -> bool:
            return (
                isinstance(part, ast.Call)
                and id(part) not in received
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

    @classmethod
    def _parameter_reads(
        cls, tree: ast.AST, carried_calls: dict[str, set[int]] | None = None
    ) -> set[int]:
        """Calls whose arguments read a received parameter of the function that makes them, by
        node id: what a caller hands in, not what the file carries. A parameter is received only
        when no call of the function in this file passes it a carried value (a literal, a module
        name or attribute, a decode of one, a file read): `def drop(blob): ...` called as
        `drop(BLOB)` drops a carried payload (the lead, 11-11). A function nothing here calls (a
        framework's handler) has none. Direct reads only, the innermost function's parameters."""
        found: set[int] = set()
        module_names = cls._module_bound_names(tree)
        functions = list(PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef))
        for function in functions:
            arguments = function.args
            ordered = [
                a.arg
                for a in (*arguments.posonlyargs, *arguments.args)
                if a.arg not in ("self", "cls")
            ]
            params = set(ordered) | {a.arg for a in arguments.kwonlyargs}
            params |= {a.arg for a in (arguments.vararg, arguments.kwarg) if a is not None}
            params -= cls._carried_parameters(tree, function.name, ordered, module_names)
            # And the positions another file of the package passes carried (`CarriedCalls`).
            params -= {
                ordered[i]
                for i in (carried_calls or {}).get(function.name, set())
                if i < len(ordered)
            }
            if not params:
                continue
            # And what the function derives from them (`payload = task["blob"]`), to a fixed point.
            for _ in range(4):
                grown = set(params)
                for node in PythonSyntax.within(function, ast.Assign):
                    if any(
                        isinstance(n, ast.Name) and n.id in params
                        for n in PythonSyntax.nodes(node.value)
                    ):
                        grown.update(name for t in node.targets for name in BindingForms.names(t))
                if grown == params:
                    break
                params = grown
            for call in PythonSyntax.within(function, ast.Call):
                inputs = [*call.args, *(k.value for k in call.keywords)]
                if any(
                    isinstance(n, ast.Name) and n.id in params
                    for a in inputs
                    for n in PythonSyntax.nodes(a)
                ):
                    found.add(id(call))
        return found

    @staticmethod
    def _module_bound_names(tree: ast.AST) -> frozenset[str]:
        """Names the module binds at its top level (constants, imports, module objects)."""
        if not isinstance(tree, ast.Module):
            return frozenset()
        names: set[str] = set()
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                names.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                names.add(stmt.target.id)
            elif isinstance(stmt, ast.Import | ast.ImportFrom):
                names.update((a.asname or a.name).split(".")[0] for a in stmt.names)
        return frozenset(names)

    @classmethod
    def _carried_parameters(
        cls, tree: ast.AST, name: str, ordered: list[str], module_names: frozenset[str]
    ) -> set[str]:
        """The parameters some call of `name` in this file passes a carried value."""
        carried: set[str] = set()
        for call in PythonSyntax.of(tree, ast.Call):
            func = call.func
            called = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if called != name:
                continue
            for position, argument in enumerate(call.args):
                if position < len(ordered) and cls._carried(argument, module_names):
                    carried.add(ordered[position])
            carried.update(
                k.arg for k in call.keywords if k.arg and cls._carried(k.value, module_names)
            )
        return carried

    @staticmethod
    def _carried(node: ast.AST, module_names: frozenset[str]) -> bool:
        """A value the package carries: a literal, a module-level name or attribute of one, a
        call over only those (a decode of a blob), or a file read."""
        if isinstance(node, ast.Constant):
            return isinstance(node.value, str | bytes)
        names = [n for n in PythonSyntax.nodes(node) if isinstance(n, ast.Name)]
        if any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr in ("read", "read_bytes", "read_text")
            for n in PythonSyntax.nodes(node)
        ):
            return True
        return bool(names) and all(n.id in module_names for n in names)

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
