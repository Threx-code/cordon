"""A program the file carries as plain source, written out and started in the background with its
output thrown away (fresh 11-12: qzc690382 and qzc690385 1.0.0).

Their setup.py holds a server as a string literal, writes it to a file with a made-up extension and
starts it with `subprocess.Popen(..., start_new_session=True, stdout=DEVNULL, stderr=DEVNULL)` at
install: the decoded drop (`DecodedDrops`) without the decode. Writing a template that parses as
Python is ordinary (a `_version.py`, a launcher), and so is starting a helper; a carried program
written and then started detached from the installer, with nothing it prints ever seen, is a
process left running on the machine that the person installing never asked for.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.execution_flows import ExecutionFlows
from cordon_scanner.analysis.python.flows.hidden_start import HiddenStart
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES, PythonFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class CarriedPrograms(ExecutionFlows):
    """`_carried_program_started` and what it needs."""

    #: A literal is a program when it parses as Python into at least this many statements...
    STATEMENTS: ClassVar[int] = 3
    #: ...and is at least this long: a one-line template is not a server.
    LENGTH: ClassVar[int] = 200
    #: Keyword values that start a process outside the starter's session.
    DETACHING: ClassVar[frozenset[str]] = frozenset({"setsid", "setpgrp"})

    def _carried_program_started(self, tree: ast.AST) -> None:
        """A carried program written to a file, then started detached with its output discarded."""
        if not getattr(self, "_follow_literals", True):
            return
        programs = self._program_names(tree)
        if not programs:
            return
        writers: dict[str, str] = {}
        for node in PythonSyntax.of(tree, ast.Call):
            if self._dotted(node.func) == "open" and len(node.args) > 1:
                mode = PythonFacts.constant(node.args[1])
                key = self._file_key(node.args[0])
                if key and mode and ("w" in mode or "a" in mode):
                    writers[f"{getattr(node, 'lineno', 0)}:{getattr(node, 'col_offset', 0)}"] = key
        written: set[str] = set()
        self._run_on_downloaded(tree, programs, writers, written)
        if not written:
            return
        for node in PythonSyntax.of(tree, ast.Call):
            resolved = self._resolve_callee(node)
            if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                continue
            call = resolved[1]
            if not call.args or not self._background_and_silent(tree, call):
                continue
            if self._runs_one_of(call.args[0], written) or self._names_a_written_path(
                call.args[0], written
            ):
                self._record(
                    Capability.FETCH_EXEC,
                    node,
                    f"{resolved[0]} starts a carried program detached",
                )

    def _program_names(self, tree: ast.AST) -> set[str]:
        """Names bound to a carried program literal, and names derived from one, to a fixed point."""
        names: set[str] = set()
        for node in PythonSyntax.of(tree, ast.Assign):
            text = PythonFacts.constant(node.value)
            if isinstance(text, str) and self._is_program(text):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        for _ in range(3):
            for node in PythonSyntax.of(tree, ast.Assign):
                if any(
                    isinstance(part, ast.Name) and part.id in names
                    for part in PythonSyntax.within(node.value, ast.Name)
                ):
                    names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        return names

    @classmethod
    def _is_program(cls, text: str) -> bool:
        if len(text) < cls.LENGTH:
            return False
        try:
            body = ast.parse(text).body
        except (SyntaxError, ValueError):
            # S2: a literal that does not parse is not a program, so nothing here is dropped;
            # every other rule still reads the literal as text
            return False
        return len(body) >= cls.STATEMENTS

    @classmethod
    def _background_and_silent(cls, tree: ast.AST, call: ast.Call) -> bool:
        """Started outside the installer's session (or hidden), with stdout and stderr discarded."""
        keywords = {k.arg: k.value for k in call.keywords if k.arg}
        session = keywords.get("start_new_session")
        preexec = keywords.get("preexec_fn")
        detached = (
            (isinstance(session, ast.Constant) and session.value is True)
            or (
                preexec is not None
                and any(
                    (isinstance(n, ast.Attribute) and n.attr in cls.DETACHING)
                    or (isinstance(n, ast.Name) and n.id in cls.DETACHING)
                    for n in ast.walk(preexec)
                )
            )
            or HiddenStart.of(tree, call)
        )
        return detached and all(
            cls._discarded(keywords.get(stream)) for stream in ("stdout", "stderr")
        )

    @staticmethod
    def _discarded(value: ast.AST | None) -> bool:
        return isinstance(value, ast.Attribute) and value.attr == "DEVNULL"

    @staticmethod
    def _names_a_written_path(argv: ast.AST, written: set[str]) -> bool:
        """`[python, "-c", "exec(open('/tmp/x.zqx').read())"]`: a string in the command that names
        the written file (a literal path, not a variable's placeholder)."""
        paths = {w for w in written if not w.startswith("name:") and len(w) >= 4}
        return any(
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and any(p in n.value for p in paths)
            for n in ast.walk(argv)
        )


__all__ = ["CarriedPrograms"]
