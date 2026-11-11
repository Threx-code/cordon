"""Stages left loose at module level: a payload handed to a function nothing defines, and a literal
command on a temp path.

cubaflixdownload 1.0.1's `__init__.py` imports `requests` and a module the package does not ship,
then calls `decript("<186 characters>")` at module level: no function of that name is defined,
imported or bound anywhere in the file. The decoder was stripped or lives in the missing module;
what is left is an encoded payload handed to it the moment the package is imported. Benign
`__init__` files that call a name they do not define (9 of 16,274: names injected by a framework,
`if` blocks for an interpreter) pass it names, numbers or a few characters, never a payload.

maliciouspackage 0.1's `setup.py` runs a two-word literal command on a path under `/tmp` at module
level. A build runs compilers and packaging tools inside its own tree; a command that reaches a
system temp path from the install script is the install writing or running something outside it
(0 of 16,274 setup.py files).

`unresolved call on a payload literal: <name length>`: at module level, outside any `try`/`if`, a
call of a bare name nothing in the file defines, imports, binds or takes as a builtin (no star
import), whose argument is a string literal of `PAYLOAD` characters or more.

`literal command on a temp path: <call>`: at module level, a process start (os.system, os.popen,
subprocess.*) whose literal command (a string, or a list of strings and paths built on
`tempfile.gettempdir()`/`mkdtemp()`) has a word under /tmp, /var/tmp or /dev/shm, or naming
%TEMP%, %TMP%, $TMPDIR or \\Windows\\Temp\\. Graded in install context only.
"""

from __future__ import annotations

import ast
import builtins
from collections.abc import Callable
from typing import Any, ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.foundation.capabilities import Capability


class LooseStages(AnalyzerCore):
    """`_loose_stages` and what it needs."""

    PAYLOAD: ClassVar[int] = 64
    #: Prefixes matched in a command, never paths this code uses.
    TEMP: ClassVar[tuple[str, ...]] = ("/tmp/", "/var/tmp/", "/dev/shm/")  # noqa: S108
    _BUILTIN: ClassVar[frozenset[str]] = frozenset(
        {
            *dir(builtins),
            "__file__",
            "__name__",
            "__path__",
            "__spec__",
            "__loader__",
            "__builtins__",
        }
    )

    def _loose_stages(self, tree: ast.AST) -> None:
        top = list(self._unguarded(tree))
        defined = self._defined(tree)
        for statement in top:
            for call in (n for n in ast.walk(statement) if isinstance(n, ast.Call)):
                self._payload_to_nothing(call, defined)
                self._temp_command(call)

    @staticmethod
    def _unguarded(tree: ast.AST) -> list[ast.stmt]:
        """Module-level statements outside any def, class, `try` or `if`."""
        return [
            s
            for s in getattr(tree, "body", [])
            if not isinstance(
                s, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Try | ast.If
            )
        ]

    #: The names each kind of node binds.
    _BINDS: ClassVar[dict[type, Callable[[Any], set[str]]]] = {
        ast.FunctionDef: lambda n: {n.name},
        ast.AsyncFunctionDef: lambda n: {n.name},
        ast.ClassDef: lambda n: {n.name},
        ast.Import: lambda n: {(a.asname or a.name).split(".")[0] for a in n.names},
        ast.ImportFrom: lambda n: {(a.asname or a.name).split(".")[0] for a in n.names},
        ast.Name: lambda n: {n.id} if isinstance(n.ctx, ast.Store | ast.Del) else set(),
        ast.arg: lambda n: {n.arg},
        ast.Global: lambda n: set(n.names),
        ast.Nonlocal: lambda n: set(n.names),
    }

    def _defined(self, tree: ast.AST) -> set[str] | None:
        """Every name the file could resolve; None with a star import (anything could be)."""
        names = set(self._BUILTIN)
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names):
                return None
            binds = self._BINDS.get(type(n))
            if binds is not None:
                names |= binds(n)
        return names

    def _payload_to_nothing(self, call: ast.Call, defined: set[str] | None) -> None:
        if defined is None or not isinstance(call.func, ast.Name) or call.func.id in defined:
            return
        if any(
            isinstance(a, ast.Constant)
            and isinstance(a.value, str | bytes)
            and len(a.value) >= self.PAYLOAD
            for a in call.args
        ):
            self._record(
                Capability.EXECUTE,
                call,
                f"unresolved call on a payload literal: {len(call.func.id)}",
            )

    #: Spellings of the system temp directory inside a command word, Windows and shell forms.
    TEMP_MARKERS: ClassVar[tuple[str, ...]] = (
        "%temp%",
        "%tmp%",
        "$tmpdir",
        "${tmpdir}",
        "\\windows\\temp\\",
    )
    #: A command word built on the temp directory by a call (kept as this in the command).
    TEMP_SENTINEL: ClassVar[str] = "<tempdir>"
    #: Calls that return the system temp directory.
    TEMP_CALLS: ClassVar[frozenset[str]] = frozenset(
        {"tempfile.gettempdir", "tempfile.gettempdirb", "tempfile.mkdtemp"}
    )

    def _temp_word(self, word: str) -> bool:
        lowered = word.lower().replace("/", "\\")
        return (
            word == self.TEMP_SENTINEL
            or word.startswith(self.TEMP)
            or any(m in lowered for m in self.TEMP_MARKERS)
        )

    def _command_words(self, command: ast.AST) -> list[str] | None:
        """A command's words: literal text, or a list whose items are literals or paths built on
        the temp directory (`os.path.join(tempfile.gettempdir(), "x")`, kept as `TEMP_SENTINEL`)."""
        if isinstance(command, ast.Constant) and isinstance(command.value, str):
            return command.value.split()
        if not isinstance(command, ast.List | ast.Tuple):
            return None
        words: list[str] = []
        for item in command.elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                words.append(item.value)
            elif any(
                isinstance(n, ast.Call) and (self._dotted(n.func) or "") in self.TEMP_CALLS
                for n in ast.walk(item)
            ):
                words.append(self.TEMP_SENTINEL)
            else:
                return None
        return words

    def _temp_command(self, call: ast.Call) -> None:
        resolved = self._resolve_callee(call)
        if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN or not call.args:
            return
        words = self._command_words(call.args[0])
        if words is not None and any(self._temp_word(w) for w in words):
            self._record(
                Capability.SPAWN,
                call,
                f"literal command on a temp path: {resolved[0]}",
                " ".join(words),
            )


__all__ = ["LooseStages"]
