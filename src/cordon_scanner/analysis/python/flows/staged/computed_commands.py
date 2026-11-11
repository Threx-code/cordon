"""A command whose text the file assembles from its literals so that no literal is it.

openblox 1.0.0 and sqligen 1.0.0: `setup.py` calls `GetGitCommitHash()` at module level. That
helper builds `GitCmd` from `GetDefaultSystemPolicy()`, which returns
`"".join(chr(t + base) for t in [four ints])`, and runs it with `subprocess.check_output`: a
program spelled in character codes, started at install, dressed as a git-hash lookup.

`computed command run: <sink>`: a process start (a SPAWN primitive) whose command, through the
function's own bindings, conditional branches, list items, `+` and f-string pieces, holds a piece
`LiteralProgram` folds with a hiding step (`chr`, characters picked out of a text, a stepped slice,
`reversed`, XOR). The folded text is the hit's command, so `InstallPrograms` reads the program it
starts. A command written as literals (`["git", "rev-parse", "HEAD"]`) or joined from them hides
nothing and is not this.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.flows.staged.literal_program import LiteralProgram
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class ComputedCommands(AnalyzerCore):
    """`_computed_commands` and what it needs."""

    #: How far a command is followed through the function's own bindings.
    HOPS: ClassVar[int] = 4

    def _computed_commands(self, tree: ast.AST) -> None:
        if self._module_tree is None:
            return
        seen: set[int] = set()
        scopes: list[ast.AST] = [
            *PythonSyntax.of(tree, ast.FunctionDef),
            *PythonSyntax.of(tree, ast.AsyncFunctionDef),
            tree,
        ]
        for scope in scopes:
            bound = self._local_values(scope)
            for call in PythonSyntax.within(scope, ast.Call):
                if id(call) in seen:
                    continue
                seen.add(id(call))
                resolved = self._resolve_callee(call)
                if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.SPAWN:
                    continue
                command = self._command_argument(resolved[1])
                folded = None if command is None else self._hidden_piece(command, bound)
                if folded is not None:
                    self._record(
                        Capability.SPAWN, call, f"computed command run: {resolved[0]}", folded
                    )

    #: Calls that reach a module or a function by name, and the position of the name.
    NAMED_BY: ClassVar[dict[str, int]] = {
        "importlib.import_module": 0,
        "__import__": 0,
        "getattr": 1,
    }

    def _concealed_names(self, tree: ast.AST) -> None:
        """`concealed name resolved: <call>`: import_module, `__import__` or getattr handed a name
        the file spells with a hiding step (apkeep 1.0.1: `import_module("".join(chr(c) for c in
        [...]))`, then `getattr` of a name spelled the same way). The name resolves, so the call is
        read as what it reaches; that the name was hidden is a fact of its own."""
        module = self._module_tree
        if module is None:
            return
        for call in PythonSyntax.of(tree, ast.Call):
            position = self.NAMED_BY.get(self._dotted(call.func) or "")
            if position is None or len(call.args) <= position:
                continue
            argument = call.args[position]
            if isinstance(argument, ast.Constant):
                continue
            text, spelled = LiteralProgram.spelled_out(module, argument)
            if text is not None and spelled:
                self._record(
                    Capability.DYNAMIC_DISPATCH,
                    call,
                    f"concealed name resolved: {self._dotted(call.func)}",
                )

    @staticmethod
    def _command_argument(call: ast.Call) -> ast.AST | None:
        if call.args:
            return call.args[0]
        return next((k.value for k in call.keywords if k.arg in ("args", "cmd", "command")), None)

    @staticmethod
    def _local_values(scope: ast.AST) -> dict[str, ast.AST]:
        """Names the scope binds once, to their value."""
        values: dict[str, ast.AST | None] = {}
        for node in PythonSyntax.within(scope, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = None if target.id in values else node.value
        return {name: value for name, value in values.items() if value is not None}

    def _hidden_piece(self, command: ast.AST, bound: dict[str, ast.AST]) -> str | None:
        """The folded text of the first piece of the command computed with a hiding step."""
        tree = self._module_tree
        if tree is None:
            return None
        pending: list[tuple[ast.AST, int]] = [(command, 0)]
        while pending:
            node, hops = pending.pop()
            if isinstance(node, ast.Constant):
                continue
            text, concealed = self._folded_command(tree, node)
            if text is not None and concealed:
                return text
            if isinstance(node, ast.Name):
                if node.id in bound and hops < self.HOPS:
                    pending.append((bound[node.id], hops + 1))
                continue
            pending.extend((child, hops) for child in self._pieces(node))
        return None

    @staticmethod
    def _folded_command(tree: ast.AST, node: ast.AST) -> tuple[str | None, bool]:
        """The folded text of a command expression, an argument list joined in order (its
        program first), and whether a hiding step built it."""
        if not isinstance(node, ast.List | ast.Tuple):
            return LiteralProgram.folded(tree, node)
        words, hidden = [], False
        for element in node.elts:
            text, concealed = LiteralProgram.folded(tree, element)
            if text is None:
                return None, False
            words.append(text)
            hidden |= concealed
        return " ".join(words), hidden

    @staticmethod
    def _pieces(node: ast.AST) -> list[ast.AST]:
        """The parts a command expression is made of."""
        if isinstance(node, ast.IfExp):
            return [node.body, node.orelse]
        if isinstance(node, ast.List | ast.Tuple):
            return list(node.elts)
        if isinstance(node, ast.BinOp):
            return [node.left, node.right]
        if isinstance(node, ast.JoinedStr):
            return [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        return []


__all__ = ["ComputedCommands"]
