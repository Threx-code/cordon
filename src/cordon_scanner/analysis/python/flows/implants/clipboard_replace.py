"""A clipper: the clipboard read, tested against a pattern, and set to something the package brings.

A clipper waits for the user to copy a cryptocurrency address and puts its own in the clipboard, so the
payment goes to the attacker. In the code it is the same three steps whatever library reaches the
clipboard: read it (`pyperclip.paste`, `win32clipboard.GetClipboardData`, `tkinter`'s `clipboard_get`,
`pbpaste`, `xclip -o`, `wl-paste`), match the text against a pattern (a regular expression for an
address), and write a value the package supplies (a literal, a module constant, a decode of one) back
with `pyperclip.copy`, `SetClipboardText`, `clipboard_append`, `pbcopy`, `xclip`, `wl-copy`. A tool that
only reformats what it read writes what it read; a clipboard manager writes what the user chose. What
separates the clipper is the replacement that does not come from the clipboard.

`lines` returns the line of each such write: in one function (or at module level), a read, a
regular-expression test of what was read, and a write of carried content.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from cordon_scanner.analysis.python.flows.implants.backdoor_writes import ContentOrigin
from cordon_scanner.analysis.python.pysyntax import PythonSyntax

READ_SHELL: Final = re.compile(
    r"\bpbpaste\b|\bxclip\b[^;&|]*\s-o\b|\bxsel\b[^;&|]*\s-o\b|\bwl-paste\b|Get-Clipboard", re.I
)
WRITE_SHELL: Final = re.compile(
    r"\bpbcopy\b|\bxclip\b|\bxsel\b|\bwl-copy\b|\bclip(?:\.exe)?\b|Set-Clipboard", re.I
)


class ClipboardReplace:
    """The replacements of a clipboard's content in one syntax tree."""

    READS: ClassVar[frozenset[str]] = frozenset(
        {"paste", "GetClipboardData", "clipboard_get", "get_clipboard", "GetClipboardText"}
    )
    WRITES: ClassVar[frozenset[str]] = frozenset(
        {
            "copy",
            "SetClipboardText",
            "SetClipboardData",
            "clipboard_append",
            "set_clipboard",
            "SetText",
        }
    )
    REGEX: ClassVar[frozenset[str]] = frozenset(
        {"match", "search", "fullmatch", "sub", "subn", "findall", "finditer", "split"}
    )
    PROCESS: ClassVar[frozenset[str]] = frozenset(
        {"run", "call", "check_output", "check_call", "Popen", "system", "popen", "getoutput"}
    )

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        scopes: list[ast.AST] = [tree]
        scopes += [
            n
            for n in PythonSyntax.walked_of(tree, ast.FunctionDef, ast.AsyncFunctionDef)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        origin = ContentOrigin(tree)
        out: set[int] = set()
        for scope in scopes:
            body = scope.body  # type: ignore[attr-defined]
            calls = cls._calls(body)
            reads = [c for c in calls if cls._is_read(c)]
            if not reads:
                continue
            tainted = cls._tainted_names(body, reads)
            if not any(cls._tests(c, tainted, reads) for c in calls):
                continue
            func = scope if not isinstance(scope, ast.Module) else None
            for call in calls:
                if (
                    cls._is_write(call) and call.args and origin.carried(call.args[0], func, 0)
                ) or (cls._is_shell_write(call) and cls._literal_input(call)):
                    out.add(call.lineno)
        return sorted(out)

    @classmethod
    def _calls(cls, body: list[ast.stmt]) -> list[ast.Call]:
        out: list[ast.Call] = []
        stack: list[ast.AST] = list(body)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
                continue
            if isinstance(node, ast.Call):
                out.append(node)
            stack.extend(ast.iter_child_nodes(node))
        return out

    @staticmethod
    def _name(call: ast.Call) -> str:
        return call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", "")

    @classmethod
    def _is_read(cls, call: ast.Call) -> bool:
        if cls._name(call) in cls.READS:
            return True
        return cls._name(call) in cls.PROCESS and bool(READ_SHELL.search(cls._text(call)))

    @classmethod
    def _is_write(cls, call: ast.Call) -> bool:
        return cls._name(call) in cls.WRITES

    @classmethod
    def _is_shell_write(cls, call: ast.Call) -> bool:
        return (
            cls._name(call) in cls.PROCESS
            and bool(WRITE_SHELL.search(cls._text(call)))
            and not READ_SHELL.search(cls._text(call))
        )

    @staticmethod
    def _text(call: ast.Call) -> str:
        argv = call.args[0] if call.args else None
        if argv is None:
            return ""
        return " ".join(
            p.value
            for p in ast.walk(argv)
            if isinstance(p, ast.Constant) and isinstance(p.value, str)
        )

    @staticmethod
    def _literal_input(call: ast.Call) -> bool:
        value = next((k.value for k in call.keywords if k.arg == "input"), None)
        return isinstance(value, ast.Constant)

    @classmethod
    def _tainted_names(cls, body: list[ast.stmt], reads: list[ast.Call]) -> set[str]:
        read_ids = {id(r) for r in reads}
        names: set[str] = set()
        for _ in range(3):
            for node in ast.walk(ast.Module(body=body, type_ignores=[])):
                if isinstance(node, ast.Assign | ast.AnnAssign | ast.NamedExpr):
                    value = node.value
                    if value is None:
                        continue
                    parts = list(ast.walk(value))
                    if any(id(p) in read_ids for p in parts) or any(
                        isinstance(p, ast.Name) and p.id in names for p in parts
                    ):
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for t in targets:
                            if isinstance(t, ast.Name):
                                names.add(t.id)
        return names

    @classmethod
    def _tests(cls, call: ast.Call, tainted: set[str], reads: list[ast.Call]) -> bool:
        """A regular-expression call over what was read."""
        if cls._name(call) not in cls.REGEX:
            return False
        read_ids = {id(r) for r in reads}
        for arg in (*call.args, *(k.value for k in call.keywords)):
            for part in ast.walk(arg):
                if id(part) in read_ids or (isinstance(part, ast.Name) and part.id in tainted):
                    return True
        if isinstance(call.func, ast.Attribute):
            for part in ast.walk(call.func.value):
                if id(part) in read_ids or (isinstance(part, ast.Name) and part.id in tainted):
                    return True
        return False


__all__ = ["ClipboardReplace"]
