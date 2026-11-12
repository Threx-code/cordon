"""Keystrokes captured and written down or sent: a keylogger.

Four ways in: `pynput.keyboard.Listener(on_press=...)`, the `keyboard` module's `on_press` / `hook` /
`read_key`, a ctypes poll of `GetAsyncKeyState` / `GetKeyState` / `GetKeyboardState`, and
`SetWindowsHookEx` with a keyboard hook. A hotkey library maps a key to an action and an input loop
reads a key to move something; neither keeps the keys. What makes it a keylogger is the next step: the
key, or text built from it, reaches a file write or a request. The handler's key parameter (or the
poll's result) is followed through assignments, buffers and attributes (`self.buffer += name`,
`flush` writing `self.buffer`) to a write or a send.

`lines` returns the line of each write or send a captured key reaches.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class KeyCapture(PythonValueFlow):
    #: Registrations of a key handler: the call names, and the keyword that carries the handler.
    REGISTER: ClassVar[frozenset[str]] = frozenset(
        {"Listener", "on_press", "on_release", "hook", "on_key", "add_hotkey_all"}
    )
    HANDLER_KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {"on_press", "on_release", "on_key", "callback"}
    )
    #: Calls whose result is a keystroke or the keyboard's state.
    POLLS: ClassVar[frozenset[str]] = frozenset(
        {
            "GetAsyncKeyState",
            "GetKeyState",
            "GetKeyboardState",
            "read_key",
            "read_event",
            "GetKeyNameText",
        }
    )
    #: Modules a registration or poll must come from.
    MODULES: ClassVar[tuple[str, ...]] = (
        "pynput",
        "keyboard",
        "pyHook",
        "pyhook",
        "user32",
        "ctypes",
        "Xlib",
        "Quartz",
    )
    #: Calls that put what they are given in a file or send it.
    SINKS: ClassVar[frozenset[str]] = frozenset(
        {
            "write",
            "writelines",
            "write_text",
            "write_bytes",
            "post",
            "send",
            "sendall",
            "sendto",
            "send_message",
            "send_document",
            "sendMessage",
            "urlopen",
            "request",
        }
    )
    #: A write whose receiver is one of these shows the text (a terminal) or hands it to another thread; it keeps nothing.
    DISPLAYS: ClassVar[frozenset[str]] = frozenset(
        {"stdout", "stderr", "console", "terminal", "term", "screen"}
    )
    #: A request or a send needs one of these as the head of the call, or a socket-like receiver.
    NETWORK: ClassVar[tuple[str, ...]] = (
        "requests",
        "httpx",
        "urllib",
        "aiohttp",
        "http",
        "session",
        "client",
        "sock",
        "conn",
        "bot",
        "webhook",
        "smtp",
    )

    def __init__(self, tree: ast.AST) -> None:
        super().__init__(tree)
        self.handlers: set[str] = set()
        self.uses_capture = False
        self.imports_capture = False
        self._params_cache: list[tuple[int, int, str]] | None = None
        self._branches: list[tuple[int, int]] | None = None
        self._loops: list[tuple[int, int]] | None = None
        self._collect(tree)

    def _collect(self, tree: ast.AST) -> None:
        for node in PythonSyntax.walked(tree):
            if isinstance(node, ast.ImportFrom | ast.Import):
                names = (
                    [node.module or ""]
                    if isinstance(node, ast.ImportFrom)
                    else [a.name for a in node.names]
                )
                if any(
                    m.split(".")[0] in ("pynput", "keyboard", "pyHook", "pyhook", "Xlib", "Quartz")
                    for m in names
                ):
                    self.uses_capture = True
                    self.imports_capture = True
            if isinstance(node, ast.Call):
                name = self.name(node.func) or ""
                if self.imports_capture and name in self.REGISTER:
                    for k in node.keywords:
                        if k.arg in self.HANDLER_KEYWORDS and isinstance(
                            k.value, ast.Name | ast.Attribute
                        ):
                            self.handlers.add(self.name(k.value) or "")
                    if name in ("on_press", "on_release", "hook", "on_key") and node.args:
                        first = node.args[0]
                        if isinstance(first, ast.Name | ast.Attribute):
                            self.handlers.add(self.name(first) or "")
                if name in self.POLLS or name.startswith("SetWindowsHookEx"):
                    self.uses_capture = True

    @classmethod
    def _keeps(cls, node: ast.Call, analysis: KeyCapture) -> bool:
        """A call that puts text in a file or sends it: not a terminal's write, not a queue."""
        dotted = (analysis.dotted(node.func) or "").lower()
        name = analysis.name(node.func) or ""
        head = dotted.split(".")
        if name in ("write", "writelines"):
            return not any(part in cls.DISPLAYS for part in head[:-1])
        if name in ("write_text", "write_bytes"):
            return True
        return any(part.startswith(cls.NETWORK) for part in head[:-1]) or name in (
            "urlopen",
            "send_message",
            "send_document",
            "sendMessage",
        )

    def _in_loop(self, line: int) -> bool:
        if self._loops is None:
            self._loops = [
                (n.lineno, n.end_lineno or n.lineno)
                for n in PythonSyntax.walked(self.tree)
                if isinstance(n, ast.For | ast.While)
            ]
        return any(start <= line <= end for start, end in self._loops)

    def seed(self, node: ast.AST) -> Label | None:
        if isinstance(node, ast.Call) and (self.name(node.func) or "") in self.POLLS:
            return node.lineno if self._in_loop(node.lineno) else None
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            for start, end, param in self._handler_params():
                if param == node.id and start <= node.lineno <= end:
                    return node.lineno
            # `if GetAsyncKeyState(code): log += chr(code)`: what the branch uses is the key.
            for start, end in self._polled_branches():
                if start <= node.lineno <= end:
                    return node.lineno
        return None

    def _polled_branches(self) -> list[tuple[int, int]]:
        if self._branches is None:
            found: list[tuple[int, int]] = []
            for n in PythonSyntax.walked(self.tree):
                if (
                    isinstance(n, ast.If)
                    and self._in_loop(n.lineno)
                    and any(
                        isinstance(c, ast.Call) and (self.name(c.func) or "") in self.POLLS
                        for c in ast.walk(n.test)
                    )
                ):
                    last = n.body[-1]
                    found.append((n.body[0].lineno, last.end_lineno or last.lineno))
            self._branches = found
        return self._branches

    def _handler_params(self) -> list[tuple[int, int, str]]:
        if self._params_cache is None:
            found: list[tuple[int, int, str]] = []
            for fn in PythonSyntax.walked(self.tree):
                if (
                    isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef)
                    and fn.name in self.handlers
                ):
                    params = [
                        a
                        for a in (*fn.args.posonlyargs, *fn.args.args)
                        if a.arg not in ("self", "cls")
                    ]
                    if params:
                        found.append((fn.lineno, fn.end_lineno or fn.lineno, params[0].arg))
            self._params_cache = found
        return self._params_cache

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        analysis = cls(tree)
        if not (analysis.handlers or analysis.uses_capture):
            return []
        if not analysis.index() or not analysis.seeds:
            return []
        analysis.flow()
        out: set[int] = set()
        for node in analysis.calls:
            name = analysis.name(node.func) or ""
            if name in cls.SINKS and cls._keeps(node, analysis):
                given = analysis.given(node) | analysis.receiver(node)
                if given:
                    out.add(node.lineno)
        return sorted(out)


__all__ = ["KeyCapture"]
