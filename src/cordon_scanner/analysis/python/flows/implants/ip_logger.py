"""A link that logs the address of whoever opens it, fetched or handed to a program.

An IP-logging service (`IP_LOGGER_HOSTS`) hands out a short link; whoever opens it is recorded: the
address, the browser, the time. A program has no reason to open one. Code that writes the link in a
request (`requests.get`, `urlopen`), or in a command (`wget <link>`, `curl <link>`, a browser start),
tells the logger's owner that this machine ran this code, and from where. The label that the
destinations table puts on the host says only that it is one; this is the act: the link is handed to a
call. A host that is only named (a list of services a linter flags, a comment) is not.

`lines` returns the line of each call that is handed such a link, directly or through a name.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from cordon_scanner.analysis.python.py_flow import Label
from cordon_scanner.analysis.python.py_persist import PythonPersistence
from cordon_scanner.analysis.shared.destinations import IP_LOGGER_HOSTS

IP_LOGGER_LINK: Final = re.compile(
    r"(?i)(?<![\w.-])(?:" + "|".join(re.escape(h) for h in sorted(IP_LOGGER_HOSTS)) + r")(?![\w-])"
)


class IpLoggerFetch(PythonPersistence):
    """The calls handed an IP-logger link in one syntax tree."""

    def seed(self, node: ast.AST) -> Label | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and IP_LOGGER_LINK.search(node.value):
            self.texts.setdefault(node.lineno, []).append(node.value)
            return node.lineno
        return None

    #: The head of a request call whose `get` / `post` is a request, not a dictionary's `get`.
    CLIENTS: ClassVar[tuple[str, ...]] = ("requests", "httpx", "urllib", "aiohttp", "http", "session", "client", "browser", "webbrowser")

    def _written_by(self, node: ast.Call) -> set[Label]:
        head = (self.dotted(node.func) or "").lower().split(".")
        if len(head) > 1 and head[0].startswith(self.CLIENTS):
            return self.given(node)
        return super()._written_by(node)

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        analysis = cls(tree)
        if not analysis.index() or not analysis.seeds:
            return []
        analysis.flow()
        out: set[int] = set()
        for node in analysis.calls:
            if analysis._written_by(node):
                out.add(node.lineno)
        return sorted(out)


__all__ = ["IpLoggerFetch"]
