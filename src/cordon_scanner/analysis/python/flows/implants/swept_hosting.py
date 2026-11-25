"""Files swept from a directory and sent to a free-hosting, paste, tunnel or interaction host.

A backup or search tool walks a tree and reads what it finds; an uploader sends a file to its own
service. A stealer does both and sends the contents somewhere anyone can rent for nothing: a
subdomain of a free-hosting platform (`vercel.app`, `netlify.app`, `herokuapp.com`), a paste site, a
tunnel or an out-of-band interaction host. funkratov_renderkit and renderkitcore walk the driver
folders for `*.txt` logs and post each file's text to `renderkit1.vercel.app` through
`asyncio.to_thread` and an `httpx.AsyncClient`, three helpers deep.

The three legs are read from the file: a directory walk (`os.walk`, `glob`, `rglob`, `iterdir`,
`scandir`, `listdir`), a literal URL whose host is on one of those lists (also as the default of an
environment lookup), and a file's contents followed to the body of a request through the file's own
functions, through `asyncio.to_thread`, `run_in_executor`, `submit` and `Thread(target=...)` hops.
Parsed, never executed.

`lines` returns the line of each request whose body carries the contents of a file read in a file
that has the other two legs.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar, Final

from cordon_scanner.analysis.python.flows.http_clients import HTTP_CLIENT_METHODS
from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.shared.destinations import (
    FREE_HOSTING,
    INTERACTION_HOSTS,
    PASTE_HOSTS,
    TUNNEL_HOSTS,
)

URL_HOST: Final = re.compile(r"(?i)https?://([A-Za-z0-9.-]+)")
#: `github.io` hosts project documentation (3 of 16,274 benign units name one beside a directory walk and a
#: request), so it is left out of the rentable hosts here; the lists themselves are the shared ones.
HOSTS: Final = (FREE_HOSTING | PASTE_HOSTS | TUNNEL_HOSTS | INTERACTION_HOSTS) - {"github.io"}
#: Modules whose client sends a request.
CLIENT_MODULES: Final = ("httpx", "requests", "aiohttp", "urllib", "urllib3")


class SweptToHosting(PythonValueFlow):
    """The sweeps sent to a rentable host in one syntax tree."""

    WALKERS: ClassVar[frozenset[str]] = frozenset(
        {"os.walk", "os.scandir", "os.listdir", "glob.glob", "glob.iglob"}
    )
    WALK_METHODS: ClassVar[frozenset[str]] = frozenset(
        {"rglob", "glob", "walk", "iterdir", "scandir"}
    )
    READS: ClassVar[frozenset[str]] = frozenset({"read_text", "read_bytes", "read", "readlines"})
    BODY_KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {"data", "json", "files", "content", "body", "params"}
    )
    #: Calls that run another function of the file with the arguments after it.
    HOPS: ClassVar[dict[str, int]] = {
        "to_thread": 0,
        "submit": 0,
        "run_in_executor": 1,
        "start_soon": 0,
        "create_task": -1,
    }

    #: Which stage this flow is: 1 follows what a walker yields, 2 follows the contents of the files
    #: a stage-1 path was read from.
    def __init__(self, tree: ast.AST, *, reads: frozenset[int] | None = None) -> None:
        super().__init__(tree)
        #: Stage 2: the ids of the read calls whose path came from a walker.
        self.reads = reads

    def seed(self, node: ast.AST) -> Label | None:
        if not isinstance(node, ast.Call):
            return None
        if self.reads is not None:
            return node.lineno if id(node) in self.reads else None
        if isinstance(node.func, ast.Attribute) and node.func.attr in self.WALK_METHODS:
            return node.lineno
        return node.lineno if self._dotted_name(node.func) in self.WALKERS else None

    @staticmethod
    def _dotted_name(func: ast.AST) -> str:
        return SweptToHosting._dotted(func)

    def _hop(self, node: ast.Call) -> tuple[str, list[ast.AST]] | None:
        """`(function, arguments)` when this call runs a function of the file through a hop."""
        name = self.name(node.func) or ""
        if name == "Thread":
            target = next((k.value for k in node.keywords if k.arg == "target"), None)
            args = next((k.value for k in node.keywords if k.arg == "args"), None)
            fname = self.name(target) if target is not None else None
            if fname in self.functions:
                return fname, list(args.elts) if isinstance(args, ast.Tuple | ast.List) else []
            return None
        index = self.HOPS.get(name)
        if index is None or index < 0 or len(node.args) <= index:
            return None
        fname = self.name(node.args[index])
        if fname in self.functions:
            return fname, list(node.args[index + 1 :])
        return None

    def call_flow(self, node: ast.Call) -> bool:
        hop = self._hop(node)
        if hop is None:
            return False
        fname, args = hop
        changed = False
        for fn in self.functions[fname]:
            params = self.params(fn)
            for param, arg in zip(params, args, strict=False):
                changed |= self._bind_param(fn, param.arg, self.taint(arg))
        return changed

    def _taint_call(self, part: ast.Call, out: set[Label]) -> bool:
        hop = self._hop(part)
        if hop is not None:
            out |= self.returns.get(hop[0], set())
        return super()._taint_call(part, out)

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        if not (
            cls._walks(tree) and cls._names_a_rentable_host(tree) and cls._imports_a_client(tree)
        ):
            return []
        walked = cls(tree)
        if not walked.index() or not walked.seeds:
            return []
        walked.flow()
        # the reads whose path a walker yielded: `path.read_text()`, `open(path).read()`
        reads: set[int] = set()
        for node in walked.calls:
            if not (isinstance(node.func, ast.Attribute) and node.func.attr in cls.READS):
                continue
            if walked.taint(node.func.value) or any(
                walked.taint(part) for part in ast.walk(node.func.value)
            ):
                reads.add(id(node))
        if not reads:
            return []
        analysis = cls(tree, reads=frozenset(reads))
        if not analysis.index() or not analysis.seeds:
            return []
        analysis.flow()
        out: set[int] = set()
        for node in analysis.calls:
            if not (isinstance(node.func, ast.Attribute) and node.func.attr in HTTP_CLIENT_METHODS):
                continue
            body = [k.value for k in node.keywords if k.arg in cls.BODY_KEYWORDS] + list(
                node.args[1:]
            )
            if any(analysis.taint(part) for part in body):
                out.add(node.lineno)
        return sorted(out)

    @classmethod
    def _walks(cls, tree: ast.AST) -> bool:
        for node in PythonSyntax.walked_of(tree, ast.Call):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in cls.WALK_METHODS:
                    return True
                if cls._dotted(node.func) in cls.WALKERS:
                    return True
        return False

    @staticmethod
    def _dotted(func: ast.AST) -> str:
        parts: list[str] = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        return ".".join(reversed(parts))

    @staticmethod
    def _names_a_rentable_host(tree: ast.AST) -> bool:
        docstrings = {
            id(n.body[0].value)
            for n in PythonSyntax.walked_of(
                tree, ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef
            )
            if isinstance(n, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and n.body
            and isinstance(n.body[0], ast.Expr)
            and isinstance(n.body[0].value, ast.Constant)
        }  # a host in a docstring is documentation, not a destination
        for node in PythonSyntax.walked_of(tree, ast.Constant):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
            ):
                for match in URL_HOST.finditer(node.value):
                    host = match.group(1).lower().rstrip(".")
                    if any(host == known or host.endswith("." + known) for known in HOSTS):
                        return True
        return False

    @staticmethod
    def _imports_a_client(tree: ast.AST) -> bool:
        for node in PythonSyntax.walked_of(tree, ast.Import, ast.ImportFrom):
            names = (
                [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else []
            )
            if any(n.split(".")[0] in CLIENT_MODULES for n in names):
                return True
        return False


__all__ = ["SweptToHosting"]
