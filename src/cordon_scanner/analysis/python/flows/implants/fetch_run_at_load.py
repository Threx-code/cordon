"""Code fetched from the network and run when a package is imported.

Importing a library loads code that is already on the machine. One that, while it is being imported,
both fetches something from the network and runs code or a program has made the import a download and
a launch: `exec(urlopen(url).read())`, or a response written to disk and started, or a command run
beside the download in a thread the import starts. Each half alone is ordinary -- a version check, a
licence ping, a query of the machine's own tools -- and neither alone is reported here; it is the two
together in what the import runs.

Half-A PyPI malware the 0.8.0 rules passed carried this shape (the combined gate's misses, 14 Nov;
the measured pair is in `reviews/pypi-98`). What runs at load is what `PersistAtLoad.load_time_lines`
reads (module level, class bodies, and the functions the module level calls through the file's own
helpers), and a function handed by name to a call that runs at load -- a thread's target, a timer, a
registered callback -- is loaded too. The main guard and a function nothing calls are not.

A run is `exec` or `eval` of something that is not a literal, or a process started (`os.system`,
`os.popen`, `os.startfile`, the `exec*` and `spawn*` families, `subprocess`, `pty.spawn`); the
version control tools and the screen-clearing commands are the machine's own and not counted. A fetch
is a request made with `requests`, `httpx`, `urllib.request` or `http.client`, through whatever name
the file imported it as.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar

from cordon_scanner.analysis.python.flows.implants.persist_at_load import PersistAtLoad
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class FetchRunAtLoad:
    """`lines(tree)`: the first run at load in a file that also fetches at load, or nothing."""

    FETCH: ClassVar[frozenset[str]] = frozenset(
        {
            *(f"requests.{m}" for m in ("get", "post", "put", "request", "head", "patch")),
            *(f"httpx.{m}" for m in ("get", "post", "put", "request", "stream")),
            "urllib.request.urlopen",
            "urllib.request.urlretrieve",
            "urllib.urlopen",
            "urllib.urlretrieve",
            "urllib2.urlopen",
            "http.client.HTTPConnection",
            "http.client.HTTPSConnection",
        }
    )
    PROCESS: ClassVar[frozenset[str]] = frozenset(
        {
            "os.system",
            "os.popen",
            "os.startfile",
            *(f"os.{m}" for m in ("execv", "execve", "execl", "execlp", "execvp", "execvpe")),
            *(f"os.{m}" for m in ("spawnl", "spawnv", "spawnve", "spawnlp", "spawnvp")),
            *(
                f"subprocess.{m}"
                for m in (
                    "Popen",
                    "call",
                    "run",
                    "check_call",
                    "check_output",
                    "getoutput",
                    "getstatusoutput",
                )
            ),
            "pty.spawn",
        }
    )
    CODE: ClassVar[frozenset[str]] = frozenset({"exec", "eval"})
    OWN: ClassVar[re.Pattern[str]] = re.compile(r"(?:git|hg|svn|clear|cls)(?:\.exe)?")

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        if not isinstance(tree, ast.Module):
            return []
        loaded = cls._load_time_lines(tree)
        if not loaded:
            return []
        aliases = cls._aliases(tree)
        fetches = False
        runs: list[int] = []
        for node in PythonSyntax.walked_of(tree, ast.Call):
            if not isinstance(node, ast.Call) or node.lineno not in loaded:
                continue
            name = cls._resolved(node.func, aliases)
            if name in cls.FETCH:
                fetches = True
            elif cls._runs(name, node):
                runs.append(node.lineno)
        return [min(runs)] if fetches and runs else []

    @classmethod
    def _runs(cls, name: str, call: ast.Call) -> bool:
        if name in cls.CODE:
            return bool(call.args) and not isinstance(call.args[0], ast.Constant)
        if name not in cls.PROCESS:
            return False
        first = call.args[0] if call.args else None
        if isinstance(first, ast.List | ast.Tuple) and first.elts:
            first = first.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            program = first.value.strip().split(" ", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]
            return cls.OWN.fullmatch(program.lower()) is None
        return True

    @classmethod
    def _load_time_lines(cls, tree: ast.Module) -> frozenset[int]:
        """`PersistAtLoad.load_time_lines`, and every line of a function handed by name to a call
        that runs at load (a thread's target, a timer, a registered callback)."""
        lines = set(PersistAtLoad.load_time_lines(tree))
        functions: dict[str, ast.AST] = {}
        for node in PythonSyntax.walked_of(tree, ast.FunctionDef, ast.AsyncFunctionDef):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                functions.setdefault(node.name, node)
        seen: set[str] = set()
        changed = True
        while changed:
            changed = False
            for node in PythonSyntax.walked_of(tree, ast.Call):
                if not isinstance(node, ast.Call) or node.lineno not in lines:
                    continue
                handed = [*node.args, *(k.value for k in node.keywords)]
                for arg in handed:
                    if isinstance(arg, ast.Name) and arg.id in functions and arg.id not in seen:
                        seen.add(arg.id)
                        fn = functions[arg.id]
                        start = fn.lineno  # type: ignore[attr-defined]
                        lines.update(range(start, (fn.end_lineno or start) + 1))  # type: ignore[attr-defined]
                        changed = True
        return frozenset(lines)

    @staticmethod
    def _aliases(tree: ast.Module) -> dict[str, str]:
        """What each imported name stands for: `import requests as r` gives `r` -> `requests`,
        `from urllib.request import urlopen as u` gives `u` -> `urllib.request.urlopen`."""
        out: dict[str, str] = {}
        for node in PythonSyntax.walked_of(tree, ast.Import, ast.ImportFrom):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        out[a.asname] = a.name
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    out[a.asname or a.name] = f"{node.module}.{a.name}"
        return out

    @staticmethod
    def _resolved(func: ast.expr, aliases: dict[str, str]) -> str:
        parts: list[str] = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if not isinstance(func, ast.Name):
            return ""
        parts.append(aliases.get(func.id, func.id))
        return ".".join(reversed(parts))


__all__ = ["FetchRunAtLoad"]
