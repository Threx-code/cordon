"""Code fetched from the network and run when a package is imported.

Importing a library loads code that is already on the machine. One that, while it is being imported,
both fetches something from the network and runs code or a program has made the import a download and
a launch: `exec(urlopen(url).read())`, or a response written to disk and started, or a command run
beside the download in a thread the import starts. Each half alone is ordinary -- a version check, a
licence ping, a query of the machine's own tools -- and neither alone is reported here; it is the two
together in what the import runs.

Measured at the flow (14 Nov, the 0.8.0 combined gate's rows): in a package's top-level `__init__.py`
it newly catches 11 half-A PyPI malware the rules passed, for 2 of 16,828 benign packages; in a
`setup.py`, 7 for 1. In other modules it was 6 for 26, so the rules read only those two entries
(`MALWARE.IMPORT.FETCH_RUN.001`, `MALWARE.INSTALL.FETCH_RUN.001`). What runs at load is what `PersistAtLoad.load_time_lines`
reads (module level, class bodies, and the functions the module level calls through the file's own
helpers), and a function handed by name to a call that runs at load -- a thread's target, a timer, a
registered callback -- is loaded too. The main guard and a function nothing calls are not.

A run is `exec` or `eval` of something that is not a literal, or a process started (`os.system`,
`os.popen`, `os.startfile`, the `exec*` and `spawn*` families, `subprocess`, `pty.spawn`); the
version control tools and the screen-clearing commands are the machine's own and not counted, and
neither is a tool asked only for its version or help -- an argument list whose every argument after
the program is such a flag (`[cc, '--version']`, a setup script checking its compiler) -- unless the
program is something the file fetched to (a name or literal path the fetch was given or assigned to),
which `[path, '--version']` still starts. A shell string is never read as a query: it can chain
anything after the flag. Measured 14 Nov: 1 of the 3 benign packages the rules newly blocked (two
readers: scanner error) was this compiler check beside a header download. A fetch
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
    QUERY: ClassVar[frozenset[str]] = frozenset(
        {"--version", "-version", "-V", "--help", "-dumpversion", "-dumpfullversion"}
    )

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        if not isinstance(tree, ast.Module):
            return []
        loaded = cls._load_time_lines(tree)
        if not loaded:
            return []
        aliases = cls._aliases(tree)
        fetched = cls._fetched(tree, aliases)
        fetches = False
        runs: list[int] = []
        for node in PythonSyntax.walked_of(tree, ast.Call):
            if not isinstance(node, ast.Call) or node.lineno not in loaded:
                continue
            name = cls._resolved(node.func, aliases)
            if name in cls.FETCH:
                fetches = True
            elif cls._runs(name, node, fetched):
                runs.append(node.lineno)
        return [min(runs)] if fetches and runs else []

    @classmethod
    def _fetched(cls, tree: ast.Module, aliases: dict[str, str]) -> frozenset[str]:
        """The names and literal strings a fetch was given or assigned to, and the names built
        from them: what a later run of 'the fetched file' would have to mention. Module names and
        the functions called (`os` in `os.path.join(d, f)`) are not data and link nothing."""
        modules = cls._imported(tree)
        refs: set[str] = set()
        for node in PythonSyntax.walked_of(tree, ast.Call):
            if isinstance(node, ast.Call) and cls._resolved(node.func, aliases) in cls.FETCH:
                for arg in [*node.args, *(k.value for k in node.keywords)]:
                    refs |= cls._mentions(arg, modules)
        assigns = [n for n in PythonSyntax.walked_of(tree, ast.Assign) if isinstance(n, ast.Assign)]
        for node in assigns:
            if any(
                isinstance(c, ast.Call) and cls._resolved(c.func, aliases) in cls.FETCH
                for c in ast.walk(node.value)
            ):
                for target in node.targets:
                    refs |= cls._mentions(target, modules)
        changed = True
        while changed:
            changed = False
            for node in assigns:
                if cls._mentions(node.value, modules) & refs:
                    for target in node.targets:
                        new = cls._mentions(target, modules) - refs
                        if new:
                            refs |= new
                            changed = True
        return frozenset(refs)

    @staticmethod
    def _imported(tree: ast.Module) -> frozenset[str]:
        out: set[str] = set()
        for node in PythonSyntax.walked_of(tree, ast.Import, ast.ImportFrom):
            if isinstance(node, ast.Import | ast.ImportFrom):
                for a in node.names:
                    out.add(a.asname or a.name.split(".", 1)[0])
        return frozenset(out)

    @staticmethod
    def _mentions(node: ast.AST, skip: frozenset[str] = frozenset()) -> set[str]:
        callees = {id(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)}
        out: set[str] = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id not in skip and id(n) not in callees:
                out.add(n.id)
            elif isinstance(n, ast.Constant) and isinstance(n.value, str):
                out.add(n.value)
        return out

    @classmethod
    def _runs(cls, name: str, call: ast.Call, fetched: frozenset[str] = frozenset()) -> bool:
        if name in cls.CODE:
            return bool(call.args) and not isinstance(call.args[0], ast.Constant)
        if name not in cls.PROCESS:
            return False
        first = call.args[0] if call.args else None
        if isinstance(first, ast.List | ast.Tuple) and first.elts:
            if cls._query(first.elts, fetched):
                return False
            first = first.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            program = first.value.strip().split(" ", 1)[0].replace("\\", "/").rsplit("/", 1)[-1]
            return cls.OWN.fullmatch(program.lower()) is None
        return True

    @classmethod
    def _query(cls, argv: list[ast.expr], fetched: frozenset[str]) -> bool:
        """An argument list that only asks a tool for its version or help, and whose program is
        not something the file fetched to."""
        program, rest = argv[0], argv[1:]
        if not rest or not all(
            isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value in cls.QUERY
            for a in rest
        ):
            return False
        return not (cls._mentions(program) & fetched)

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
