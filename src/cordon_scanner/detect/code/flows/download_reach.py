"""What a Python download flow SAW, and the loader runs it can pair with a download (reviews/pypi-98/26).

`PythonDownloads` follows what a file downloads. "Nothing downloaded is run" is only a claim about a
file whose downloads it saw: an alias it did not resolve, a client it does not know, a program handed
over as a string literal are all unresolved, never "nothing runs". The methods here are that account,
and the runs of a downloaded file by `runpy` or a loader. They are a base of `PythonDownloads`, which
supplies the rest (`_callee`, `_runs_arg`, `_path`, `paths`, `tree`)."""

from __future__ import annotations

import ast
import re
from typing import TYPE_CHECKING, ClassVar


class DownloadReach:
    """The part of the download flow that says what it saw."""

    if TYPE_CHECKING:
        tree: ast.AST
        paths: set[str]
        _FETCH_MODULES: ClassVar[frozenset[str]]

        def _callee(self, call: ast.Call) -> tuple[str, str]: ...
        def _runs_arg(self, node: ast.AST) -> bool: ...
        def _path(self, node: ast.AST) -> str: ...

    SHELL_DOWNLOAD: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)curl|wget|powershell|invoke-webrequest|\biwr\b|certutil|bitsadmin|downloadfile|downloadstring"
        r"|https?://|ftp://|urlretrieve|urlopen"
    )
    STARTS: ClassVar[frozenset[str]] = frozenset(
        {"system", "popen", "run", "call", "Popen", "check_output", "check_call", "getoutput",
         "getstatusoutput", "startfile", "create_subprocess_shell", "create_subprocess_exec"}
    )  # fmt: skip

    #: A file run as a program in this process: `runpy.run_module`, a loader's `exec_module(module)`,
    #: `SourceFileLoader(name, path).load_module()`.
    LOADER_RUNS: ClassVar[frozenset[str]] = frozenset({"run_module", "exec_module", "load_module"})

    @staticmethod
    def import_aliases(tree: ast.AST) -> dict[str, tuple[str, str]]:
        """Name -> (module, original name) for what a file imports under another name or as a bare
        name: `from urllib.request import urlopen as Z`, `import requests as rq`."""
        found: dict[str, tuple[str, str]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    found[alias.asname or alias.name] = (node.module.rsplit(".", 1)[-1], alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        found[alias.asname] = ("", alias.name.rsplit(".", 1)[-1])
        return found

    def every_egress_is_seen(self, egress_lines: frozenset[int]) -> bool:
        """Each egress line of the window holds a recognised download, or holds no call at all (an
        import, a URL in a string): a call the flow cannot name is a fetch it did not follow."""
        seen = self._fetch_lines()
        call_lines = {n.lineno for n in ast.walk(self.tree) if isinstance(n, ast.Call)}
        return all(line in seen or line not in call_lines for line in egress_lines)

    def _fetch_lines(self) -> frozenset[int]:
        lines: set[int] = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call) and self._is_fetch_call(node):
                lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        return frozenset(lines)

    def _is_fetch_call(self, call: ast.Call) -> bool:
        owner, name = self._callee(call)
        return name in ("urlopen", "urlretrieve") or (
            name in ("get", "post", "request", "stream") and owner in self._FETCH_MODULES
        )

    def runs_a_program_it_does_not_read(self) -> bool:
        """`exec`/`eval`/`compile` of a string literal, or a process started with a string that names a
        download: the program is text the outer tree does not parse."""
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            owner, name = self._callee(node)
            if name in ("exec", "eval", "compile") and not owner:
                first = node.args[0] if node.args else None
                if isinstance(first, ast.Constant | ast.JoinedStr) and not (
                    isinstance(first, ast.Constant) and not isinstance(first.value, str)
                ):
                    return True
            if name in self.STARTS and any(
                isinstance(sub, ast.Constant)
                and isinstance(sub.value, str)
                and self.SHELL_DOWNLOAD.search(sub.value)
                for arg in node.args
                for sub in ast.walk(arg)
            ):
                return True
        return False

    def loader_runs_a_download(
        self, call: ast.Call, name: str, owner: str, args: list[ast.expr]
    ) -> bool:
        """Whether a loader run is handed a downloaded file: `exec_module(m)` where `m` was built from
        a spec for a downloaded path, `load_module()` on a loader built from one, `run_module` of a
        module name taken from a download. A plugin loader on a local path is not: nothing in the
        call's arguments or receiver is downloaded."""
        if name == "run_module":
            return owner == "runpy" and any(
                self._runs_arg(a) or self._names_a_downloaded_module(a) for a in args
            )
        receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
        return any(self._runs_arg(a) for a in args) or (
            name == "load_module" and receiver is not None and self._runs_arg(receiver)
        )

    def _names_a_downloaded_module(self, node: ast.AST) -> bool:
        """A module name (`"x"`, `"pkg.x"`) whose file is one the flow saw written from a download."""
        name = self._path(node) if isinstance(node, ast.Constant | ast.Name) else ""
        stem = name.rsplit(".", 1)[-1]
        return bool(stem) and any(
            p.rsplit("/", 1)[-1].removesuffix(".py") == stem for p in self.paths if p
        )
