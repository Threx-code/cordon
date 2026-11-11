"""A fingerprint of the machine sent out, and a program the answer names run: a server choosing,
per machine, what to install.

is-it-ai 0.1.1: `context.get_context()` reads environment variables and the platform and hashes
files at paths a shipped config names; `verifier.verify()` posts `json.dumps(get_context())` to a
host from that config; `_parse_report(response)` downloads the URL the answer names, makes it
executable and starts it. Each half is ordinary: a self-updater asks a release API which build to
fetch and runs the installer; a telemetry client reports the platform. What a self-updater does not
send is the environment and hashes of the user's files, and what telemetry does not do is run the
answer. Together they are a server deciding, from who the machine is, what runs on it.

`MachineCollectors.of(sources)` (machine_collectors.py): `{path: {name: "0"}}` for each file that imports, from another file
of the package, a top-level function that reads machine context (`os.environ`, `os.getenv`,
`platform.*`, `socket.gethostname`, `getpass.getuser`, `uuid.getnode`) and reads or hashes files
(`open`, `read_bytes`, `read_text`, `hashlib.*`, `glob.*`), directly or through a function of its
own file it calls (`ScanContext.python_imported_collectors`; the runner map's shape).

`machine report answered with a program: <sink>`: a request whose arguments carry the result of a
call to such a function (directly or through one binding), made in a function that is, or calls,
a function holding a fetched run (FETCH_EXEC) that downloads to a file or makes one runnable
(urlretrieve, chmod, startfile, write_bytes). helixor reports in one function and updates itself
in an unrelated one; env-doctor runs a fix command a server suggests, with no program on disk: 2
of 16,274 that way, quiet now.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PRIMITIVES
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class MachineReports(AnalyzerCore):
    """`_machine_reports` and what it needs."""

    def _machine_reports(self, tree: ast.AST) -> None:
        collectors = self._imported_collectors
        fetch_lines = {h.line for h in self._hits if h.capability is Capability.FETCH_EXEC}
        if not collectors or not fetch_lines:
            return
        functions = [
            *PythonSyntax.of(tree, ast.FunctionDef),
            *PythonSyntax.of(tree, ast.AsyncFunctionDef),
        ]
        droppers = {f.name for f in functions if self._drops_a_program(f, fetch_lines)}
        for scope in functions:
            if not self._reaches_a_dropper(scope, droppers):
                continue
            carriers = self._report_carriers(scope, collectors)
            for call in PythonSyntax.within(scope, ast.Call):
                resolved = self._resolve_callee(call)
                if resolved is None or PRIMITIVES.get(resolved[0]) is not Capability.EGRESS:
                    continue
                parts = [*resolved[1].args, *(k.value for k in resolved[1].keywords)]
                if any(self._report_carries(p, collectors, carriers) for p in parts):
                    self._record(
                        Capability.EGRESS,
                        call,
                        f"machine report answered with a program: {resolved[0]}",
                    )
                    return

    #: Calls that put a downloaded program on disk or make a file runnable.
    _DROP: ClassVar[frozenset[str]] = frozenset(
        {"urlretrieve", "chmod", "startfile", "write_bytes"}
    )

    def _drops_a_program(self, function: ast.AST, fetch_lines: set[int]) -> bool:
        """A function holding a fetched run that also downloads to a file or makes one runnable:
        a program delivered, not a command (env-doctor runs a fix command a server suggests)."""
        first = getattr(function, "lineno", 0)
        last = getattr(function, "end_lineno", first) or first
        if not any(first <= line <= last for line in fetch_lines):
            return False
        return any(
            isinstance(c, ast.Call)
            and (self._dotted(c.func) or "").rsplit(".", 1)[-1] in self._DROP
            for c in ast.walk(function)
        )

    @staticmethod
    def _reaches_a_dropper(scope: ast.AST, droppers: set[str]) -> bool:
        """The report's function is the dropper or calls it: the answer is what gets run
        (helixor reports in one function and updates itself in an unrelated one)."""
        if getattr(scope, "name", None) in droppers:
            return True
        return any(
            isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name | ast.Attribute)
            and (c.func.id if isinstance(c.func, ast.Name) else c.func.attr) in droppers
            for c in ast.walk(scope)
        )

    @staticmethod
    def _report_collector_call(node: ast.AST, collectors: set[str]) -> bool:
        return any(
            isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id in collectors
            for c in ast.walk(node)
        )

    def _report_carriers(self, scope: ast.AST, collectors: set[str]) -> set[str]:
        """Names the function binds to a collector's result, or to a value built from one."""
        carried: set[str] = set()
        for _ in range(3):
            for node in PythonSyntax.within(scope, ast.Assign):
                if self._report_carries(node.value, collectors, carried):
                    carried |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        return carried

    def _report_carries(self, node: ast.AST, collectors: set[str], carried: set[str]) -> bool:
        return self._report_collector_call(node, collectors) or any(
            isinstance(n, ast.Name) and n.id in carried for n in ast.walk(node)
        )


__all__ = ["MachineReports"]
