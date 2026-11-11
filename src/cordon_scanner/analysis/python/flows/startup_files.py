"""A startup file put into site-packages: a `.pth`, `sitecustomize.py` or `usercustomize.py` copied,
moved or written to a directory Python reads at every interpreter start (persistence, without the
package ever being imported).

tinkoff_cloud_apis_internal 8.5.4's install command `_Install.run` copies its `telemetry.pth` with
`shutil.copy2(src, site.getsitepackages()[0])`; what the `.pth` then imports sends the machine's
facts on every start. A wheel that ships a `.pth` in its purelib is read by the startup facts
(`StartupHooks`); this is the install that writes one itself.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class StartupFiles(AnalyzerCore):
    """`_startup_file_written` and what it needs."""

    #: Calls that put a file somewhere, and the argument that names where.
    PLACERS: ClassVar[dict[str, int]] = {
        "shutil.copy": 1,
        "shutil.copy2": 1,
        "shutil.copyfile": 1,
        "shutil.move": 1,
        "os.rename": 1,
        "os.replace": 1,
        "os.symlink": 1,
        "open": 0,
    }
    #: Path methods that write the file they are called on.
    PATH_WRITERS: ClassVar[frozenset[str]] = frozenset({"write_text", "write_bytes", "symlink_to"})
    #: What names a directory Python reads startup files from.
    SITE_CALLS: ClassVar[frozenset[str]] = frozenset(
        {
            "site.getsitepackages",
            "site.getusersitepackages",
            "sysconfig.get_path",
            "sysconfig.get_paths",
            "distutils.sysconfig.get_python_lib",
            "get_python_lib",
        }
    )
    SITE_ATTRS: ClassVar[frozenset[str]] = frozenset(
        {"install_lib", "install_purelib", "install_platlib", "USER_SITE"}
    )
    STARTUP_NAME: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:\.pth|(?:^|[/\\])(?:site|user)customize\.py)$"
    )

    def _startup_file_written(self, tree: ast.AST) -> None:
        """A copy, move or write whose file is a startup file and whose target is a site dir."""
        for scope in [tree, *PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)]:
            bound = self._single_bindings(scope)
            for call in PythonSyntax.within(scope, ast.Call):
                dotted = self._dotted(call.func) or ""
                if dotted in self.PLACERS and len(call.args) > self.PLACERS[dotted]:
                    target = call.args[self.PLACERS[dotted]]
                    if dotted == "open" and not self._writes(call):
                        continue
                    pieces = [*call.args, target]
                elif isinstance(call.func, ast.Attribute) and call.func.attr in self.PATH_WRITERS:
                    target = call.func.value
                    pieces = [target]
                else:
                    continue
                if self._names_site(target, bound) and any(
                    self._names_startup_file(p, bound) for p in pieces
                ):
                    self._record(Capability.PERSIST, call, f"startup file written: {dotted}")

    @staticmethod
    def _writes(call: ast.Call) -> bool:
        mode = call.args[1] if len(call.args) > 1 else None
        mode = mode or next((k.value for k in call.keywords if k.arg == "mode"), None)
        return (
            isinstance(mode, ast.Constant)
            and isinstance(mode.value, str)
            and ("w" in mode.value or "a" in mode.value or "x" in mode.value)
        )

    def _single_bindings(self, scope: ast.AST) -> dict[str, ast.AST]:
        """Names assigned exactly once in this scope, to their value."""
        seen: dict[str, list[ast.AST]] = {}
        for node in PythonSyntax.within(scope, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    seen.setdefault(target.id, []).append(node.value)
        return {name: values[0] for name, values in seen.items() if len(values) == 1}

    def _expanded(self, node: ast.AST, bound: dict[str, ast.AST]) -> list[ast.AST]:
        """The node's own sub-nodes and those of the names it reads, two bindings deep."""
        nodes = list(PythonSyntax.nodes(node))
        for _ in range(2):
            extra = [
                bound[n.id]
                for n in nodes
                if isinstance(n, ast.Name) and n.id in bound and bound[n.id] not in nodes
            ]
            if not extra:
                break
            for value in extra:
                nodes.extend(PythonSyntax.nodes(value))
        return nodes

    def _names_site(self, node: ast.AST, bound: dict[str, ast.AST]) -> bool:
        for part in self._expanded(node, bound):
            if isinstance(part, ast.Call) and (self._dotted(part.func) or "") in self.SITE_CALLS:
                return True
            if isinstance(part, ast.Attribute) and part.attr in self.SITE_ATTRS:
                return True
            if (
                isinstance(part, ast.Constant)
                and isinstance(part.value, str)
                and "site-packages" in part.value
            ):
                return True
        return False

    def _names_startup_file(self, node: ast.AST, bound: dict[str, ast.AST]) -> bool:
        return any(
            isinstance(part, ast.Constant)
            and isinstance(part.value, str)
            and bool(self.STARTUP_NAME.search(part.value))
            for part in self._expanded(node, bound)
        )


__all__ = ["StartupFiles"]
