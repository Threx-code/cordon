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
                if not (
                    self._names_site(target, bound)
                    and any(self._names_startup_file(p, bound) for p in pieces)
                ):
                    continue
                if self._writes_only_a_path(call, scope, bound):
                    # A `.pth` of path entries runs nothing: the legacy `distribute_setup.py`
                    # bootstrap writes `setuptools.pth` holding a directory (nose3 1.3.8, RTMPy).
                    continue
                self._record(Capability.PERSIST, call, f"startup file written: {dotted}")

    #: Calls that only build a path.
    _PATH_CALLS: ClassVar[frozenset[str]] = frozenset(
        {
            "os.path.join",
            "os.path.abspath",
            "os.path.dirname",
            "os.path.realpath",
            "os.path.normpath",
            "os.path.expanduser",
            "os.curdir",
            "os.getcwd",
            "str",
            "Path",
            "pathlib.Path",
        }
    )

    def _writes_only_a_path(
        self, call: ast.Call, scope: ast.AST, bound: dict[str, ast.AST]
    ) -> bool:
        """Whether this write puts only a path into the file. A copy, a move or a link carries the
        source file's lines, which this file does not show: never only a path. A write whose
        content cannot be found counts as code (closed)."""
        dotted = self._dotted(call.func) or ""
        if dotted in ("shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move"):
            return False
        if dotted in ("os.rename", "os.replace", "os.symlink"):
            return False
        content: ast.AST | None
        if isinstance(call.func, ast.Attribute) and call.func.attr in self.PATH_WRITERS:
            content = call.args[0] if call.args else None
        else:
            content = self._content_written_through(call, scope)
        return content is not None and self._only_a_path(content, bound)

    def _content_written_through(self, opened: ast.Call, scope: ast.AST) -> ast.AST | None:
        """What `with open(...) as f: f.write(X)` or `open(...).write(X)` writes: X, or None."""
        for node in PythonSyntax.within(scope, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in ("write", "writelines")
                and func.value is opened
                and node.args
            ):
                written: ast.AST = node.args[0]
                return written
        # `f = open(...)`, then `f.write(X)`: the nearest write on that name after this open (the
        # name may be rebound in the same function: distribute_setup.py opens two files as `f`).
        for node in PythonSyntax.within(scope, ast.Assign):
            if node.value is not opened or not (
                len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            ):
                continue
            handle, after = node.targets[0].id, node.lineno
            writes = sorted(
                (inner.lineno, inner.args[0])
                for inner in PythonSyntax.within(scope, ast.Call)
                if isinstance(inner.func, ast.Attribute)
                and inner.func.attr in ("write", "writelines")
                and isinstance(inner.func.value, ast.Name)
                and inner.func.value.id == handle
                and inner.args
                and inner.lineno >= after
            )
            if writes:
                nearest: ast.AST = writes[0][1]
                return nearest
        for node in PythonSyntax.within(scope, ast.With):
            for item in node.items:
                if item.context_expr is opened and isinstance(item.optional_vars, ast.Name):
                    handle = item.optional_vars.id
                    for inner in PythonSyntax.within(node, ast.Call):
                        func = inner.func
                        if (
                            isinstance(func, ast.Attribute)
                            and func.attr in ("write", "writelines")
                            and isinstance(func.value, ast.Name)
                            and func.value.id == handle
                            and inner.args
                        ):
                            found: ast.AST = inner.args[0]
                            return found
        return None

    def _only_a_path(self, node: ast.AST, bound: dict[str, ast.AST]) -> bool:
        """Built only from path calls, names and string literals holding no code."""
        for part in self._expanded(node, bound):
            if (
                isinstance(part, ast.Call)
                and (self._dotted(part.func) or "") not in self._PATH_CALLS
            ):
                return False
            if (
                isinstance(part, ast.Constant)
                and isinstance(part.value, str)
                and any(word in part.value for word in ("import", "exec", "eval", "__"))
            ):
                return False
        return True

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
