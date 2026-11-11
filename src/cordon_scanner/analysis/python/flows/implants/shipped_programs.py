"""A program the package ships, started by the package.

`subprocess.run([executable, ...])` where `executable` is built from `__file__` or from the package's
resource directory (`importlib.resources.files`, `pkg_resources.resource_filename`) runs a file that
came inside the archive, not a program the user installed. That is what a wrapper for ruff or uv does
with its binary, and what a dropper does with the one it carries. Whether it is the first or the second
is what the archive says (a platform-tagged wheel holds one; a pure wheel has no business doing it), so
this module records only the fact: the line of each start of such a path.

`lines` returns the line of each process started with a path derived from the file or its resources,
and `made_executable` the line of each mode change on one.
"""

from __future__ import annotations

import ast
from typing import ClassVar

from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow


class ShippedPrograms(PythonValueFlow):
    #: Calls that give the path of a file in the package's own resources.
    RESOURCES: ClassVar[frozenset[str]] = frozenset(
        {"resource_filename", "files", "as_file", "get_resource_filename", "path", "resource_path"}
    )
    #: Calls that start a program in place of this one.
    REPLACES: ClassVar[frozenset[str]] = frozenset(
        {
            "os.execv",
            "os.execve",
            "os.execvp",
            "os.execvpe",
            "os.execl",
            "os.execle",
            "os.execlp",
            "os.execlpe",
            "os.startfile",
            "os.spawnv",
            "os.spawnl",
        }
    )

    def seed(self, node: ast.AST) -> Label | None:
        if isinstance(node, ast.Name) and node.id == "__file__":
            return node.lineno
        if isinstance(node, ast.Call):
            name = self.name(node.func)
            dotted = self.dotted(node.func) or ""
            if name in self.RESOURCES and (
                "resources" in dotted
                or "pkg_resources" in dotted
                or name in ("resource_filename", "get_resource_filename", "resource_path")
            ):
                return node.lineno
        return None

    @classmethod
    def lines(cls, tree: ast.AST) -> list[int]:
        analysis = cls(tree)
        if not analysis.index() or not analysis.seeds:
            return []
        analysis.flow()
        out: set[int] = set()
        for node in analysis.calls:
            dotted = analysis.dotted(node.func) or ""
            name = analysis.name(node.func) or ""
            starts = (
                dotted in analysis.PROCESS or name in analysis.PROCESS or dotted in cls.REPLACES
            )
            if starts and node.args and analysis.taint(node.args[0]):
                out.add(node.lineno)
        return sorted(out)

    @classmethod
    def path_lines(cls, tree: ast.AST) -> list[int]:
        """The lines that build a path from the file or from the package's resources."""
        analysis = cls(tree)
        analysis.index()
        return sorted(set(analysis.seeds.values()))

    @classmethod
    def made_executable(cls, tree: ast.AST) -> list[int]:
        analysis = cls(tree)
        if not analysis.index() or not analysis.seeds:
            return []
        analysis.flow()
        out: list[int] = []
        for node in analysis.calls:
            name = analysis.name(node.func) or ""
            if name in ("chmod", "lchmod") and (
                (node.args and analysis.taint(node.args[0]))
                or (isinstance(node.func, ast.Attribute) and analysis.receiver(node))
            ):
                out.append(node.lineno)
        return sorted(out)


__all__ = ["ShippedPrograms"]
