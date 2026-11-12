"""Code loaded from a file that is not code: a module imported from a `.wav`, a script read out of
a `.png` and handed to `exec`, a zip archive imported under an image's name.

A package keeps its code in source and compiled files, and Python's loaders exist to import those.
Pointing a loader, `exec` or `compile` at a sound, an image, a text or a data file is the payload
carried where no reader of source looks (houdus 1.0.0 imports `assets/*.wav` through
`spec_from_file_location` and runs it with `exec_module`). The test is the path's extension, read
from the literals the path is built from: whatever the bytes are, a loader given a file named as
data is told to run something that was named so it would not be read.
"""

from __future__ import annotations

import ast
from pathlib import PurePosixPath
from typing import ClassVar

from cordon_scanner.analysis.python.analyzer_core import AnalyzerCore
from cordon_scanner.analysis.python.pyfacts import PythonFacts
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability


class DataFileCode(AnalyzerCore):
    """`_code_from_data_file` and what it needs."""

    #: Calls that import or run the file at their path argument (the last positional).
    LOADERS: ClassVar[frozenset[str]] = frozenset(
        {
            "spec_from_file_location",
            "SourceFileLoader",
            "SourcelessFileLoader",
            "ExtensionFileLoader",
            "run_path",
            "load_source",
            "load_compiled",
            "zipimporter",
        }
    )
    #: Calls that run the text or code object they are given.
    RUNNERS: ClassVar[frozenset[str]] = frozenset({"exec", "eval", "compile", "marshal.loads"})
    #: Calls that read a file's contents, by the path they are given or the file they act on.
    READERS: ClassVar[frozenset[str]] = frozenset(
        {"open", "read_text", "read_bytes", "io.open", "codecs.open", "get_data"}
    )
    #: What code is kept in: source, bytecode, extension modules and the archives zipimport reads.
    CODE_SUFFIXES: ClassVar[frozenset[str]] = frozenset(
        {".py", ".pyw", ".pyc", ".pyo", ".pyi", ".so", ".pyd", ".dll", ".dylib", ".zip", ".egg",
         ".whl", ".pyz"}
    )  # fmt: skip

    def _code_from_data_file(self, tree: ast.AST) -> None:
        """A loader or runner pointed at a file named as data: `code from a data file: <call> <ext>`."""
        constants = self._module_strings(tree)
        for call in PythonSyntax.of(tree, ast.Call):
            name = self._callee_name(call)
            if name in self.LOADERS and call.args:
                suffix = self._data_suffix(call.args[-1], constants)
                if suffix:
                    self._record(
                        Capability.EXECUTE, call, f"code from a data file: {name} {suffix}"
                    )
            elif self._dotted(call.func) in self.RUNNERS and call.args:
                suffix = self._read_from(call.args[0], constants)
                if suffix:
                    self._record(
                        Capability.EXECUTE,
                        call,
                        f"code from a data file: {self._dotted(call.func)} {suffix}",
                    )

    @staticmethod
    def _callee_name(call: ast.Call) -> str:
        func = call.func
        if isinstance(func, ast.Attribute):
            return func.attr
        return func.id if isinstance(func, ast.Name) else ""

    @staticmethod
    def _module_strings(tree: ast.AST) -> dict[str, ast.AST]:
        """Module- and function-level names bound once to a path expression."""
        bound: dict[str, ast.AST] = {}
        for node in PythonSyntax.of(tree, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                bound[node.targets[0].id] = node.value
        return bound

    def _read_from(self, node: ast.AST, constants: dict[str, ast.AST]) -> str | None:
        """The data suffix of a file whose contents `node` is: `open(P).read()`, `Path(P).read_text()`."""
        for call in PythonSyntax.within(node, ast.Call):
            name = self._callee_name(call)
            if name in self.READERS or self._dotted(call.func) in self.READERS:
                target = call.args[0] if call.args else call.func
                if isinstance(target, ast.Attribute) and not call.args:
                    target = target.value
                suffix = self._data_suffix(target, constants)
                if suffix:
                    return suffix
        if isinstance(node, ast.Name) and node.id in constants:
            return self._read_from(
                constants[node.id], {k: v for k, v in constants.items() if k != node.id}
            )
        return None

    def _data_suffix(
        self, path: ast.AST, constants: dict[str, ast.AST], depth: int = 0
    ) -> str | None:
        """The extension of the file a path expression names, when it is not one code is kept in."""
        if depth > 4:
            return None
        if isinstance(path, ast.Name) and path.id in constants:
            return self._data_suffix(constants[path.id], constants, depth + 1)
        last = self._last_piece(path, constants, depth)
        if last is None:
            return None
        suffix = PurePosixPath(last.replace("\\", "/")).suffix.lower()
        if not suffix or not suffix[1:].isalnum() or len(suffix) > 6:
            return None
        return None if suffix in self.CODE_SUFFIXES else suffix

    def _last_piece(self, node: ast.AST, constants: dict[str, ast.AST], depth: int) -> str | None:
        """The literal text a path ends with: the last argument of a join, the right of `/` or `+`."""
        value = PythonFacts.constant(node)
        if isinstance(value, str):
            return value
        if isinstance(node, ast.Name) and node.id in constants and depth < 4:
            return self._last_piece(constants[node.id], constants, depth + 1)
        if isinstance(node, ast.BinOp):
            return self._last_piece(node.right, constants, depth + 1)
        if isinstance(node, ast.JoinedStr) and node.values:
            tail = node.values[-1]
            return (
                tail.value
                if isinstance(tail, ast.Constant) and isinstance(tail.value, str)
                else None
            )
        if isinstance(node, ast.Call):
            name = self._callee_name(node)
            if name in ("join", "joinpath", "Path", "PurePath") and node.args:
                return self._last_piece(node.args[-1], constants, depth + 1)
            if (
                name in ("str", "fspath", "abspath", "realpath", "resolve", "expanduser")
                and node.args
            ):
                return self._last_piece(node.args[0], constants, depth + 1)
            if isinstance(node.func, ast.Attribute) and name in (
                "resolve",
                "absolute",
                "with_suffix",
            ):
                if name == "with_suffix" and node.args:
                    return self._last_piece(node.args[0], constants, depth + 1)
                return self._last_piece(node.func.value, constants, depth + 1)
        return None


__all__ = ["DataFileCode"]
