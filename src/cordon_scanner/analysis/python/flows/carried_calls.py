"""Which parameters of a package's functions another of its files passes a carried value: the
cross-file half of `DecodedDrops._carried_parameters`.

`pkg/drop.py: def drop(blob): ...decode, write, run` called as `drop(BLOB)` from `pkg/__init__.py`
after `from .drop import drop` drops a payload the package carries, one file over (the lead,
2026-11-11). This pass reads every Python file of the package once, finds each call of a function
imported from another of its files, and records the positions that call passes a literal, a module
name or attribute, a call over those, or a file read. The defining file's analyser then counts those
parameters as carried. Parsed, never executed; only files present in the scan are followed.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from typing import Any

from cordon_scanner.analysis.python.flows.decoded_drops import DecodedDrops
from cordon_scanner.analysis.python.flows.imported_clients import ImportedClients, ScannedFile
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class CarriedCalls:
    """`{defining path: {function: "0,2"}}`: the parameter positions an importer passes carried."""

    @classmethod
    def of(cls, sources: Mapping[str, str]) -> dict[str, dict[str, str]]:
        trees = ImportedClients._trees(sources)
        if len(trees) < 2:
            return {}
        found: dict[str, dict[str, set[int]]] = {}
        for path, tree in trees.items():
            module_names = DecodedDrops._module_bound_names(tree)
            imported = cls._imported_functions(path, tree, trees)
            if not imported:
                continue
            for call in PythonSyntax.of(tree, ast.Call):
                if not isinstance(call.func, ast.Name) or call.func.id not in imported:
                    continue
                source, name = imported[call.func.id]
                positions = {
                    i
                    for i, argument in enumerate(call.args)
                    if not isinstance(argument, ast.Starred)
                    and DecodedDrops._carried(argument, module_names)
                }
                if positions:
                    found.setdefault(source, {}).setdefault(name, set()).update(positions)
        return {
            path: {name: ",".join(str(i) for i in sorted(p)[:16]) for name, p in names.items()}
            for path, names in found.items()
        }

    @staticmethod
    def _imported_functions(
        path: str, tree: ast.Module, trees: Mapping[str, ast.Module]
    ) -> dict[str, tuple[str, str]]:
        """Local name -> (defining file, function name) for `from <package module> import f`."""
        out: dict[str, tuple[str, str]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            source = ImportedClients._module_file(path, node, trees)
            if source is None or source == path:
                continue
            defined = {
                f.name
                for f in trees[source].body
                if isinstance(f, ast.FunctionDef | ast.AsyncFunctionDef)
            }
            for alias in node.names:
                if alias.name in defined:
                    out[alias.asname or alias.name] = (source, alias.name)
        return out

    @classmethod
    def of_units(cls, units: Sequence[ScannedFile]) -> dict[str, dict[str, str]] | None:
        """`of` over a scan's Python files (`ScanContext.python_carried_calls`), or None."""
        sources: dict[str, Any] = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if len(sources) < 2:
            return None
        return cls.of(sources) or None


__all__ = ["CarriedCalls"]
