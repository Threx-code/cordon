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
from cordon_scanner.analysis.python.flows.imported_clients import (
    FileSummaries,
    FileSummary,
    ImportedClients,
    ScannedFile,
)
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class CarriedCalls:
    """`{defining path: {function: "0,2"}}`: the parameter positions an importer passes carried."""

    @classmethod
    def of(cls, sources: Mapping[str, str]) -> dict[str, dict[str, str]]:
        return cls.from_summaries(sources, FileSummaries.build(sources, {}))

    @classmethod
    def from_summaries(
        cls, sources: Mapping[str, str], summaries: Mapping[str, FileSummary]
    ) -> dict[str, dict[str, str]]:
        """Each importing file parsed again, alone, for its calls: the summaries say which file
        defines what, so no two trees are alive at once."""
        if len(summaries) < 2:
            return {}
        found: dict[str, dict[str, set[int]]] = {}
        for path, summary in summaries.items():
            imported = cls._imported_functions(path, summary, summaries)
            if not imported:
                continue
            try:
                tree = PythonSyntax.parse(sources[path])
            except (SyntaxError, ValueError, RecursionError):
                # S2: summarised from this very text a moment ago; a parse that fails now offers
                # nothing to carry, and the file's own analyser reports it.
                continue
            module_names = DecodedDrops._module_bound_names(tree)
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
            del tree
        return {
            path: {name: ",".join(str(i) for i in sorted(p)[:16]) for name, p in names.items()}
            for path, names in found.items()
        }

    @staticmethod
    def _imported_functions(
        path: str, summary: FileSummary, summaries: Mapping[str, FileSummary]
    ) -> dict[str, tuple[str, str]]:
        """Local name -> (defining file, function name) for `from <package module> import f`."""
        out: dict[str, tuple[str, str]] = {}
        for node in summary.imports:
            source = ImportedClients._module_file(path, node, summaries)
            if source is None or source == path:
                continue
            defined = summaries[source].functions
            for name, asname in node.names:
                if name in defined:
                    out[asname or name] = (source, name)
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
