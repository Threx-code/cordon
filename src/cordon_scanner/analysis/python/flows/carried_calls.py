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
from typing import Any, ClassVar

from cordon_scanner.analysis.python.flows.decoded_drops import DecodedDrops
from cordon_scanner.analysis.python.flows.imported_clients import (
    Exporter,
    FileSummaries,
    FileSummary,
    ModuleResolver,
    ScannedFile,
)
from cordon_scanner.analysis.python.pysyntax import PythonSyntax


class CarriedCalls:
    """`{defining path: {function: "0,2"}}`: the parameter positions an importer passes carried."""

    #: The summary's entry (`FileSummary.exported`) this map reads.
    KIND: ClassVar[str] = "calls"

    @classmethod
    def of(cls, sources: Mapping[str, str]) -> dict[str, dict[str, str]]:
        return cls.from_summaries(FileSummaries.build(sources, {cls.KIND: cls.exporter()}))

    @classmethod
    def exporter(cls) -> Exporter:
        """The summary's reading of one file (`_calls_here`), made in the same parse as the rest of
        the summary: the file was parsed a second time for this alone (litellm 1.88.0rc2, 0.8.0)."""
        return (None, cls._calls_here)

    @staticmethod
    def _calls_here(tree: ast.Module) -> dict[str, str]:
        """`{local name: "0,2"}`: for each name the file takes with `from ... import`, the argument
        positions where a call of it by that name passes a carried value, over all its calls. Which
        of those names are another file's functions is the summaries' to say (`from_summaries`)."""
        taken = {
            alias.asname or alias.name
            for node in PythonSyntax.walked_of(tree, ast.ImportFrom)
            for alias in node.names
            if alias.name != "*"
        }
        if not taken:
            return {}
        module_names: frozenset[str] | None = None
        found: dict[str, set[int]] = {}
        for call in PythonSyntax.walked_of(tree, ast.Call):
            if not isinstance(call.func, ast.Name) or call.func.id not in taken:
                continue
            if module_names is None:
                module_names = DecodedDrops._module_bound_names(tree)
            positions = {
                i
                for i, argument in enumerate(call.args)
                if not isinstance(argument, ast.Starred)
                and DecodedDrops._carried(argument, module_names)
            }
            if positions:
                found.setdefault(call.func.id, set()).update(positions)
        return {name: ",".join(str(i) for i in sorted(p)) for name, p in found.items()}

    @classmethod
    def from_summaries(
        cls, summaries: Mapping[str, FileSummary], resolve: ModuleResolver | None = None
    ) -> dict[str, dict[str, str]]:
        """Each file's carried calls (its summary's `calls`) of a function it imports from another
        of the package's files, by the defining file. `resolve`, made over these summaries, may be
        shared with the other maps (`CrossFileMaps`)."""
        if len(summaries) < 2:
            return {}
        resolve = resolve or ModuleResolver(summaries)
        found: dict[str, dict[str, set[int]]] = {}
        for path, summary in summaries.items():
            calls = summary.exported.get(cls.KIND) or {}
            if not calls:
                continue
            imported = cls._imported_functions(path, summary, summaries, resolve)
            for local, positions in calls.items():
                if local in imported:
                    source, name = imported[local]
                    found.setdefault(source, {}).setdefault(name, set()).update(
                        int(p) for p in positions.split(",")
                    )
        return {
            path: {name: ",".join(str(i) for i in sorted(p)[:16]) for name, p in names.items()}
            for path, names in found.items()
        }

    @staticmethod
    def _imported_functions(
        path: str,
        summary: FileSummary,
        summaries: Mapping[str, FileSummary],
        resolve: ModuleResolver,
    ) -> dict[str, tuple[str, str]]:
        """Local name -> (defining file, function name) for `from <package module> import f`."""
        out: dict[str, tuple[str, str]] = {}
        for node in summary.imports:
            source = resolve(path, node)
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
