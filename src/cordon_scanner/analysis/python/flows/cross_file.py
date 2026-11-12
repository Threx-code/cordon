"""The cross-file maps a scan builds from all of a package's Python files before any file is analysed:
the HTTP clients, command runners, carried calls and machine-context collectors each file takes from
another (`ScanContext.python_imported_*`, `python_carried_calls`), and the names other files send
for it (`python_sent_names`). Built once here so each stage that seeds a context spreads the same
five."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from cordon_scanner.analysis.python.flows.carried_calls import CarriedCalls
from cordon_scanner.analysis.python.flows.imported_clients import (
    FileSummaries,
    ImportedClients,
    ModuleResolver,
)
from cordon_scanner.analysis.python.flows.sent_names import SentNames
from cordon_scanner.analysis.python.flows.staged.machine_collectors import MachineCollectors

if TYPE_CHECKING:
    from cordon_scanner.analysis.python.flows.imported_clients import ScannedFile


class CrossFileMaps:
    @staticmethod
    def of(units: Sequence[ScannedFile]) -> dict[str, Any]:
        """The five maps, by ScanContext field name, from one summary of each file: every file
        parsed once, one at a time (`FileSummaries`), never the package's trees together."""
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        if len(sources) < 2:
            return dict.fromkeys(CrossFileMaps.FIELDS)
        summaries = FileSummaries.build(
            sources,
            {
                "made": (None, ImportedClients._made_here),
                "runs": (ImportedClients._SINK_WORDS, ImportedClients._runs_here),
                "collects": MachineCollectors.exporter(),
                "sends": SentNames.exporter(),
            },
        )
        if len(summaries) < 2:
            return dict.fromkeys(CrossFileMaps.FIELDS)
        # Each import line resolved once for the three follows (`ModuleResolver`).
        resolve = ModuleResolver(summaries)
        return {
            "python_imported_clients": ImportedClients.follow(summaries, "made", resolve=resolve)
            or None,
            "python_imported_runners": ImportedClients.follow(
                summaries, "runs", modules=True, resolve=resolve
            )
            or None,
            "python_carried_calls": CarriedCalls.from_summaries(sources, summaries) or None,
            "python_imported_collectors": ImportedClients.follow(
                summaries, "collects", modules=True, resolve=resolve
            )
            or None,
            "python_sent_names": SentNames.from_summaries(summaries) or None,
        }

    FIELDS = (
        "python_imported_clients",
        "python_imported_runners",
        "python_carried_calls",
        "python_imported_collectors",
        "python_sent_names",
    )


__all__ = ["CrossFileMaps"]
