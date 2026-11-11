"""The cross-file maps a scan builds from all of a package's Python files before any file is analysed:
the HTTP clients, command runners, carried calls and machine-context collectors each file takes from
another (`ScanContext.python_imported_*`, `python_carried_calls`). Built once here so each stage
that seeds a context spreads the same four."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from cordon_scanner.analysis.python.flows.carried_calls import CarriedCalls
from cordon_scanner.analysis.python.flows.imported_clients import ImportedClients
from cordon_scanner.analysis.python.flows.staged.machine_collectors import MachineCollectors

if TYPE_CHECKING:
    from cordon_scanner.analysis.python.flows.imported_clients import ScannedFile


class CrossFileMaps:
    @staticmethod
    def of(units: Sequence[ScannedFile]) -> dict[str, Any]:
        """The four maps, by ScanContext field name."""
        return {
            "python_imported_clients": ImportedClients.of_units(units),
            "python_imported_runners": ImportedClients.runners_of_units(units),
            "python_carried_calls": CarriedCalls.of_units(units),
            "python_imported_collectors": MachineCollectors.of_units(units),
        }


__all__ = ["CrossFileMaps"]
