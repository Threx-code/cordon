"""The implant facts of one syntax tree, in the order each reads the ones before it.

Moved out of `PythonAnalyzer.analyse` (its line limit): a shipped program's run is a run that
persistence beside it reads, and an autostart is hidden when its launcher is both a script host and
a program the package ships.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.flows.implants.backdoor_writes import BackdoorWrites
from cordon_scanner.analysis.python.flows.implants.clipboard_replace import ClipboardReplace
from cordon_scanner.analysis.python.flows.implants.cloud_leak import CloudLeak
from cordon_scanner.analysis.python.flows.implants.foreign_index import ForeignIndex
from cordon_scanner.analysis.python.flows.implants.hidden_launch import HiddenLaunch
from cordon_scanner.analysis.python.flows.implants.ip_logger import IpLoggerFetch
from cordon_scanner.analysis.python.flows.implants.key_capture import KeyCapture
from cordon_scanner.analysis.python.flows.implants.persist_at_load import PersistAtLoad
from cordon_scanner.analysis.python.flows.implants.persist_runs import (
    AUTOSTART_WORD,
    RUN_DETAILS,
    PersistRuns,
)
from cordon_scanner.analysis.python.flows.implants.shipped_programs import ShippedPrograms
from cordon_scanner.analysis.python.pyfacts import AstHit
from cordon_scanner.foundation.capabilities import Capability

if TYPE_CHECKING:
    from collections.abc import Sequence


class ImplantFacts:
    """`hits`: what the implant flows add to the hits the analyser already has."""

    #: Flows that report one detail per line they find.
    LINE_FLOWS = (
        (CloudLeak, Capability.FLOW, "machine facts uploaded"),
        (IpLoggerFetch, Capability.FLOW, "ip logger fetched"),
        (KeyCapture, Capability.FLOW, "keystrokes logged"),
        (ClipboardReplace, Capability.FLOW, "clipboard replaced"),
        (ForeignIndex, Capability.SPAWN, "foreign index install"),
        (PersistAtLoad, Capability.FLOW, "persist at load"),
    )

    @classmethod
    def hits(cls, tree: ast.Module, source: str, existing: Sequence[AstHit]) -> list[AstHit]:
        out = [
            AstHit(Capability.SPAWN, line, "shipped program run")
            for line in ShippedPrograms.lines(tree)
        ]
        runs = frozenset(
            h.line for h in (*existing, *out) if any(d in h.detail for d in RUN_DETAILS)
        )
        out += [
            AstHit(Capability.FLOW, line, "persist and run")
            for line in PersistRuns.lines(tree, runs)
        ]
        hidden = set(
            PersistRuns.lines(
                tree, frozenset(HiddenLaunch.script_host_lines(tree)), source, AUTOSTART_WORD
            )
        ) & set(
            PersistRuns.lines(
                tree, frozenset(ShippedPrograms.path_lines(tree)), source, AUTOSTART_WORD
            )
        )
        out += [AstHit(Capability.FLOW, line, "autostart hidden") for line in sorted(hidden)]
        for flow, capability, detail in cls.LINE_FLOWS:
            out += [AstHit(capability, line, detail) for line in flow.lines(tree)]
        out += [
            AstHit(
                Capability.PERSIST,
                line,
                f"backdoor write: {kind}" + (" carried" if carried else ""),
            )
            for line, kind, carried in BackdoorWrites.hits(tree)
        ]
        return out


__all__ = ["ImplantFacts"]
