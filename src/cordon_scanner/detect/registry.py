"""Where the engine finds the detection layer's parts it uses by name.

The engine imports this layer only through its ports: `base`, the protocols, and this
module, the registry of what implements them. A detector, ecosystem or source the engine
does not name is found through `engine.registry` instead."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

#: What the engine uses of this layer by name, and the module that provides each: the one place
#: that knows, so the layer's modules can move without the engine changing. Each is imported
#: when it is first asked for (PEP 562), as the engine's own imports were.
ROLES: dict[str, tuple[str, str]] = {
    "BinaryDetector": ("cordon_scanner.detect.binary.binary", "BinaryDetector"),
    "CapabilityDetector": ("cordon_scanner.detect.code.capability.detector", "CapabilityDetector"),
    "ComposerPluginHooks": ("cordon_scanner.detect.supply.composer_plugins", "ComposerPluginHooks"),
    "DeclaredSource": ("cordon_scanner.detect.supply.manifest", "DeclaredSource"),
    "DownloadFlow": ("cordon_scanner.detect.code.download_flow", "DownloadFlow"),
    "ImportReachability": ("cordon_scanner.detect.supply.reachability", "ImportReachability"),
    "JudgeGate": ("cordon_scanner.detect.agents.agent_judge", "JudgeGate"),
    "LoadPath": ("cordon_scanner.detect.code.capability.load_path", "LoadPath"),
    "NATIVE_FORMATS": ("cordon_scanner.detect.binary.binary", "NATIVE_FORMATS"),
    "ReachedFlows": ("cordon_scanner.detect.code.reached_flows", "ReachedFlows"),
    "SBOM_NAMES": ("cordon_scanner.detect.supply.sbom", "SBOM_NAMES"),
    "SBOM_SUFFIXES": ("cordon_scanner.detect.supply.sbom", "SBOM_SUFFIXES"),
    "SERVER_SOURCE_SUFFIXES": ("cordon_scanner.detect.agents.agents", "_SERVER_SOURCE_SUFFIXES"),
    "Submodules": ("cordon_scanner.detect.source.submodules", "Submodules"),
}

if TYPE_CHECKING:
    from cordon_scanner.detect.agents.agent_judge import JudgeGate
    from cordon_scanner.detect.agents.agents import (
        _SERVER_SOURCE_SUFFIXES as SERVER_SOURCE_SUFFIXES,
    )
    from cordon_scanner.detect.binary.binary import NATIVE_FORMATS, BinaryDetector
    from cordon_scanner.detect.code.capability.detector import CapabilityDetector
    from cordon_scanner.detect.code.capability.load_path import LoadPath
    from cordon_scanner.detect.code.download_flow import DownloadFlow
    from cordon_scanner.detect.code.reached_flows import ReachedFlows
    from cordon_scanner.detect.source.submodules import Submodules
    from cordon_scanner.detect.supply.composer_plugins import ComposerPluginHooks
    from cordon_scanner.detect.supply.manifest import DeclaredSource
    from cordon_scanner.detect.supply.reachability import ImportReachability
    from cordon_scanner.detect.supply.sbom import SBOM_NAMES, SBOM_SUFFIXES


def __getattr__(name: str) -> object:
    """The implementation of one of `ROLES`, imported on first use."""
    try:
        module, attribute = ROLES[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(importlib.import_module(module), attribute)


__all__ = [
    "NATIVE_FORMATS",
    "ROLES",
    "SBOM_NAMES",
    "SBOM_SUFFIXES",
    "SERVER_SOURCE_SUFFIXES",
    "BinaryDetector",
    "CapabilityDetector",
    "ComposerPluginHooks",
    "DeclaredSource",
    "DownloadFlow",
    "ImportReachability",
    "JudgeGate",
    "LoadPath",
    "ReachedFlows",
    "Submodules",
]
