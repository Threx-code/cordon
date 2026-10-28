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
    "BinaryDetector": ("cordon_scanner.detect.binary.detector", "BinaryDetector"),
    "ComposerPluginHooks": ("cordon_scanner.detect.supply.composer_plugins", "ComposerPluginHooks"),
    "DeclaredSource": ("cordon_scanner.detect.supply.manifests.sources", "DeclaredSource"),
    "DownloadFlow": ("cordon_scanner.detect.code.download_flow", "DownloadFlow"),
    "ImportReachability": ("cordon_scanner.detect.supply.reachability", "ImportReachability"),
    "JudgeGate": ("cordon_scanner.detect.agents.language_model_judge", "JudgeGate"),
    "LoadPath": ("cordon_scanner.detect.code.capability.load_path", "LoadPath"),
    "NATIVE_FORMATS": ("cordon_scanner.detect.binary.detector", "NATIVE_FORMATS"),
    "ReachedFlows": ("cordon_scanner.detect.code.reached_flows", "ReachedFlows"),
    "SBOM_NAMES": ("cordon_scanner.detect.supply.sbom", "SBOM_NAMES"),
    "SBOM_SUFFIXES": ("cordon_scanner.detect.supply.sbom", "SBOM_SUFFIXES"),
    "ServerSources": ("cordon_scanner.detect.agents.mcp_servers.source", "ServerSources"),
    "Submodules": ("cordon_scanner.detect.source.submodules", "Submodules"),
}

if TYPE_CHECKING:
    from cordon_scanner.detect.agents import (
        language_model_judge as _detect_agents_language_model_judge,
    )
    from cordon_scanner.detect.agents.mcp_servers import source as _detect_agents_mcp_servers_source
    from cordon_scanner.detect.base import (
        BinaryIdentification,
        ComposerPluginPaths,
        DeclaredSourceKinds,
        DownloadRunning,
        ImportReachabilityNotes,
        JudgeScheduling,
        ReachedFlowFacts,
        ServerSourceFinding,
        SkillScripts,
        SubmoduleDependencies,
    )
    from cordon_scanner.detect.binary import detector as _detect_binary_detector
    from cordon_scanner.detect.code import download_flow as _detect_code_download_flow
    from cordon_scanner.detect.code import reached_flows as _detect_code_reached_flows
    from cordon_scanner.detect.code.capability import load_path as _detect_code_capability_load_path
    from cordon_scanner.detect.source import submodules as _detect_source_submodules
    from cordon_scanner.detect.supply import composer_plugins as _detect_supply_composer_plugins
    from cordon_scanner.detect.supply import reachability as _detect_supply_reachability
    from cordon_scanner.detect.supply import sbom as _detect_supply_sbom
    from cordon_scanner.detect.supply.manifests import sources as _detect_supply_manifests_sources

    # Each implementation, as the engine sees it: by its protocol (the type checker proves the
    # implementation conforms) or, for a plain value, by the value's type.
    BinaryDetector: BinaryIdentification = _detect_binary_detector.BinaryDetector
    ComposerPluginHooks: ComposerPluginPaths = _detect_supply_composer_plugins.ComposerPluginHooks
    DeclaredSource: DeclaredSourceKinds = _detect_supply_manifests_sources.DeclaredSource
    DownloadFlow: DownloadRunning = _detect_code_download_flow.DownloadFlow
    ImportReachability: ImportReachabilityNotes = _detect_supply_reachability.ImportReachability
    JudgeGate: JudgeScheduling = _detect_agents_language_model_judge.JudgeGate
    LoadPath: SkillScripts = _detect_code_capability_load_path.LoadPath
    NATIVE_FORMATS: frozenset[str] = _detect_binary_detector.NATIVE_FORMATS
    ReachedFlows: ReachedFlowFacts = _detect_code_reached_flows.ReachedFlows
    SBOM_NAMES: tuple[str, ...] = _detect_supply_sbom.SBOM_NAMES
    SBOM_SUFFIXES: tuple[str, ...] = _detect_supply_sbom.SBOM_SUFFIXES
    ServerSources: ServerSourceFinding = _detect_agents_mcp_servers_source.ServerSources
    Submodules: SubmoduleDependencies = _detect_source_submodules.Submodules


def __getattr__(name: str) -> object:
    """The implementation of one of `ROLES`, imported on first use."""
    try:
        module, attribute = ROLES[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    found: object = importlib.import_module(module)
    for part in attribute.split("."):  # a class's member: `Class.MEMBER`
        found = getattr(found, part)
    return found


__all__ = [
    "NATIVE_FORMATS",
    "ROLES",
    "SBOM_NAMES",
    "SBOM_SUFFIXES",
    "BinaryDetector",
    "ComposerPluginHooks",
    "DeclaredSource",
    "DownloadFlow",
    "ImportReachability",
    "JudgeGate",
    "LoadPath",
    "ReachedFlows",
    "ServerSources",
    "Submodules",
]
