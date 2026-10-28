"""Where the engine finds the intelligence it consults.

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
    "AdvisoryBundle": ("cordon_scanner.intel.store.dbsync", "AdvisoryBundle"),
    "AdvisoryDatabase": ("cordon_scanner.intel.advisories.advisories", "AdvisoryDatabase"),
    "ECOSYSTEMS": ("cordon_scanner.intel.registries.registry_record", "ECOSYSTEMS"),
    "Ed25519": ("cordon_scanner.intel.provenance._ed25519", "Ed25519"),
    "FeedClient": ("cordon_scanner.intel.malware.feed", "FeedClient"),
    "LicenseCategory": ("cordon_scanner.intel.store.licenses", "LicenseCategory"),
    "LicenseClassifier": ("cordon_scanner.intel.store.licenses", "LicenseClassifier"),
    "MoreRegistries": ("cordon_scanner.intel.registries.more_registries", "MoreRegistries"),
    "RegistryError": ("cordon_scanner.intel.registries.registry_client", "RegistryError"),
    "RegistryRecord": ("cordon_scanner.intel.registries.registry_record", "RegistryRecord"),
    "ReleaseHistory": ("cordon_scanner.intel.registries.release_history", "ReleaseHistory"),
    "VersionRanges": ("cordon_scanner.intel.advisories.ranges", "VersionRanges"),
    "Versions": ("cordon_scanner.intel.advisories.versions", "Versions"),
    "YOUNG_DEPENDENCY_DAYS": (
        "cordon_scanner.intel.registries.release_history",
        "YOUNG_DEPENDENCY_DAYS",
    ),
}

if TYPE_CHECKING:
    from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase
    from cordon_scanner.intel.advisories.ranges import VersionRanges
    from cordon_scanner.intel.advisories.versions import Versions
    from cordon_scanner.intel.malware.feed import FeedClient
    from cordon_scanner.intel.provenance._ed25519 import Ed25519
    from cordon_scanner.intel.registries.more_registries import MoreRegistries
    from cordon_scanner.intel.registries.registry_client import RegistryError
    from cordon_scanner.intel.registries.registry_record import ECOSYSTEMS, RegistryRecord
    from cordon_scanner.intel.registries.release_history import (
        YOUNG_DEPENDENCY_DAYS,
        ReleaseHistory,
    )
    from cordon_scanner.intel.store.dbsync import AdvisoryBundle
    from cordon_scanner.intel.store.licenses import LicenseCategory, LicenseClassifier


def __getattr__(name: str) -> object:
    """The implementation of one of `ROLES`, imported on first use."""
    try:
        module, attribute = ROLES[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(importlib.import_module(module), attribute)


__all__ = [
    "ECOSYSTEMS",
    "ROLES",
    "YOUNG_DEPENDENCY_DAYS",
    "AdvisoryBundle",
    "AdvisoryDatabase",
    "Ed25519",
    "FeedClient",
    "LicenseCategory",
    "LicenseClassifier",
    "MoreRegistries",
    "RegistryError",
    "RegistryRecord",
    "ReleaseHistory",
    "VersionRanges",
    "Versions",
]
