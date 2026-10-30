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
    "AdvisoryFiles": ("cordon_scanner.intel.advisories.advisories", "AdvisoryFiles"),
    "ECOSYSTEMS": ("cordon_scanner.intel.registries.registry_record", "ECOSYSTEMS"),
    "EUVD_PAGE": ("cordon_scanner.intel.advisories.exploited", "EUVD_PAGE"),
    "Epss": ("cordon_scanner.intel.advisories.exploited", "Epss"),
    "ExploitedCatalogue": ("cordon_scanner.intel.advisories.exploited", "ExploitedCatalogue"),
    "KEV_PAGE": ("cordon_scanner.intel.advisories.exploited", "KEV_PAGE"),
    "Ed25519": ("cordon_scanner.intel.provenance._ed25519", "Ed25519"),
    "FeedClient": ("cordon_scanner.intel.malware.feed", "FeedClient"),
    "LICENSE_UNKNOWN": ("cordon_scanner.intel.store.licenses", "LicenseCategory.UNKNOWN"),
    "LicenseClassifier": ("cordon_scanner.intel.store.licenses", "LicenseClassifier"),
    "MoreRegistries": ("cordon_scanner.intel.registries.more_registries", "MoreRegistries"),
    "OsvImport": ("cordon_scanner.intel.advisories.osv_import", "OsvImport"),
    "UPSTREAM_ECOSYSTEMS": ("cordon_scanner.intel.advisories.upstream_advisories", "SUPPORTED"),
    "UpstreamAdvisories": (
        "cordon_scanner.intel.advisories.upstream_advisories",
        "UpstreamAdvisories",
    ),
    "BuiltinPackageNames": ("cordon_scanner.intel.registries.names", "BuiltinPackageNames"),
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
    import enum

    from cordon_scanner.intel.advisories import advisories as _intel_advisories_advisories
    from cordon_scanner.intel.advisories import exploited as _intel_advisories_exploited
    from cordon_scanner.intel.advisories import osv_import as _intel_advisories_osv_import
    from cordon_scanner.intel.advisories import ranges as _intel_advisories_ranges
    from cordon_scanner.intel.advisories import upstream_advisories as _intel_advisories_upstream
    from cordon_scanner.intel.advisories import versions as _intel_advisories_versions
    from cordon_scanner.intel.base import (
        AdvisoryDatabases,
        AdvisoryFileChecks,
        BundleKeys,
        Exploitations,
        ExploitLikelihoods,
        FeedStatus,
        LicenseClassification,
        OsvRepositories,
        PackageNames,
        RangeMatching,
        RegistryRecords,
        RegistryVersions,
        ReleaseHistories,
        SignatureCheck,
        UpstreamLookup,
        VersionOrdering,
    )
    from cordon_scanner.intel.malware import feed as _intel_malware_feed
    from cordon_scanner.intel.provenance import _ed25519 as _intel_provenance__ed25519
    from cordon_scanner.intel.registries import more_registries as _intel_registries_more_registries
    from cordon_scanner.intel.registries import names as _intel_registries_names
    from cordon_scanner.intel.registries import registry_client as _intel_registries_registry_client
    from cordon_scanner.intel.registries import registry_record as _intel_registries_registry_record
    from cordon_scanner.intel.registries import release_history as _intel_registries_release_history
    from cordon_scanner.intel.store import dbsync as _intel_store_dbsync
    from cordon_scanner.intel.store import licenses as _intel_store_licenses

    # Each implementation, as the engine sees it: by its protocol (the type checker proves the
    # implementation conforms) or, for a plain value, by the value's type.
    AdvisoryBundle: BundleKeys = _intel_store_dbsync.AdvisoryBundle
    AdvisoryDatabase: AdvisoryDatabases = _intel_advisories_advisories.AdvisoryDatabase
    AdvisoryFiles: AdvisoryFileChecks = _intel_advisories_advisories.AdvisoryFiles
    ECOSYSTEMS: frozenset[str] = _intel_registries_registry_record.ECOSYSTEMS
    EUVD_PAGE: str = _intel_advisories_exploited.EUVD_PAGE
    Epss: ExploitLikelihoods = _intel_advisories_exploited.Epss
    ExploitedCatalogue: Exploitations = _intel_advisories_exploited.ExploitedCatalogue
    KEV_PAGE: str = _intel_advisories_exploited.KEV_PAGE
    Ed25519: SignatureCheck = _intel_provenance__ed25519.Ed25519
    FeedClient: FeedStatus = _intel_malware_feed.FeedClient
    LICENSE_UNKNOWN: enum.Enum = _intel_store_licenses.LicenseCategory.UNKNOWN
    LicenseClassifier: LicenseClassification = _intel_store_licenses.LicenseClassifier
    MoreRegistries: RegistryVersions = _intel_registries_more_registries.MoreRegistries
    OsvImport: OsvRepositories = _intel_advisories_osv_import.OsvImport
    UPSTREAM_ECOSYSTEMS: frozenset[str] = _intel_advisories_upstream.SUPPORTED
    UpstreamAdvisories: UpstreamLookup = _intel_advisories_upstream.UpstreamAdvisories
    BuiltinPackageNames: PackageNames = _intel_registries_names.BuiltinPackageNames
    RegistryError: type[Exception] = _intel_registries_registry_client.RegistryError
    RegistryRecord: RegistryRecords = _intel_registries_registry_record.RegistryRecord
    ReleaseHistory: ReleaseHistories = _intel_registries_release_history.ReleaseHistory
    VersionRanges: RangeMatching = _intel_advisories_ranges.VersionRanges
    Versions: VersionOrdering = _intel_advisories_versions.Versions
    YOUNG_DEPENDENCY_DAYS: int = _intel_registries_release_history.YOUNG_DEPENDENCY_DAYS


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
    "ECOSYSTEMS",
    "EUVD_PAGE",
    "KEV_PAGE",
    "LICENSE_UNKNOWN",
    "ROLES",
    "UPSTREAM_ECOSYSTEMS",
    "YOUNG_DEPENDENCY_DAYS",
    "AdvisoryBundle",
    "AdvisoryDatabase",
    "AdvisoryFiles",
    "BuiltinPackageNames",
    "Ed25519",
    "Epss",
    "ExploitedCatalogue",
    "FeedClient",
    "LicenseClassifier",
    "MoreRegistries",
    "OsvImport",
    "RegistryError",
    "RegistryRecord",
    "ReleaseHistory",
    "UpstreamAdvisories",
    "VersionRanges",
    "Versions",
]
