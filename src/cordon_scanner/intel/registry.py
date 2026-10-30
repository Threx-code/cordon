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
    "AtrEngine": ("cordon_scanner.intel.malware.atr", "AtrEngine"),
    "RuleLinks": ("cordon_scanner.intel.malware.atr", "RuleLinks"),
    "ATR_TEXT_KINDS": ("cordon_scanner.intel.malware.atr", "TEXT_KINDS"),
    "ATR_INSTRUCTION_TOLERANCE": ("cordon_scanner.intel.malware.atr", "INSTRUCTION_TOLERANCE"),
    "HallucinatedPackages": ("cordon_scanner.intel.malware.hallucinated", "HallucinatedPackages"),
    "CampaignFingerprint": ("cordon_scanner.intel.malware.campaign", "CampaignFingerprint"),
    "CampaignIndex": ("cordon_scanner.intel.malware.campaign", "CampaignIndex"),
    "CAMPAIGN_FACETS": ("cordon_scanner.intel.malware.campaign", "FACETS"),
    "FeedStore": ("cordon_scanner.intel.malware.feed", "FeedStore"),
    "AdvisoryTextSymbols": ("cordon_scanner.intel.advisories.advisory_text", "AdvisoryTextSymbols"),
    "AdvisoryBundle": ("cordon_scanner.intel.store.dbsync", "AdvisoryBundle"),
    "BundledAdvisories": ("cordon_scanner.intel.advisories.shipped", "ShippedAdvisories"),
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
    "EstablishedPackageNames": ("cordon_scanner.intel.registries.names", "EstablishedPackageNames"),
    "PopularPackageNames": ("cordon_scanner.intel.registries.names", "PopularPackageNames"),
    "RemovedPackageNames": ("cordon_scanner.intel.registries.removed", "RemovedNames"),
    "AdvisoryCveNames": ("cordon_scanner.intel.advisories.exploited", "ExploitedCatalogue"),
    "RegistryError": ("cordon_scanner.intel.registries.registry_client", "RegistryError"),
    "RegistryRecord": ("cordon_scanner.intel.registries.registry_record", "RegistryRecord"),
    "ReleaseHistory": ("cordon_scanner.intel.registries.release_history", "ReleaseHistory"),
    "VersionRanges": ("cordon_scanner.intel.advisories.ranges", "VersionRanges"),
    "Versions": ("cordon_scanner.intel.advisories.versions", "Versions"),
    "YOUNG_DEPENDENCY_DAYS": (
        "cordon_scanner.intel.registries.release_history",
        "YOUNG_DEPENDENCY_DAYS",
    ),
    "BazelProvenance": ("cordon_scanner.intel.provenance.bazel_provenance", "BazelProvenance"),
    "GitHubRepository": ("cordon_scanner.intel.provenance.github_repository", "GitHubRepository"),
    "HelmProvenance": ("cordon_scanner.intel.provenance.helm_provenance", "HelmProvenance"),
    "HomebrewProvenance": (
        "cordon_scanner.intel.provenance.homebrew_provenance",
        "HomebrewProvenance",
    ),
    "IntelDataFile": ("cordon_scanner.intel.store.datafile", "IntelDataFile"),
    "KNOWN_INSTALLERS": ("cordon_scanner.intel.registries.installers", "KNOWN_INSTALLERS"),
    "LiveMcp": ("cordon_scanner.intel.store.live_mcp", "LiveMcp"),
    "LiveMcpError": ("cordon_scanner.intel.store.live_mcp", "LiveMcpError"),
    "McpApprovals": ("cordon_scanner.intel.store.live_mcp", "McpApprovals"),
    "OfficialInstallers": ("cordon_scanner.intel.registries.installers", "OfficialInstallers"),
    "OpenPgp": ("cordon_scanner.intel.provenance.openpgp", "OpenPgp"),
    "PUBLIC_HOSTS": ("cordon_scanner.intel.registries.registry_hosts", "PUBLIC_HOSTS"),
    "PrivateRegistries": (
        "cordon_scanner.intel.registries.private_registries",
        "PrivateRegistries",
    ),
    "PublishedManifests": ("cordon_scanner.intel.registries.registry_client", "RegistryClient"),
    "RegistryArtifacts": ("cordon_scanner.intel.registries.registry_client", "RegistryClient"),
    "RegistryClient": ("cordon_scanner.intel.registries.registry_client", "RegistryClient"),
    "AnsibleSignatures": (
        "cordon_scanner.intel.provenance.ansible_signatures",
        "AnsibleSignatures",
    ),
    "AttestationDocuments": ("cordon_scanner.intel.provenance.attest", "AttestationDocuments"),
    "NEW_PACKAGE_DAYS": ("cordon_scanner.intel.registries.registry_client", "NEW_PACKAGE_DAYS"),
    "PackageNotFound": ("cordon_scanner.intel.registries.registry_client", "PackageNotFound"),
    "SigstoreVerification": ("cordon_scanner.intel.provenance.attest", "SigstoreVerification"),
    "YoungReleases": ("cordon_scanner.intel.registries.registry_client", "RegistryClient"),
}

if TYPE_CHECKING:
    import enum

    from cordon_scanner.intel.advisories import advisories as _intel_advisories_advisories
    from cordon_scanner.intel.advisories import advisory_text as _intel_advisories_advisory_text
    from cordon_scanner.intel.advisories import exploited as _intel_advisories_exploited
    from cordon_scanner.intel.advisories import osv_import as _intel_advisories_osv_import
    from cordon_scanner.intel.advisories import ranges as _intel_advisories_ranges
    from cordon_scanner.intel.advisories import shipped as _intel_advisories_shipped
    from cordon_scanner.intel.advisories import upstream_advisories as _intel_advisories_upstream
    from cordon_scanner.intel.advisories import versions as _intel_advisories_versions
    from cordon_scanner.intel.base import (
        AdvisoryCves,
        AdvisoryFileChecks,
        AdvisoryTextReading,
        ArtifactQueries,
        AttestationQueries,
        BottleProvenance,
        BundledAdvisoryDatabase,
        BundleKeys,
        BundleVerification,
        CampaignFacets,
        CampaignIndexes,
        ChartProvenance,
        CollectionSignatureQueries,
        DataFiles,
        EstablishedNames,
        Exploitations,
        ExploitLikelihoods,
        FeedOverlays,
        FeedStatus,
        HallucinationLookup,
        InstallerChecks,
        InstructionRules,
        Keyrings,
        LicenseExpressions,
        LiveServers,
        ModuleProvenance,
        OsvRepositories,
        PackageFactsQueries,
        PopularNames,
        PrivateRegistryQueries,
        PublishedManifestQueries,
        RangeMatching,
        RegistryRecords,
        RegistryVersions,
        ReleaseAgeQueries,
        ReleaseHistories,
        RemovedNameList,
        RepositoryHeads,
        RuleAddresses,
        SignatureCheck,
        ToolApprovals,
        UpstreamLookup,
        VersionOrdering,
    )
    from cordon_scanner.intel.malware import atr as _intel_malware_atr
    from cordon_scanner.intel.malware import campaign as _intel_malware_campaign
    from cordon_scanner.intel.malware import feed as _intel_malware_feed
    from cordon_scanner.intel.malware import hallucinated as _intel_malware_hallucinated
    from cordon_scanner.intel.provenance import _ed25519 as _intel_provenance__ed25519
    from cordon_scanner.intel.provenance import (
        ansible_signatures as _intel_provenance_ansible_signatures,
    )
    from cordon_scanner.intel.provenance import attest as _intel_provenance_attest
    from cordon_scanner.intel.provenance import (
        bazel_provenance as _intel_provenance_bazel_provenance,
    )
    from cordon_scanner.intel.provenance import (
        github_repository as _intel_provenance_github_repository,
    )
    from cordon_scanner.intel.provenance import helm_provenance as _intel_provenance_helm_provenance
    from cordon_scanner.intel.provenance import (
        homebrew_provenance as _intel_provenance_homebrew_provenance,
    )
    from cordon_scanner.intel.provenance import openpgp as _intel_provenance_openpgp
    from cordon_scanner.intel.registries import installers as _intel_registries_installers
    from cordon_scanner.intel.registries import more_registries as _intel_registries_more_registries
    from cordon_scanner.intel.registries import names as _intel_registries_names
    from cordon_scanner.intel.registries import (
        private_registries as _intel_registries_private_registries,
    )
    from cordon_scanner.intel.registries import registry_client as _intel_registries_registry_client
    from cordon_scanner.intel.registries import registry_hosts as _intel_registries_registry_hosts
    from cordon_scanner.intel.registries import registry_record as _intel_registries_registry_record
    from cordon_scanner.intel.registries import release_history as _intel_registries_release_history
    from cordon_scanner.intel.registries import removed as _intel_registries_removed
    from cordon_scanner.intel.store import datafile as _intel_store_datafile
    from cordon_scanner.intel.store import dbsync as _intel_store_dbsync
    from cordon_scanner.intel.store import licenses as _intel_store_licenses
    from cordon_scanner.intel.store import live_mcp as _intel_store_live_mcp

    # Each implementation, as the engine sees it: by its protocol (the type checker proves the
    # implementation conforms) or, for a plain value, by the value's type.
    AdvisoryBundle: BundleKeys = _intel_store_dbsync.AdvisoryBundle
    BundledAdvisories: BundledAdvisoryDatabase = _intel_advisories_shipped.ShippedAdvisories
    AdvisoryFiles: AdvisoryFileChecks = _intel_advisories_advisories.AdvisoryFiles
    ECOSYSTEMS: frozenset[str] = _intel_registries_registry_record.ECOSYSTEMS
    EUVD_PAGE: str = _intel_advisories_exploited.EUVD_PAGE
    Epss: ExploitLikelihoods = _intel_advisories_exploited.Epss
    ExploitedCatalogue: Exploitations = _intel_advisories_exploited.ExploitedCatalogue
    KEV_PAGE: str = _intel_advisories_exploited.KEV_PAGE
    Ed25519: SignatureCheck = _intel_provenance__ed25519.Ed25519
    FeedClient: FeedStatus = _intel_malware_feed.FeedClient
    LICENSE_UNKNOWN: enum.Enum = _intel_store_licenses.LicenseCategory.UNKNOWN
    LicenseClassifier: LicenseExpressions = _intel_store_licenses.LicenseClassifier
    MoreRegistries: RegistryVersions = _intel_registries_more_registries.MoreRegistries
    OsvImport: OsvRepositories = _intel_advisories_osv_import.OsvImport
    UPSTREAM_ECOSYSTEMS: frozenset[str] = _intel_advisories_upstream.SUPPORTED
    UpstreamAdvisories: UpstreamLookup = _intel_advisories_upstream.UpstreamAdvisories
    EstablishedPackageNames: EstablishedNames = _intel_registries_names.EstablishedPackageNames
    PopularPackageNames: PopularNames = _intel_registries_names.PopularPackageNames
    RemovedPackageNames: RemovedNameList = _intel_registries_removed.RemovedNames
    AdvisoryCveNames: AdvisoryCves = _intel_advisories_exploited.ExploitedCatalogue
    RegistryError: type[Exception] = _intel_registries_registry_client.RegistryError
    RegistryRecord: RegistryRecords = _intel_registries_registry_record.RegistryRecord
    ReleaseHistory: ReleaseHistories = _intel_registries_release_history.ReleaseHistory
    VersionRanges: RangeMatching = _intel_advisories_ranges.VersionRanges
    Versions: VersionOrdering = _intel_advisories_versions.Versions
    YOUNG_DEPENDENCY_DAYS: int = _intel_registries_release_history.YOUNG_DEPENDENCY_DAYS

    # The detectors' ports (intel/base.py, review 27 F2).
    BazelProvenance: ModuleProvenance = _intel_provenance_bazel_provenance.BazelProvenance
    GitHubRepository: RepositoryHeads = _intel_provenance_github_repository.GitHubRepository
    HelmProvenance: ChartProvenance = _intel_provenance_helm_provenance.HelmProvenance
    HomebrewProvenance: BottleProvenance = _intel_provenance_homebrew_provenance.HomebrewProvenance
    IntelDataFile: DataFiles = _intel_store_datafile.IntelDataFile
    KNOWN_INSTALLERS: tuple[tuple[str, str], ...] = _intel_registries_installers.KNOWN_INSTALLERS
    LiveMcp: LiveServers = _intel_store_live_mcp.LiveMcp
    LiveMcpError: type[Exception] = _intel_store_live_mcp.LiveMcpError
    McpApprovals: ToolApprovals = _intel_store_live_mcp.McpApprovals
    OfficialInstallers: InstallerChecks = _intel_registries_installers.OfficialInstallers
    OpenPgp: Keyrings = _intel_provenance_openpgp.OpenPgp
    PUBLIC_HOSTS: frozenset[str] = _intel_registries_registry_hosts.PUBLIC_HOSTS
    PrivateRegistries: PrivateRegistryQueries = (
        _intel_registries_private_registries.PrivateRegistries
    )
    PublishedManifests: PublishedManifestQueries = _intel_registries_registry_client.RegistryClient
    RegistryArtifacts: ArtifactQueries = _intel_registries_registry_client.RegistryClient
    RegistryClient: PackageFactsQueries = _intel_registries_registry_client.RegistryClient
    AtrEngine: InstructionRules = _intel_malware_atr.AtrEngine
    RuleLinks: RuleAddresses = _intel_malware_atr.RuleLinks
    ATR_TEXT_KINDS: tuple[str, ...] = _intel_malware_atr.TEXT_KINDS
    ATR_INSTRUCTION_TOLERANCE: int = _intel_malware_atr.INSTRUCTION_TOLERANCE
    HallucinatedPackages: HallucinationLookup = _intel_malware_hallucinated.HallucinatedPackages
    CampaignFingerprint: CampaignFacets = _intel_malware_campaign.CampaignFingerprint
    CampaignIndex: CampaignIndexes = _intel_malware_campaign.CampaignIndex
    CAMPAIGN_FACETS: tuple[str, ...] = _intel_malware_campaign.FACETS
    FeedStore: FeedOverlays = _intel_malware_feed.FeedStore
    AdvisoryTextSymbols: AdvisoryTextReading = _intel_advisories_advisory_text.AdvisoryTextSymbols
    AnsibleSignatures: CollectionSignatureQueries = (
        _intel_provenance_ansible_signatures.AnsibleSignatures
    )
    AttestationDocuments: AttestationQueries = _intel_provenance_attest.AttestationDocuments
    NEW_PACKAGE_DAYS: int = _intel_registries_registry_client.NEW_PACKAGE_DAYS
    PackageNotFound: type[Exception] = _intel_registries_registry_client.PackageNotFound
    SigstoreVerification: BundleVerification = _intel_provenance_attest.SigstoreVerification
    YoungReleases: ReleaseAgeQueries = _intel_registries_registry_client.RegistryClient


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
    "ATR_INSTRUCTION_TOLERANCE",
    "ATR_TEXT_KINDS",
    "CAMPAIGN_FACETS",
    "ECOSYSTEMS",
    "EUVD_PAGE",
    "KEV_PAGE",
    "KNOWN_INSTALLERS",
    "LICENSE_UNKNOWN",
    "NEW_PACKAGE_DAYS",
    "PUBLIC_HOSTS",
    "ROLES",
    "UPSTREAM_ECOSYSTEMS",
    "YOUNG_DEPENDENCY_DAYS",
    "AdvisoryBundle",
    "AdvisoryCveNames",
    "AdvisoryFiles",
    "AdvisoryTextSymbols",
    "AnsibleSignatures",
    "AtrEngine",
    "AttestationDocuments",
    "BazelProvenance",
    "BundledAdvisories",
    "CampaignFingerprint",
    "CampaignIndex",
    "Ed25519",
    "Epss",
    "EstablishedPackageNames",
    "ExploitedCatalogue",
    "FeedClient",
    "FeedStore",
    "GitHubRepository",
    "HallucinatedPackages",
    "HelmProvenance",
    "HomebrewProvenance",
    "IntelDataFile",
    "LicenseClassifier",
    "LiveMcp",
    "LiveMcpError",
    "McpApprovals",
    "MoreRegistries",
    "OfficialInstallers",
    "OpenPgp",
    "OsvImport",
    "PackageNotFound",
    "PopularPackageNames",
    "PrivateRegistries",
    "PublishedManifests",
    "RegistryArtifacts",
    "RegistryClient",
    "RegistryError",
    "RegistryRecord",
    "ReleaseHistory",
    "RemovedPackageNames",
    "RuleLinks",
    "SigstoreVerification",
    "UpstreamAdvisories",
    "VersionRanges",
    "Versions",
    "YoungReleases",
]
