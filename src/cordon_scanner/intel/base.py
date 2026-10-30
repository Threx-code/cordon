"""The intel layer's ports: what the engine and the decision layer consult, as protocols."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence
    from collections.abc import Set as AbstractSet
    from pathlib import Path
    from typing import Any

    from cordon_scanner.foundation.results import Dependency
    from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
    from cordon_scanner.intel.provenance.helm_provenance import ChartCheck
    from cordon_scanner.intel.provenance.homebrew_provenance import BottleCheck
    from cordon_scanner.intel.provenance.openpgp import Keyring
    from cordon_scanner.intel.registries.private_registries import PrivateRegistry
    from cordon_scanner.intel.registries.registry_client import PackageArchive, PackageFacts
    from cordon_scanner.intel.store.live_mcp import ServedTool

# Engine-facing ports: what the engine uses of this layer, as protocols. `registry` hands the engine
# each implementation typed by one of these, and the type checker proves the implementation
# conforms, so the engine never sees a concrete adapter type.


class Advisories(Protocol):
    """What the engine uses of instances of `AdvisoryDatabase`."""

    def covers(self, ecosystem: str) -> bool: ...
    def matching(
        self, ecosystem: str, name: str, version: str | None
    ) -> tuple[AdvisoryRecord, ...]: ...


class AdvisoryCatalog(Advisories, Protocol):
    """What the advisory detector uses of instances of `AdvisoryDatabase`, beyond the engine's: every
    record about a package, whether there is anything to match, and when the data was built."""

    @property
    def is_empty(self) -> bool: ...
    @property
    def meta(self) -> AdvisoryMeta: ...
    def for_package(self, ecosystem: str, name: str) -> tuple[AdvisoryRecord, ...]: ...


class AdvisoryMeta(Protocol):
    """When and from where the advisory data was built (`DatabaseMeta`)."""

    @property
    def built_at(self) -> str: ...
    @property
    def sources(self) -> tuple[str, ...]: ...
    @property
    def record_count(self) -> int: ...
    @property
    def filtered(self) -> bool: ...


class AdvisoryRecord(Protocol):
    """What the engine and the detectors read of one `Advisory`: its fields, and whether it covers
    a version."""

    @property
    def identifier(self) -> str: ...
    @property
    def malicious(self) -> bool: ...
    @property
    def reference(self) -> str: ...
    @property
    def summary(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def aliases(self) -> tuple[str, ...]: ...
    @property
    def versions(self) -> tuple[str, ...]: ...
    @property
    def introduced(self) -> str | None: ...
    @property
    def fixed(self) -> str | None: ...
    @property
    def last_affected(self) -> str | None: ...
    @property
    def repositories(self) -> tuple[str, ...]: ...
    def affects(self, version: str | None) -> bool: ...


class Exploitations(Protocol):
    """What the detectors use of the class `ExploitedCatalogue`: the newest known-exploited catalogue
    (CISA KEV, ENISA EUVD)."""

    def catalogue(self) -> ExploitedLookup: ...


class AdvisoryCves(Protocol):
    """Every CVE an advisory names (`ExploitedCatalogue.cves_of`), for the advisory findings."""

    def cves_of(self, advisory: AdvisoryRecord) -> set[str]: ...


class ExploitedLookup(Protocol):
    """One catalogue (`Catalogue`): the exploitation recorded for any of a set of CVEs."""

    def lookup(self, cves: set[str]) -> ExploitationFacts | None: ...


class ExploitationFacts(Protocol):
    """One CVE's recorded exploitation (`Exploitation`)."""

    def describe(self) -> str: ...
    def references(self) -> tuple[str, ...]: ...


class ExploitLikelihoods(Protocol):
    """What the detectors use of the class `Epss`: the highest-probability score among some CVEs."""

    def lookup(self, cves: set[str]) -> LikelihoodFacts | None: ...


class LikelihoodFacts(Protocol):
    """One EPSS score (`EpssScore`)."""

    def describe(self) -> str: ...


class UpstreamLookup(Protocol):
    """What the advisory detector asks for packages no advisory source covers (the class
    `UpstreamAdvisories`): OSV through their upstreams when online, then NVD, merged."""

    def for_graph(
        self, dependencies: Iterable[Dependency], covers: Callable[[str], bool], *, offline: bool
    ) -> UpstreamFindings | None: ...


class UpstreamFindings(Protocol):
    """What the detector reads of that answer (`UpstreamResult`): advisories by purl, the purls
    checked, and why the others were not."""

    @property
    def advisories(self) -> Mapping[str, Sequence[AdvisoryRecord]]: ...
    @property
    def checked(self) -> AbstractSet[str]: ...
    @property
    def unchecked(self) -> Mapping[str, str]: ...


class OsvRepositories(Protocol):
    """What the detectors use of the class `OsvImport`: a repository address in its one spelling."""

    def repository_key(self, url: str) -> str | None: ...


class AdvisoryFileChecks(Protocol):
    """What the detectors report of the advisory files themselves (`AdvisoryFiles`): those refused
    for a digest mismatch, and synced ones this install did not write."""

    def tampered_files(self) -> tuple[str, ...]: ...
    def refused_synced_files(self) -> tuple[str, ...]: ...


class AdvisoryDatabases(Protocol):
    """What the engine and the detectors use of the class `AdvisoryDatabase`."""

    def bundled(self) -> AdvisoryCatalog: ...


class BundleKeys(Protocol):
    """What the engine uses of the class `AdvisoryBundle`."""

    def pinned_key_hex(self) -> str: ...


class FeedStatus(Protocol):
    """What the engine uses of the class `FeedClient`."""

    def offline_requested(self, environ: Mapping[str, str] | None = ...) -> bool: ...
    def status(self, *, use_feed: bool, max_age: int | None) -> IntelReport: ...


class IntelReport(Protocol):
    """What the engine uses of the `IntelStatus` a feed reports."""

    @property
    def age_seconds(self) -> int | None: ...
    @property
    def error(self) -> str: ...
    @property
    def max_age_seconds(self) -> int | None: ...
    @property
    def stale(self) -> bool: ...
    def to_dict(self) -> dict[str, Any]: ...


class LicenseCategory(enum.StrEnum):
    """What a licence obliges, as `LicenseClassification` grades it: a plain value, so it lives with
    the ports rather than behind one."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    COPYLEFT = "copyleft"
    NETWORK_COPYLEFT = "network_copyleft"
    UNKNOWN = "unknown"


class LicenseClassification(Protocol):
    """What the engine uses of the class `LicenseClassifier`."""

    def classify(self, raw: str | None) -> LicenseCategory: ...


class LicenseExpressions(LicenseClassification, Protocol):
    """What the licence and package-policy detectors use of it, beyond the engine's: an expression's
    canonical form, and its operands at the top level."""

    def normalize(self, raw: str | None) -> str | None: ...
    def split_top_level(self, expression: str, operator: str) -> list[str] | None: ...


class PopularNames(Protocol):
    """The popular package names per ecosystem, their curated neighbours, and whether a name is a
    package known to exist (the three read together, for lookalikes)."""

    def popular(self, ecosystem: str) -> frozenset[str]: ...
    def neighbours(self, ecosystem: str) -> frozenset[str]: ...
    def is_known(self, ecosystem: str, normalized_name: str) -> bool: ...


class EstablishedNames(Protocol):
    """The shipped list of established package names per ecosystem."""

    def established(self, ecosystem: str) -> frozenset[str]: ...


class RemovedNameList(Protocol):
    """The names a registry no longer serves, per ecosystem, and when that list was refreshed."""

    def removed(self, ecosystem: str) -> frozenset[str]: ...
    def checked(self, ecosystem: str) -> str: ...


class RangeMatching(Protocol):
    """What the engine uses of the class `VersionRanges`."""

    def admits(self, ecosystem: str, spec: str, version: str) -> bool: ...


class RegistryRecordFacts(Protocol):
    """What the engine uses of instances of `RegistryRecord`."""

    def facts(self) -> dict[str, float]: ...


class RegistryRecords(Protocol):
    """What the engine uses of the class `RegistryRecord`."""

    def load(
        self, ecosystem: str, name: str, version: str, root: Path | None = ...
    ) -> RegistryRecordFacts | None: ...


class RegistryVersions(Protocol):
    """What the engine uses of the class `MoreRegistries`."""

    def versions(self, ecosystem: str, name: str) -> list[str]: ...


class ReleaseBaseline(Protocol):
    """What the engine uses of instances of `Baseline`."""

    @property
    def baseline_published(self) -> str | None: ...
    @property
    def baseline_version(self) -> str | None: ...
    @property
    def introduced(self) -> dict[str, str]: ...
    @property
    def obfuscated(self) -> tuple[str, ...]: ...
    @property
    def published(self) -> str | None: ...
    def unchanged(self, key: str, digest: str) -> bool: ...


class ReleaseHistories(Protocol):
    """What the engine uses of the class `ReleaseHistory`."""

    def key(self, member_path: str, version: str) -> str: ...
    def load(
        self, ecosystem: str, name: str, version: str, root: Path | None = ...
    ) -> ReleaseBaseline | None: ...


class ReleaseArchiveReader(Protocol):
    """How `ReleaseHistory.acquire` reads an established release's archive, handed in by its caller
    (the archive reader and the packing signatures live above intel): its files, and whether one
    has an obfuscator's output shape."""

    def members(self, data: bytes, filename: str) -> Iterable[tuple[str, bytes]]: ...
    def packed(self, path: str, data: bytes) -> bool: ...


class SignatureCheck(Protocol):
    """What the engine uses of the class `Ed25519`."""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


class VersionOrdering(Protocol):
    """What the engine uses of the class `Versions`."""

    def compare(self, ecosystem: str, a: str, b: str) -> int: ...


# Detector-facing ports (review 27, F2): what a detector asks of registries, provenance checks,
# live MCP servers, the known installers and the data files. `registry` hands each implementation
# typed by one of these, so a detector never imports a concrete intel module.


class InstallerChecks(Protocol):
    """Whether a command or a URL is a project's own published installer."""

    def is_official_installer(self, text: str) -> bool: ...
    def pinned_download(self, url: str) -> bool: ...


class PackageFactsQueries(Protocol):
    """What a public registry says about one package version."""

    def facts(
        self, ecosystem: str, name: str, version: str | None, source: str | None = None
    ) -> PackageFacts: ...


class ArtifactQueries(Protocol):
    """A version's published artefact and its attestation, for provenance checks."""

    def attestation_payload(
        self, ecosystem: str, name: str, version: str | None, digest: str | None = None
    ) -> dict[str, Any] | None: ...
    def package_archive(self, ecosystem: str, name: str, version: str | None) -> PackageArchive: ...


class PublishedManifestQueries(Protocol):
    """A registry's manifest for one published version, to compare with what was packed."""

    def version_manifest(self, name: str, version: str) -> dict[str, Any]: ...


class PrivateRegistryQueries(Protocol):
    """The organisation's own registries: which one serves a package, and what it says."""

    def matching(
        self,
        configured: tuple[PrivateRegistry, ...],
        ecosystem: str,
        name: str,
        resolved_from: str | None,
    ) -> PrivateRegistry | None: ...
    def facts(
        self, registry: PrivateRegistry, ecosystem: str, name: str, version: str | None
    ) -> PackageFacts: ...


class LiveServers(Protocol):
    """A configured MCP server's tools, read from the server itself."""

    def remote_url(self, server: dict[str, Any]) -> str | None: ...
    def tools(self, url: str) -> list[ServedTool]: ...


class ToolApprovals(Protocol):
    """The tools a user approved, and how what a server serves now differs from them."""

    def load(self, root: Path) -> dict[str, Any] | None: ...
    def differences(
        self, approved: dict[str, Any], tools: list[ServedTool]
    ) -> list[tuple[str, str]]: ...


class DataFiles(Protocol):
    """The newest copy of one of the intel data files: shipped, or refreshed since."""

    def newest(self, name: str) -> dict[str, Any]: ...


class ModuleProvenance(Protocol):
    """Whether a Bazel module's published integrity matches its registry's."""

    def check(self, name: str, version: str, integrity: str | None) -> ModuleCheck: ...


class ChartProvenance(Protocol):
    """Whether a Helm chart is signed by a key the user trusts."""

    def check(
        self,
        name: str,
        version: str,
        source: str | None,
        integrity: str | None,
        keyring: Keyring,
    ) -> ChartCheck: ...


class BottleProvenance(Protocol):
    """Whether a Homebrew bottle is attested by the tap that builds it."""

    def check(self, name: str, version: str | None) -> BottleCheck: ...


class RepositoryHeads(Protocol):
    """A GitHub repository's current name and default branch, as GitHub reports them."""

    def current(self, owner: str, name: str) -> tuple[str, str] | None: ...


class Keyrings(Protocol):
    """The OpenPGP keys a user has said to trust."""

    def load(self, paths: tuple[str, ...]) -> Keyring: ...




__all__ = [
    "Advisories",
    "AdvisoryDatabases",
    "AdvisoryRecord",
    "ArtifactQueries",
    "BottleProvenance",
    "BundleKeys",
    "ChartProvenance",
    "DataFiles",
    "FeedStatus",
    "InstallerChecks",
    "IntelReport",
    "Keyrings",
    "LicenseClassification",
    "LiveServers",
    "ModuleProvenance",
    "PackageFactsQueries",
    "PrivateRegistryQueries",
    "PublishedManifestQueries",
    "RangeMatching",
    "RegistryRecordFacts",
    "RegistryRecords",
    "RegistryVersions",
    "ReleaseBaseline",
    "ReleaseHistories",
    "RepositoryHeads",
    "SignatureCheck",
    "ToolApprovals",
    "VersionOrdering",
]
