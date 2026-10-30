"""The intel layer's ports: what the engine and the decision layer consult, as protocols."""

from __future__ import annotations

import enum
import threading
import urllib.parse
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, NamedTuple, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence
    from collections.abc import Set as AbstractSet
    from datetime import datetime
    from pathlib import Path
    from typing import Any

    from cordon_scanner.foundation.results import Dependency
    from cordon_scanner.intel.advisories.advisories import AdvisoryDatabase
    from cordon_scanner.intel.provenance.bazel_provenance import ModuleCheck
    from cordon_scanner.intel.provenance.helm_provenance import ChartCheck
    from cordon_scanner.intel.provenance.homebrew_provenance import BottleCheck
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
    @property
    def symbols(self) -> tuple[str, ...]: ...
    @property
    def matched_through(self) -> str: ...
    @property
    def is_range(self) -> bool: ...
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


class BundledAdvisoryDatabase(Protocol):
    """What the engine and the detectors use of the class `ShippedAdvisories`: the advisory set
    that ships with this release."""

    def database(self) -> AdvisoryDatabase: ...


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


class AttestationQueries(Protocol):
    """What a detector uses of the class `AttestationDocuments`: the digest a lockfile pinned, and
    the bundles a registry's attestation payload holds."""

    def parse_integrity(self, integrity: str | None) -> tuple[str, str] | None: ...
    def extract_bundles(
        self, ecosystem: str, payload: dict[str, Any] | None
    ) -> tuple[str, ...]: ...


class BundleVerification(Protocol):
    """What a detector uses of the class `SigstoreVerification`."""

    def verify(
        self,
        bundle_json: str | bytes,
        *,
        digest_hex: str,
        algorithm: str,
        source_repo: tuple[str, str, str] | None,
        offline: bool = ...,
    ) -> AttestationResult: ...


class CollectionSignatureQueries(Protocol):
    """What a detector uses of the class `AnsibleSignatures`."""

    def installed(
        self,
        name: str,
        version: str,
        manifest: bytes,
        signatures: tuple[str, ...],
        keyring: Keyring,
    ) -> CollectionCheck: ...
    def remote(
        self, name: str, version: str, sources: tuple[str, ...], keyring: Keyring
    ) -> CollectionCheck: ...


class ReleaseAgeQueries(Protocol):
    """What a detector uses of the class `RegistryClient` to ask how old a release is."""

    def younger_than(self, timestamp: str | None, days: int) -> bool: ...


class IntelUpdates:
    """How many times this process has installed new intelligence. Whatever caches intel data
    compares the generation it read at with `current()` and rereads when they differ, so the
    code that installs an update tells no cache by name (architecture audit F3)."""

    _generation: ClassVar[int] = 0
    _lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def bump(cls) -> None:
        """Record that new intelligence was installed in this process."""
        with cls._lock:
            cls._generation += 1

    @classmethod
    def current(cls) -> int:
        return cls._generation


class AtrRuleFacts(Protocol):
    """What a detector reads of one ATR rule (`intel.malware.atr.AtrRule`)."""

    @property
    def rule_id(self) -> str: ...
    @property
    def title(self) -> str: ...
    @property
    def category(self) -> str: ...
    @property
    def severity(self) -> str: ...
    @property
    def status(self) -> str: ...
    @property
    def grade(self) -> str: ...
    @property
    def instruction_hits(self) -> int | None: ...


class AtrMatchFacts(Protocol):
    """One ATR rule's match in a text, as a detector reads it (`intel.malware.atr.AtrMatch`)."""

    @property
    def rule(self) -> AtrRuleFacts: ...
    @property
    def start(self) -> int: ...
    @property
    def end(self) -> int: ...


class InstructionRules(Protocol):
    """What a detector uses of the class `AtrEngine`."""

    def evaluate(self, text: str, kinds: Iterable[str]) -> Sequence[AtrMatchFacts]: ...


class RuleAddresses(Protocol):
    """What a detector uses of the class `RuleLinks`: where a rule is published."""

    def url(self, rule_id: str) -> str: ...


class HallucinationLookup(Protocol):
    """What a detector uses of the class `HallucinatedPackages`."""

    def lookup(self, ecosystem: str, name: str) -> Hallucination | None: ...


class CampaignFacets(Protocol):
    """What a detector uses of the class `CampaignFingerprint`."""

    def of(self, manifest: Mapping[str, Any], paths: Iterable[str]) -> dict[str, str | None]: ...


class CampaignSiblings(Protocol):
    """What a detector uses of a `CampaignIndex`: the condemned releases a package is one
    campaign with."""

    def siblings(self, facets: Mapping[str, str | None]) -> list[dict[str, Any]]: ...


class CampaignIndexes(Protocol):
    """What a detector uses of the class `CampaignIndex`."""

    def shipped(self) -> CampaignSiblings: ...


class FeedOverlays(Protocol):
    """What a detector reads of the feed's installed overlays (`intel.malware.feed.FeedStore`)."""

    def read_provisional(self, ecosystem: str) -> list[dict[str, Any]]: ...
    def read_overlay(self, ecosystem: str) -> tuple[list[dict[str, Any]], frozenset[str]]: ...


class AdvisoryTextReading(Protocol):
    """What a detector uses of the class `AdvisoryTextSymbols`."""

    def is_text(self, symbols: tuple[str, ...] | list[str]) -> bool: ...
    def matches(self, used: str, named: str) -> bool: ...


# Values the ports carry: plain data, defined here so a detector holds them without reaching a
# concrete intel module.


class AttestationOutcome(enum.StrEnum):
    """The result of asking whether a bundle verifies."""

    VERIFIED = "verified"
    """The signature, the transparency-log entry, the artefact digest and the
    signing identity all checked out."""

    INVALID = "invalid"
    """The bundle was cryptographically rejected, or it was signed by an
    identity other than the declared repository. This is the actionable one."""

    UNVERIFIABLE = "unverifiable"
    """Verification could not be attempted: the declared repository is missing or
    on an unsupported forge, the bundle did not parse, or it uses evidence this
    verifier does not read. Distinct from
    `INVALID`, because "not checked" and "checked and failed" are opposite
    facts -- the same distinction the registry client draws for reachability."""


@dataclass(frozen=True, slots=True)
class AttestationResult:
    outcome: AttestationOutcome
    detail: str


@dataclass(frozen=True, slots=True)
class PackageFacts:
    """What a registry says about one package version."""

    name: str
    version: str | None
    yanked: bool = False
    yanked_reason: str | None = None
    latest: str | None = None
    repository: str | None = None
    """The source repository the registry records, for comparison with what the
    package claims locally."""

    digests: tuple[str, ...] = ()
    """Hashes the registry publishes for this version's artefacts."""

    attested: bool = False
    """Whether the registry holds build provenance for *this* version."""

    first_published: str | None = None
    """ISO-8601 time of the package's first release: how long the name has existed."""

    last_published: str | None = None
    """ISO-8601 time of the package's most recent release: whether anyone still maintains it."""

    deprecated: str | None = None
    """The publisher's deprecation notice for this version (npm), or the project's own statement
    that it is inactive (PyPI's `Development Status :: 7 - Inactive`). Publisher-written text."""

    releases: int = 0

    weekly_downloads: int | None = None
    """npm's last-week download count, asked only for a package under a quarter old. None when not
    asked, or for a registry with no first-party download figures (PyPI)."""

    attested_versions: int = 0
    """Attested releases published *before* the one pinned here.

    Not a total, and the distinction is the rule. A package that has never
    published provenance says nothing by not publishing it, and so does one
    that started attesting last month -- every older pin predates the practice,
    and counting totals made `requests==2.31.0` look like a gap because
    `requests` attests now.

    What is worth reporting is a release that shipped while the package was
    already attesting and skipped it. That needs the ordering, so this counts
    only the siblings that came first."""


class PrivateRegistry(NamedTuple):
    base: str
    """`https://host[:port]/path`, without a trailing slash."""
    variable: str
    """The environment variable holding the token: `token` (bearer) or `user:token` (basic)."""

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.base).netloc.lower()


@dataclass(frozen=True)
class KeyInfo:
    """One certificate of the keyring, as its own packets describe it."""

    cert: Any
    fingerprint: str
    key_ids: frozenset[str]
    """The primary key's and every subkey's fingerprint and key ID, upper case."""
    certified: tuple[datetime, ...]
    """When each self-signature over the primary key (a user ID certification, or a direct-key
    signature) was made."""
    bound: dict[str, tuple[datetime, ...]]
    """For each subkey ID (and fingerprint), when each binding signature over it was made."""


@dataclass(frozen=True)
class Keyring:
    """The certificates in the operator's keyring files, and every key and subkey ID they hold."""

    keys: tuple[KeyInfo, ...] = ()
    paths: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()

    @property
    def certs(self) -> tuple[Any, ...]:
        return tuple(k.cert for k in self.keys)

    @property
    def key_ids(self) -> frozenset[str]:
        return frozenset(i for k in self.keys for i in k.key_ids)

    def holding(self, key_id: str) -> KeyInfo | None:
        return next((k for k in self.keys if key_id.upper() in k.key_ids), None)

    def __bool__(self) -> bool:
        return bool(self.keys)


@dataclass(frozen=True)
class CollectionCheck:
    outcome: str
    """`verified`, `invalid`, `unverifiable`, `unconfigured` (signed; no keyring) or `absent`."""
    detail: str


@dataclass(frozen=True, slots=True)
class PackageArchive:
    """One published package archive, downloaded and checked against the registry's digest."""

    ecosystem: str
    name: str
    version: str
    filename: str
    data: bytes


# A value both the feed and the rule packs it delivers raise, so neither imports the other for it.


class FeedError(Exception):
    """The feed could not be used. Carries a message that is safe to show."""


@dataclass(frozen=True)
class Hallucination:
    ecosystem: str
    name: str
    intended: str
    note: str


__all__ = [
    "Advisories",
    "AdvisoryRecord",
    "ArtifactQueries",
    "BottleProvenance",
    "BundleKeys",
    "BundledAdvisoryDatabase",
    "ChartProvenance",
    "DataFiles",
    "FeedError",
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
