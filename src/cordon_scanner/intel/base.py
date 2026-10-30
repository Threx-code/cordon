"""The intel layer's ports: what the engine and the decision layer consult, as protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import enum
    from collections.abc import Mapping, Sequence
    from pathlib import Path
    from typing import Any

    from cordon_scanner.detect.base import FileUnit
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


class AdvisoryRecord(Protocol):
    """What the engine uses of one `Advisory` the database matched."""

    @property
    def identifier(self) -> str: ...
    @property
    def malicious(self) -> bool: ...
    @property
    def reference(self) -> str: ...
    @property
    def summary(self) -> str: ...


class AdvisoryDatabases(Protocol):
    """What the engine uses of the class `AdvisoryDatabase`."""

    def bundled(self) -> Advisories: ...


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


class LicenseClassification(Protocol):
    """What the engine uses of the class `LicenseClassifier`."""

    def classify(self, raw: str | None) -> enum.Enum: ...


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

    def declared_dependencies(
        self, units: Sequence[FileUnit], distribution: str
    ) -> frozenset[str]: ...
    def key(self, member_path: str, version: str) -> str: ...
    def load(
        self, ecosystem: str, name: str, version: str, root: Path | None = ...
    ) -> ReleaseBaseline | None: ...


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
