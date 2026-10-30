"""The intel layer's ports: what the engine and the decision layer consult, as protocols."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path
    from typing import Any

    from cordon_scanner.detect.base import FileUnit

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


class LicenseCategory(enum.StrEnum):
    """What a licence obliges, as `LicenseClassification` grades it: a plain value, so it lives with
    the ports rather than behind one."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    COPYLEFT = "copyleft"
    NETWORK_COPYLEFT = "network_copyleft"
    UNKNOWN = "unknown"


class LicenseClassification(Protocol):
    """What the engine and the detectors use of the class `LicenseClassifier`."""

    def classify(self, raw: str | None) -> LicenseCategory: ...
    def normalize(self, raw: str | None) -> str | None: ...
    def split_top_level(self, expression: str, operator: str) -> list[str] | None: ...


class PackageNames(Protocol):
    """What the detectors ask of the package-name lists, per ecosystem: the popular names, their
    curated neighbours, the shipped established names, and the names a registry has removed."""

    def popular(self, ecosystem: str) -> frozenset[str]: ...
    def neighbours(self, ecosystem: str) -> frozenset[str]: ...
    def is_known(self, ecosystem: str, normalized_name: str) -> bool: ...
    def established(self, ecosystem: str) -> frozenset[str]: ...
    def removed(self, ecosystem: str) -> frozenset[str]: ...
    def removed_checked(self, ecosystem: str) -> str: ...


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


__all__ = [
    "Advisories",
    "AdvisoryDatabases",
    "AdvisoryRecord",
    "BundleKeys",
    "FeedStatus",
    "IntelReport",
    "LicenseClassification",
    "RangeMatching",
    "RegistryRecordFacts",
    "RegistryRecords",
    "RegistryVersions",
    "ReleaseBaseline",
    "ReleaseHistories",
    "SignatureCheck",
    "VersionOrdering",
]
