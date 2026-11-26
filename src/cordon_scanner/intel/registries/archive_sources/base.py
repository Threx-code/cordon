"""The shared interface of the verified archive: what an ecosystem supplies, and the one fetch that checks it."""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.base import PackageArchive
from cordon_scanner.intel.registries.record_sources.base import (
    Document,
    RecordBuilder,
    RecordFetch,
    Release,
)
from cordon_scanner.intel.registries.record_sources.table import RecordSources
from cordon_scanner.intel.registries.registry_request import RegistryError, RegistryRequest

if TYPE_CHECKING:
    from collections.abc import Mapping

#: The algorithms an archive may be checked with, strongest first; anything else a registry states is not a check.
STRENGTH = ("sha512", "sha384", "sha256", "sha1", "md5")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+@~-]{0,200}")


@dataclass(frozen=True)
class Located:
    """Where one release's archive is and what the registry says it hashes to."""

    url: str
    filename: str
    digests: tuple[tuple[str, str], ...]
    """`(algorithm, lower-case hex)` for each digest the registry states; the archive must match every one."""

    @property
    def strength(self) -> str:
        """The strongest algorithm among the digests: what a comparison's report says it was checked with."""
        stated = {algorithm for algorithm, _ in self.digests}
        return next((a for a in STRENGTH if a in stated), "")


class ArchiveSource(ABC):
    """What an ecosystem supplies to fetch the archive of a release."""

    ecosystem: ClassVar[str]
    #: The hosts the archive may be downloaded from: the registry names the URL, so it is confined to these.
    HOSTS: ClassVar[frozenset[str]]
    #: Follow a redirect, each to a host `allows` (a registry that signs a storage URL); none otherwise.
    REDIRECTS: ClassVar[int] = 0

    def allows(self, host: str) -> bool:
        """Whether the archive may be downloaded from `host`: the registry's own file hosts, by default."""
        return host in self.HOSTS

    @abstractmethod
    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        """The documents the archive is located from."""

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        return ()

    @abstractmethod
    def locate(self, name: str, version: str, documents: Mapping[str, Any]) -> Located | None:
        """Where the archive of `version` is, or None when the registry has none for it. Pure: the same documents, the same answer."""


class ArchiveFetch:
    """Downloading a located archive and checking it."""

    @staticmethod
    def digest_ok(data: bytes, digests: tuple[tuple[str, str], ...]) -> bool:
        """Every stated digest matches, and at least one was stated."""
        if not digests:
            return False
        return all(
            hashlib.new(algorithm, data, usedforsecurity=False).hexdigest() == expected.lower()
            for algorithm, expected in digests
        )

    @classmethod
    def located(cls, source: ArchiveSource, name: str, version: str) -> Located:
        documents = RecordFetch.documents(source, name, version)
        if documents is None:
            raise RegistryError(f"{source.ecosystem} has no {name}")
        found = source.locate(name, version, documents)
        if found is None:
            raise RegistryError(f"{source.ecosystem} publishes no archive for {name}@{version}")
        if not found.digests:
            raise RegistryError(
                f"{source.ecosystem} publishes no digest for {name}@{version}; nothing to verify against"
            )
        if any(a not in STRENGTH for a, _ in found.digests):
            raise RegistryError(f"{source.ecosystem} names a digest algorithm that is no check")
        return found

    @classmethod
    def archive(cls, source: ArchiveSource, name: str, version: str) -> PackageArchive:
        found = cls.located(source, name, version)
        data = RegistryRequest.fetch_bytes(
            found.url, source.ecosystem, redirects=source.REDIRECTS, allow=source.allows
        )
        if not cls.digest_ok(data, found.digests):
            raise RegistryError(
                f"{name}@{version} does not match the {found.strength} {source.ecosystem} publishes"
            )
        filename = (
            found.filename if FILENAME.fullmatch(found.filename) else f"{source.ecosystem}-archive"
        )
        return PackageArchive(source.ecosystem, name, version, filename, data)

    @staticmethod
    def before(ecosystem: str, version: str, published: Mapping[str, Any]) -> str | None:
        """The release before `version` on its own line: of the versions published before it, the highest below it in the
        ecosystem's version order. Not the latest published before it: maintained lines interleave in time, and `express`
        4.21.2 was compared with 5.0.1, out a month before it on the next major line."""
        from cordon_scanner.intel.advisories.versions import Versions

        current = published.get(version)
        if current is None:
            return None
        best: str | None = None
        for candidate, when in published.items():
            if when >= current or Versions.compare(ecosystem, candidate, version) >= 0:
                continue
            if best is None or Versions.compare(ecosystem, candidate, best) > 0:
                best = candidate
        return best

    @classmethod
    def previous(cls, ecosystem: str, name: str, version: str) -> str | None:
        """The release before `version` among the ones the registry has not withdrawn (`version` itself is kept whatever its state)."""
        published = {
            r.version: r.published
            for r in cls.releases(ecosystem, name, version)
            if not r.withdrawn or r.version == version
        }
        return cls.before(ecosystem, version, published)

    @staticmethod
    def releases(ecosystem: str, name: str, version: str) -> list[Release]:
        """Every release of `name` the registry states, from the same documents the registry record reads."""
        source = RecordSources.of(ecosystem)
        if source is None:
            raise RegistryError(f"no release history for {ecosystem}")
        documents = RecordFetch.documents(source, name, version)
        if documents is None:
            raise RegistryError(f"{ecosystem} has no {name}")
        return RecordBuilder.releases_of(source, name, version, documents)


__all__ = ["ArchiveFetch", "ArchiveSource", "Located"]
