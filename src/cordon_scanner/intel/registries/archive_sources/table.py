"""Every ecosystem's archive source, by id."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.intel.registries.archive_sources.base import ArchiveSource
from cordon_scanner.intel.registries.archive_sources.git_sourced import (
    ActionsArchive,
    CocoapodsArchive,
    ComposerArchive,
    JuliaArchive,
    NixArchive,
    SwiftArchive,
    TerraformArchive,
)
from cordon_scanner.intel.registries.archive_sources.listed import (
    AnsibleArchive,
    CondaArchive,
    HelmArchive,
)
from cordon_scanner.intel.registries.archive_sources.oci import HomebrewArchive, ImageArchive
from cordon_scanner.intel.registries.archive_sources.upstream import (
    BazelArchive,
    ConanArchive,
    CranArchive,
    OpamArchive,
)

if TYPE_CHECKING:
    from cordon_scanner.intel.base import PackageArchive


class ArchiveSources:
    SOURCES: ClassVar[tuple[ArchiveSource, ...]] = (
        CondaArchive(),
        AnsibleArchive(),
        BazelArchive(),
        OpamArchive(),
        ConanArchive(),
        CranArchive(),
        ActionsArchive(),
        SwiftArchive(),
        NixArchive(),
        ComposerArchive(),
        CocoapodsArchive(),
        TerraformArchive(),
        JuliaArchive(),
        HelmArchive(),
        ImageArchive(),
        HomebrewArchive(),
    )

    @classmethod
    def of(cls, ecosystem: str) -> ArchiveSource | None:
        return next((s for s in cls.SOURCES if s.ecosystem == ecosystem), None)

    @classmethod
    def package_archive(cls, ecosystem: str, name: str, version: str | None) -> PackageArchive:
        """The verified archive of a release of any ecosystem: from its archive source, else the registry client's own readers."""
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch
        from cordon_scanner.intel.registries.registry_client import RegistryClient
        from cordon_scanner.intel.registries.registry_request import RegistryError

        source = cls.of(ecosystem)
        if source is None:
            return RegistryClient.package_archive(ecosystem, name, version)
        if not version:
            raise RegistryError(f"name a version of {name}: {ecosystem} has no `latest` to resolve")
        return ArchiveFetch.archive(source, name, version)

    @classmethod
    def previous(cls, ecosystem: str, name: str, version: str) -> str | None:
        """The release before `version`: from the archive source's release history, else the registries' own lists."""
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch
        from cordon_scanner.intel.registries.more_registries import MoreRegistries

        if cls.of(ecosystem) is not None:
            return ArchiveFetch.previous(ecosystem, name, version)
        return MoreRegistries.previous(ecosystem, name, version)

    @classmethod
    def ids(cls) -> frozenset[str]:
        return frozenset(s.ecosystem for s in cls.SOURCES)
