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
from cordon_scanner.intel.registries.archive_sources.native import (
    CargoArchive,
    GomodArchive,
    GradleArchive,
    HackageArchive,
    HexArchive,
    MavenArchive,
    NpmArchive,
    NugetArchive,
    PubArchive,
    PypiArchive,
    RubygemsArchive,
    VscodeArchive,
)
from cordon_scanner.intel.registries.archive_sources.oci import HomebrewArchive, ImageArchive
from cordon_scanner.intel.registries.archive_sources.upstream import (
    BazelArchive,
    ConanArchive,
    CranArchive,
    OpamArchive,
)
from cordon_scanner.intel.registries.archive_sources.vcpkg import VcpkgArchive

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
        NpmArchive(),
        PypiArchive(),
        CargoArchive(),
        RubygemsArchive(),
        NugetArchive(),
        GomodArchive(),
        HexArchive(),
        PubArchive(),
        MavenArchive(),
        GradleArchive(),
        VscodeArchive(),
        HackageArchive(),
        VcpkgArchive(),
    )

    @classmethod
    def of(cls, ecosystem: str) -> ArchiveSource | None:
        return next((s for s in cls.SOURCES if s.ecosystem == ecosystem), None)

    @classmethod
    def package_archive(cls, ecosystem: str, name: str, version: str | None) -> PackageArchive:
        """The verified archive of a release of an ecosystem, from its archive source."""
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch
        from cordon_scanner.intel.registries.registry_request import RegistryError

        source = cls.of(ecosystem)
        if source is None:
            raise RegistryError(f"no verified archive for {ecosystem}")
        return ArchiveFetch.archive(source, name, version or source.current(name))

    @classmethod
    def previous(cls, ecosystem: str, name: str, version: str) -> str | None:
        """The release before `version`, from the release history of the ecosystem's registry record."""
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch

        if cls.of(ecosystem) is None:
            return None
        return ArchiveFetch.previous(ecosystem, name, version)

    @classmethod
    def versions(cls, ecosystem: str, name: str) -> list[str]:
        """Every release of `name` the registry has not withdrawn, unordered."""
        from cordon_scanner.intel.registries.archive_sources.base import ArchiveFetch

        return [r.version for r in ArchiveFetch.releases(ecosystem, name, "") if not r.withdrawn]

    @classmethod
    def fetchable(cls) -> frozenset[str]:
        """Every ecosystem whose release archive is fetched and checked."""
        return cls.ids()

    @classmethod
    def ids(cls) -> frozenset[str]:
        return frozenset(s.ecosystem for s in cls.SOURCES)
