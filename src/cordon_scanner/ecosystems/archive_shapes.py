"""What a published package of each ecosystem looks like as an archive.

Each ecosystem adapter declares one `published_archive`: the shape(s) its registry's packages have, or, where
the thing itself does not exist, the reason (`NoArchive`), or the ecosystem whose archives it shares
(`SameArchiveAs`). `PackageFormat.of` asks each adapter's shapes in `precedence` order. A shape reads the
archive's first level only: a repository snapshot that vendors a package tarball is still a repository.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.foundation.formats.served_json import ServedJson

if TYPE_CHECKING:
    from cordon_scanner.detect.base import FileUnit

GO_MODULE_ROOT: Final = re.compile(r"[^@!]{1,1024}@v\d[^/@!]{0,128}/")
"""A module proxy zip's first level: every file sits under `<module path>@<version>/`."""


@dataclass(frozen=True, slots=True)
class ArchiveLevels:
    """An archive as its shapes read it: the first-level members, the files directly inside each first-level
    directory, every member, and the units themselves (for a shape that reads a file)."""

    units: Sequence[FileUnit]
    top: frozenset[str]
    roots: dict[str, frozenset[str]]
    members: frozenset[str]

    @classmethod
    def of(cls, units: Sequence[FileUnit]) -> ArchiveLevels:
        top: set[str] = set()
        members: set[str] = set()
        for unit in units:
            _, sep, member = unit.path.partition("!")
            if sep:
                members.add(member)
                if "!" not in member:
                    top.add(member)
        roots: dict[str, set[str]] = {}
        for member in top:
            directory, sep, leaf = member.partition("/")
            if sep and "/" not in leaf:
                roots.setdefault(directory, set()).add(leaf)
        return cls(
            units=units,
            top=frozenset(top),
            roots={directory: frozenset(leaves) for directory, leaves in roots.items()},
            members=frozenset(members),
        )

    def text(self, member: str) -> str:
        """The text of a first-level member, or "" where there is none or it cannot be read."""
        for unit in self.units:
            if unit.path.partition("!")[2] == member:
                try:
                    return str(unit.content.text)
                except (AttributeError, ValueError):
                    return ""
        return ""


class ArchiveShape:
    """One way a package archive is recognised: by the metadata file its packaging tool writes."""

    #: What `PackageFormat.of` answers; the adapter's id where this is empty.
    format: ClassVar[str] = ""
    #: The order shapes are asked in: lower first. The order the formats have always been read in.
    precedence: ClassVar[int] = 1000

    def matches(self, levels: ArchiveLevels) -> bool:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class NoArchive:
    """An ecosystem that has no package archive of its own to recognise, and why."""

    reason: str


@dataclass(frozen=True, slots=True)
class SameArchiveAs:
    """An ecosystem that publishes the archives of another one, recognised as that one."""

    ecosystem: str


class PypiArchive(ArchiveShape):
    precedence = 10

    def matches(self, levels: ArchiveLevels) -> bool:
        return any(
            "PKG-INFO" in leaves or (directory.endswith(".dist-info") and "METADATA" in leaves)
            for directory, leaves in levels.roots.items()
        )


class NpmPackageArchive(ArchiveShape):
    precedence = 20

    def matches(self, levels: ArchiveLevels) -> bool:
        return "package.json" in levels.roots.get("package", frozenset())


class CargoArchive(ArchiveShape):
    precedence = 30

    def matches(self, levels: ArchiveLevels) -> bool:
        return any("Cargo.toml.orig" in leaves for leaves in levels.roots.values())


class CranArchive(ArchiveShape):
    precedence = 40

    def matches(self, levels: ArchiveLevels) -> bool:
        return any("DESCRIPTION" in leaves and "MD5" in leaves for leaves in levels.roots.values())


class HackageArchive(ArchiveShape):
    precedence = 50

    def matches(self, levels: ArchiveLevels) -> bool:
        return any(
            leaf.endswith(".cabal") and re.fullmatch(rf"{re.escape(leaf[:-6])}-\d[\d.]*", directory)
            for directory, leaves in levels.roots.items()
            for leaf in leaves
        )


class GemArchive(ArchiveShape):
    precedence = 60

    def matches(self, levels: ArchiveLevels) -> bool:
        return "metadata.gz" in levels.top


class NuGetArchive(ArchiveShape):
    precedence = 70

    def matches(self, levels: ArchiveLevels) -> bool:
        return "[Content_Types].xml" in levels.top and any(
            m.endswith(".nuspec") and "/" not in m for m in levels.top
        )


class HexArchive(ArchiveShape):
    precedence = 80

    def matches(self, levels: ArchiveLevels) -> bool:
        return "metadata.config" in levels.top and "CHECKSUM" in levels.top


class MavenArchive(ArchiveShape):
    precedence = 90

    def matches(self, levels: ArchiveLevels) -> bool:
        return "META-INF/MANIFEST.MF" in levels.top


class CondaArchive(ArchiveShape):
    precedence = 100

    def matches(self, levels: ArchiveLevels) -> bool:
        if "info/index.json" in levels.top:
            return True
        # A `.conda` package: a zip of `metadata.json` and two zstd tarballs, its `info/` inside
        # `info-*.tar.zst` -- the same package as the `.tar.bz2`, one level further down.
        return "metadata.json" in levels.top and any(
            re.search(r"![^!/]*info-[^!/]*\.tar\.zst!info/index\.json$", unit.path)
            for unit in levels.units
        )


class GalaxyArchive(ArchiveShape):
    format = "galaxy"
    precedence = 110

    def matches(self, levels: ArchiveLevels) -> bool:
        return "MANIFEST.json" in levels.top and "FILES.json" in levels.top


class GoModuleArchive(ArchiveShape):
    precedence = 120

    def matches(self, levels: ArchiveLevels) -> bool:
        return any(GO_MODULE_ROOT.match(m) for m in levels.top)


class HelmArchive(ArchiveShape):
    """`helm package`: one directory named for the chart, holding its `Chart.yaml`, whose `name` is that same name.
    A repository snapshot is named for the repository and the commit, not for the chart inside it."""

    precedence = 130

    def matches(self, levels: ArchiveLevels) -> bool:
        for directory, leaves in levels.roots.items():
            if "Chart.yaml" in leaves and re.search(
                rf"^name:\s*[\"']?{re.escape(directory)}[\"']?\s*$",
                levels.text(f"{directory}/Chart.yaml"),
                re.MULTILINE,
            ):
                return True
        return False


class VsixArchive(ArchiveShape):
    """A `.vsix`: an OPC zip with the editor's own `extension.vsixmanifest` beside `[Content_Types].xml`."""

    precedence = 140

    def matches(self, levels: ArchiveLevels) -> bool:
        return "extension.vsixmanifest" in levels.top and "[Content_Types].xml" in levels.top


class ProviderArchive(ArchiveShape):
    """A Terraform provider zip: the provider's own binary, `terraform-provider-<name>_v<version>...`."""

    precedence = 150
    BINARY: ClassVar[re.Pattern[str]] = re.compile(r"terraform-provider-[^/_]+_v\d[^/]*")

    def matches(self, levels: ArchiveLevels) -> bool:
        return any(self.BINARY.fullmatch(member) for member in levels.top)


class PubArchive(ArchiveShape):
    """A pub.dev archive: the package's files at the archive's first level (no folder around them), `pubspec.yaml`
    among them."""

    precedence = 160

    def matches(self, levels: ArchiveLevels) -> bool:
        return "pubspec.yaml" in levels.top


class BottleArchive(ArchiveShape):
    """A Homebrew bottle: `<formula>/<version>/`, holding the formula it was built from (`.brew/<formula>.rb`) or
    its `INSTALL_RECEIPT.json`."""

    precedence = 170
    MEMBER: ClassVar[re.Pattern[str]] = re.compile(
        r"(?P<formula>[^/]+)/[^/]+/(?:\.brew/(?P=formula)\.rb|INSTALL_RECEIPT\.json)"
    )

    def matches(self, levels: ArchiveLevels) -> bool:
        return any(self.MEMBER.fullmatch(member) for member in levels.members)


class OciLayoutArchive(ArchiveShape):
    """A saved image in the OCI image layout: `oci-layout` and `index.json` at the first level, the blobs under
    `blobs/sha256/`."""

    format = "image"
    precedence = 180

    def matches(self, levels: ArchiveLevels) -> bool:
        return "oci-layout" in levels.top and "index.json" in levels.top


class DockerSaveArchive(ArchiveShape):
    """A `docker save` tar: `manifest.json` and `repositories` at the first level, a folder of layers per image."""

    format = "image"
    precedence = 190

    def matches(self, levels: ArchiveLevels) -> bool:
        return "manifest.json" in levels.top and "repositories" in levels.top


class SingleFolderArchive(ArchiveShape):
    """A snapshot of one repository, read as a package by the file that names the project in its one folder.
    Weaker than a marker file a packaging tool writes (a repository with the same file looks the same), so it is
    asked after every marker shape."""

    precedence = 800
    NAMES: ClassVar[tuple[str, ...]] = ()

    def matches(self, levels: ArchiveLevels) -> bool:
        folders = {member.partition("/")[0] for member in levels.top}
        if len(folders) != 1 or any("/" not in member for member in levels.top):
            return False
        (folder,) = folders
        return any(name in levels.roots.get(folder, frozenset()) for name in self.NAMES)


class ComposerArchive(SingleFolderArchive):
    """A Packagist dist zip: the git host's snapshot of the tag, with `composer.json` in its one folder."""

    NAMES = ("composer.json",)


class ActionArchive(SingleFolderArchive):
    """What the runner downloads for `uses: owner/repo@ref`: the host's tarball of the repository, with
    `action.yml` or `action.yaml` in its one folder."""

    precedence = 810
    NAMES = ("action.yml", "action.yaml")


class JuliaArchive(ArchiveShape):
    """A Pkg server tarball of a package's tree: `Project.toml` and `src/` at the first level, no folder around them."""

    precedence = 200

    def matches(self, levels: ArchiveLevels) -> bool:
        return "Project.toml" in levels.top and any(m.startswith("src/") for m in levels.top)


class ConanArchive(ArchiveShape):
    """A Conan revision as the server holds it: `conanmanifest.txt` with the recipe (`conanfile.py`) or, for a
    binary package, its `conaninfo.txt`."""

    precedence = 210

    def matches(self, levels: ArchiveLevels) -> bool:
        return "conanmanifest.txt" in levels.top and (
            "conanfile.py" in levels.top or "conaninfo.txt" in levels.top
        )


class NarArchive(ArchiveShape):
    """A Nix archive (NAR): a serialisation that begins with the length-prefixed string `nix-archive-1`, the
    format a binary cache serves a store path in."""

    precedence = 220
    MAGIC: ClassVar[bytes] = b"\x0d\x00\x00\x00\x00\x00\x00\x00nix-archive-1\x00\x00\x00"

    def matches(self, levels: ArchiveLevels) -> bool:
        return any(
            getattr(getattr(unit, "content", None), "raw", b"").startswith(self.MAGIC)
            for unit in levels.units
        )


class NpmRenamedArchive(ArchiveShape):
    """An npm tarball packed under a directory other than `package/` (`pkg/`, the package's own name): npm installs
    one by stripping the first path component, whatever it is, so renaming it must not switch npm's install-time
    reading off (review 98 #18). Only a gzipped tar whose every member sits under that one directory, beside a
    package.json with a name and a version: a snapshot with files next to its directory is not one."""

    format = "npm"
    precedence = 900

    def matches(self, levels: ArchiveLevels) -> bool:
        if len(levels.roots) != 1 or any("/" not in m for m in levels.top):
            return False
        (directory,) = levels.roots
        if "package.json" not in levels.roots[directory]:
            return False
        for unit in levels.units:
            archive, sep, member = unit.path.partition("!")
            if sep and member == f"{directory}/package.json":
                if not archive.endswith((".tgz", ".tar.gz")):
                    return False
                return self._named_and_versioned(unit)
        return False

    @staticmethod
    def _named_and_versioned(unit: Any) -> bool:
        try:
            manifest = ServedJson.loads(unit.content.text, unit.path)
        except (ValueError, RecursionError):
            return False
        return (
            isinstance(manifest, dict)
            and isinstance(manifest.get("name"), str)
            and isinstance(manifest.get("version"), str)
        )


__all__ = [
    "GO_MODULE_ROOT",
    "ArchiveLevels",
    "ArchiveShape",
    "NoArchive",
    "SameArchiveAs",
]
