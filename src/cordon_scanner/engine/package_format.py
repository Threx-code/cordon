"""Which published-package format an archive is, from the metadata its packaging tool writes.

Moved out of engine/engine.py (review 98 #18), where it was `Engine._distribution_format`, which
now delegates here.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from cordon_scanner.detect.base import FileUnit

GO_MODULE_ROOT: Final = re.compile(r"[^@!]{1,1024}@v\d[^/@!]{0,128}/")
"""A module proxy zip's first level: every file sits under `<module path>@<version>/`."""


class PackageFormat:
    @staticmethod
    def of(units: list[FileUnit]) -> str:
        """Which published-package format the archive is, or "" when it is not one.

        Recognised by the metadata file each format's own packaging tool writes, at the
        archive's first level only. That level matters: a repository snapshot that vendors a
        package tarball is still a repository, and its own lockfiles are still the project's.
        Formats whose archives have the same shape as a repository snapshot (pub, Packagist,
        Helm, Terraform modules) are not recognised, because nothing tells them apart.
        """

        top: set[str] = set()
        for unit in units:
            _, sep, member = unit.path.partition("!")
            if sep and "!" not in member:
                top.add(member)
        roots: dict[str, set[str]] = {}
        for member in top:
            directory, sep, leaf = member.partition("/")
            if sep and "/" not in leaf:
                roots.setdefault(directory, set()).add(leaf)
        for directory, leaves in roots.items():
            if "PKG-INFO" in leaves or (directory.endswith(".dist-info") and "METADATA" in leaves):
                return "pypi"
            if directory == "package" and "package.json" in leaves:
                return "npm"
            if "Cargo.toml.orig" in leaves:
                return "cargo"
            if "DESCRIPTION" in leaves and "MD5" in leaves:
                return "cran"
            if any(
                leaf.endswith(".cabal")
                and re.fullmatch(rf"{re.escape(leaf[:-6])}-\d[\d.]*", directory)
                for leaf in leaves
            ):
                return "hackage"
        if "metadata.gz" in top:
            return "rubygems"
        if "[Content_Types].xml" in top and any(
            m.endswith(".nuspec") and "/" not in m for m in top
        ):
            return "nuget"
        if "metadata.config" in top and "CHECKSUM" in top:
            return "hex"
        if "META-INF/MANIFEST.MF" in top:
            return "maven"
        if "info/index.json" in top:
            return "conda"
        # A `.conda` package: a zip of `metadata.json` and two zstd tarballs, its `info/` inside
        # `info-*.tar.zst` -- the same package as the `.tar.bz2`, one level further down.
        if "metadata.json" in top and any(
            re.search(r"![^!/]*info-[^!/]*\.tar\.zst!info/index\.json$", unit.path)
            for unit in units
        ):
            return "conda"
        if "MANIFEST.json" in top and "FILES.json" in top:
            return "galaxy"
        if any(GO_MODULE_ROOT.match(m) for m in top):
            return "gomod"
        return "npm" if PackageFormat.npm_under_another_root(units, top, roots) else ""

    @staticmethod
    def npm_under_another_root(
        units: list[FileUnit], top: set[str], roots: dict[str, set[str]]
    ) -> bool:
        """An npm tarball packed under a directory other than `package/` (`pkg/`, the package's own
        name): npm installs one by stripping the first path component, whatever it is, so renaming
        it must not switch npm's install-time reading off (review 98 #18). Only a gzipped tar whose
        every member sits under that one directory, beside a package.json with a name and a
        version: a snapshot with files next to its directory is not one."""
        if len(roots) != 1 or any("/" not in m for m in top):
            return False
        (directory,) = roots
        if "package.json" not in roots[directory]:
            return False
        for unit in units:
            archive, sep, member = unit.path.partition("!")
            if sep and member == f"{directory}/package.json":
                if not archive.endswith((".tgz", ".tar.gz")):
                    return False
                try:
                    manifest = json.loads(unit.content.text)
                except ValueError:
                    return False
                return (
                    isinstance(manifest, dict)
                    and isinstance(manifest.get("name"), str)
                    and isinstance(manifest.get("version"), str)
                )
        return False


__all__ = ["GO_MODULE_ROOT", "PackageFormat"]
