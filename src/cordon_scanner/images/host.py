"""A developer's or CI runner's machine, read as an image is (advanced gap M7).

What a host has installed is the same question an image answers, asked of a live filesystem: the
distribution's package database (dpkg, apk, rpm -- the legacy Berkeley DB `Packages` included --
pacman or portage) and the language packages installed globally, outside any project: Python's
system, `/usr/local` and per-user site-packages and pipx's environments, npm's global
`node_modules`, RubyGems' specifications, `cargo install`'s record, the Go binaries in `~/go/bin`,
Homebrew's Cellar, and the runtimes themselves. Each is read from the metadata its installer
leaves, with the image readers (`images/oci.py`, `images/langpkgs.py`, `images/binmeta.py`), so a
package is identified the same way on a host as in an image.

Read-only, bounded (files, bytes, depth), and nothing is run: no `dpkg -l`, no `pip list`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Final

from cordon_scanner.images import langpkgs
from cordon_scanner.images.oci import (
    APK_INSTALLED,
    APK_INSTALLED_USR,
    APK_WORLD,
    APT_STATES,
    DPKG_STATUS,
    DPKG_STATUS_D,
    OS_RELEASE,
    PACMAN_LOCAL,
    PORTAGE_DB,
    PORTAGE_FILES,
    RPM_LEGACY,
    RPM_SQLITE,
    ImageInventory,
    ImageLayers,
)

MAX_DATABASE_BYTES: Final = 512 << 20
MAX_METADATA_BYTES: Final = 1 << 20
MAX_BINARY_BYTES: Final = 256 << 20
MAX_FILES: Final = 200_000
"""Metadata files read in one host scan, across every root."""

#: Where Python, npm and RubyGems install outside a project, relative to the root or the home.
SYSTEM_SITE: Final = (
    "usr/lib/python3*/site-packages",
    "usr/lib/python3*/dist-packages",
    "usr/lib/python3/dist-packages",
    "usr/local/lib/python3*/site-packages",
    "usr/local/lib/python3*/dist-packages",
    "opt/homebrew/lib/python3*/site-packages",
)
USER_SITE: Final = (
    ".local/lib/python3*/site-packages",
    ".local/pipx/venvs/*/lib/python3*/site-packages",
    ".local/share/pipx/venvs/*/lib/python3*/site-packages",
)
SYSTEM_NODE: Final = (
    "usr/local/lib/node_modules",
    "usr/lib/node_modules",
    "opt/homebrew/lib/node_modules",
)
USER_NODE: Final = (".npm-global/lib/node_modules",)
SYSTEM_GEMS: Final = (
    "usr/lib/ruby/gems/*/specifications",
    "var/lib/gems/*/specifications",
    "usr/local/lib/ruby/gems/*/specifications",
    "opt/homebrew/lib/ruby/gems/*/specifications",
)
USER_GEMS: Final = (".gem/ruby/*/specifications", ".local/share/gem/ruby/*/specifications")
CELLARS: Final = ("opt/homebrew/Cellar", "usr/local/Cellar", "home/linuxbrew/.linuxbrew/Cellar")
#: The files a runtime installed from its own release records its version in (`langpkgs.RUNTIME_FILES`).
RUNTIME_FILES: Final = (
    "usr/local/include/python3*/patchlevel.h",
    "usr/local/include/node/node_version.h",
    "usr/local/go/VERSION",
    "opt/java/openjdk/release",
    "usr/lib/jvm/*/release",
    "usr/local/openjdk*/release",
    "opt/openjdk*/release",
    "usr/local/lib/ruby/*/*/rbconfig.rb",
)
_CRATE_KEY: Final = re.compile(r"^(?P<name>[A-Za-z0-9_-]{1,64}) (?P<version>\d[\w.+-]{0,60}) \(")


class HostFilesystem:
    """The inventory of a filesystem root: its OS packages and its global language installs."""

    def __init__(self, root: Path, home: Path | None = None) -> None:
        self.root = root
        self.home = home
        self.read = 0

    def _bytes(self, path: Path, limit: int) -> bytes | None:
        if self.read >= MAX_FILES:
            return None
        try:
            if not path.is_file():
                return None
            # A link out of the root reads somebody else's file under this host's name.
            if path.is_symlink() and not path.resolve().is_relative_to(self.root.resolve()):
                return None
            if path.stat().st_size > limit:
                return None
            self.read += 1
            return path.read_bytes()
        except OSError:
            return None

    def _database_files(self) -> dict[str, bytes]:
        """The same files `ImageLayers._wanted` selects from a layer, read from disk."""
        wanted = [
            DPKG_STATUS,
            APK_INSTALLED,
            APK_INSTALLED_USR,
            *RPM_SQLITE,
            *(p + "-wal" for p in RPM_SQLITE),
            *RPM_LEGACY,
            *OS_RELEASE,
            APT_STATES,
            APK_WORLD,
        ]
        files: dict[str, bytes] = {}
        for relative in wanted:
            data = self._bytes(self.root / relative, MAX_DATABASE_BYTES)
            if data is not None:
                files[relative] = data
        for directory, pattern in (
            (DPKG_STATUS_D, "*"),
            (PACMAN_LOCAL, "*/desc"),
            (PACMAN_LOCAL, "*/files"),
            *((PORTAGE_DB, f"*/*/{name}") for name in PORTAGE_FILES),
        ):
            base = self.root / directory
            if not base.is_dir():
                continue
            for path in sorted(base.glob(pattern))[:MAX_FILES]:
                relative = path.relative_to(self.root).as_posix()
                if ImageLayers._wanted(relative):
                    data = self._bytes(path, MAX_METADATA_BYTES)
                    if data is not None:
                        files[relative] = data
        return files

    def _under(self, bases: tuple[Path, ...], patterns: tuple[str, ...]) -> list[Path]:
        found: list[Path] = []
        for base in bases:
            for pattern in patterns:
                found += [p for p in sorted(base.glob(pattern)) if p.is_dir()]
        return found

    def _language_packages(self, inventory: ImageInventory) -> None:
        from cordon_scanner.images.binmeta import BinaryMetadata

        bases = (self.root,)
        homes = (self.home,) if self.home is not None else ()
        seen: set[tuple[str, str, str]] = set()

        def add(package: langpkgs.LanguagePackage | None) -> None:
            if package is None:
                return
            key = (package.ecosystem, package.name, package.version)
            if key not in seen:
                seen.add(key)
                inventory.language_packages.append(package)

        def label(path: Path) -> str:
            for base in (*homes, self.root):
                if path.is_relative_to(base):
                    prefix = "~/" if base in homes and base != self.root else ""
                    return prefix + path.relative_to(base).as_posix()
            return path.as_posix()

        def relabelled(
            package: langpkgs.LanguagePackage | None, path: Path
        ) -> langpkgs.LanguagePackage | None:
            return (
                None
                if package is None
                else langpkgs.LanguagePackage(
                    package.ecosystem, package.name, package.version, label(path)
                )
            )

        for site in self._under(bases, SYSTEM_SITE) + self._under(homes, USER_SITE):
            for metadata in sorted(
                [
                    *site.glob("*.dist-info/METADATA"),
                    *site.glob("*.egg-info/PKG-INFO"),
                    *site.glob("*.egg-info"),
                ]
            )[:MAX_FILES]:
                relative = f"site-packages/{metadata.relative_to(site).as_posix()}"
                if metadata.is_file() and langpkgs.LanguagePackages.is_metadata(relative):
                    data = self._bytes(metadata, MAX_METADATA_BYTES)
                    if data is not None:
                        add(relabelled(langpkgs.LanguagePackages.parse(relative, data), metadata))
        for modules in self._under(bases, SYSTEM_NODE) + self._under(homes, USER_NODE):
            for manifest in sorted(modules.rglob("package.json"))[:MAX_FILES]:
                # Read as an installed tree would name it, so the directory-name check applies.
                relative = "node_modules/" + manifest.relative_to(modules).as_posix()
                if langpkgs.LanguagePackages.is_metadata(relative):
                    data = self._bytes(manifest, MAX_METADATA_BYTES)
                    if data is not None:
                        add(relabelled(langpkgs.LanguagePackages.parse(relative, data), manifest))
        for specifications in self._under(bases, SYSTEM_GEMS) + self._under(homes, USER_GEMS):
            for spec in sorted(
                [*specifications.glob("*.gemspec"), *specifications.glob("default/*.gemspec")]
            )[:MAX_FILES]:
                add(
                    relabelled(
                        langpkgs.LanguagePackages.parse(f"specifications/{spec.name}", b""), spec
                    )
                )
        for home in homes:
            crates = self._bytes(home / ".cargo" / ".crates2.json", MAX_METADATA_BYTES)
            if crates is not None:
                try:
                    installs = json.loads(crates).get("installs") or {}
                except (ValueError, AttributeError):
                    installs = {}
                for key in installs if isinstance(installs, dict) else ():
                    matched = _CRATE_KEY.match(str(key))
                    if matched and "crates.io-index" in str(key):
                        add(
                            langpkgs.LanguagePackage(
                                "cargo",
                                matched.group("name"),
                                matched.group("version"),
                                "~/.cargo/.crates2.json",
                            )
                        )
            go_bin = home / "go" / "bin"
            for binary in sorted(go_bin.glob("*"))[:5000] if go_bin.is_dir() else ():
                data = self._bytes(binary, MAX_BINARY_BYTES)
                if data is not None:
                    for package in BinaryMetadata.go(f"~/go/bin/{binary.name}", data):
                        add(package)
        for cellar in (self.root / c for c in CELLARS):
            if cellar.is_dir():
                for receipt in sorted(cellar.glob("*/*/INSTALL_RECEIPT.json"))[:MAX_FILES]:
                    add(
                        langpkgs.LanguagePackage(
                            "homebrew",
                            receipt.parent.parent.name,
                            receipt.parent.name,
                            label(receipt),
                        )
                    )
        for pattern in RUNTIME_FILES:
            for path in sorted(self.root.glob(pattern))[:100]:
                relative = path.relative_to(self.root).as_posix()
                data = self._bytes(path, MAX_METADATA_BYTES)
                if data is not None:
                    add(langpkgs.LanguagePackages.runtime(relative, data))

    def inventory(self) -> ImageInventory:
        inventory = ImageLayers.databases(self._database_files(), ImageInventory())
        self._language_packages(inventory)
        if self.read >= MAX_FILES:
            inventory.problems.append(
                f"more than {MAX_FILES} metadata files; the rest were not read"
            )
        return inventory


__all__ = ["HostFilesystem"]
