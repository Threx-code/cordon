"""npm manifest confusion: the registry describes one package and the tarball is another.

npm stores the manifest a publisher submits beside the tarball and never checks that the two agree.
The registry's copy is what `npm view`, the website and most scanners read; the tarball's own
`package.json` is what `npm install` runs. A publisher who submits a clean manifest and ships a
tarball whose `package.json` adds a `postinstall`, or a dependency, gets an install hook nobody who
read the registry saw.

So, when a published npm tarball is scanned with `--online`, the tarball's `package.json` is read
from the archive and compared with the manifest the registry serves for the same version. A
difference in what runs at install, what is installed with it, or which commands it puts on the
path is reported. Fields npm adds at publish (`_id`, `dist`, `gitHead` and the rest) are not
compared, and what npm's own normalisation rewrites is normalised on both sides first: a `bin`
string becomes an object and loses its `./`, optional dependencies are merged into
`dependencies`, `bundleDependencies: true` names every dependency, a leading `v` leaves the
version, git shorthands are expanded, and `install: node-gyp rebuild` is added for a package that
ships `binding.gyp`. Without that every native addon would be reported.
"""

from __future__ import annotations

import json
import tarfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.core.models import Finding, Severity

RULE_ID = "SUSPECT.PACKAGE.MANIFEST_CONFUSION.001"
MAX_MANIFEST_BYTES = 1 << 20


@dataclass(frozen=True, slots=True)
class Disagreement:
    field: str
    registry: str
    packaged: str


class ManifestConfusion:
    """Compares a tarball's own `package.json` with the manifest npm serves for it."""

    #: What runs at install from the registry. `prepare` runs only for git and local installs.
    HOOKS: ClassVar[tuple[str, ...]] = ("preinstall", "install", "postinstall")

    @staticmethod
    def packaged(target: Path) -> dict[str, Any] | None:
        """The tarball's top-level `package.json`, or None when the archive has none to read."""
        if not target.name.lower().endswith((".tgz", ".tar.gz")):
            return None
        try:
            with tarfile.open(target) as archive:
                for entry in archive:
                    parts = entry.name.split("/")
                    if len(parts) != 2 or parts[-1] != "package.json" or not entry.isfile():
                        continue
                    if entry.size > MAX_MANIFEST_BYTES:
                        return None
                    handle = archive.extractfile(entry)
                    document = json.loads(handle.read()) if handle else None
                    return document if isinstance(document, dict) else None
        except (tarfile.TarError, OSError, ValueError):
            return None
        return None

    @classmethod
    def differences(cls, registry: dict[str, Any], packaged: dict[str, Any]) -> list[Disagreement]:
        """Every install-relevant field on which the two manifests disagree."""
        out: list[Disagreement] = []
        if cls._text(registry.get("name")) != cls._text(packaged.get("name")):
            out.append(
                Disagreement(
                    "name", cls._text(registry.get("name")), cls._text(packaged.get("name"))
                )
            )
        if cls._version(registry.get("version")) != cls._version(packaged.get("version")):
            out.append(
                Disagreement(
                    "version",
                    cls._text(registry.get("version")),
                    cls._text(packaged.get("version")),
                )
            )
        registry_scripts = cls._mapping(registry.get("scripts"))
        packaged_scripts = cls._mapping(packaged.get("scripts"))
        for hook in cls.HOOKS:
            before, after = (
                cls._text(registry_scripts.get(hook)),
                cls._text(packaged_scripts.get(hook)),
            )
            if hook == "install" and before == cls.GYP_INSTALL and not after:
                continue  # npm adds it at publish for a package that ships binding.gyp
            if before != after:
                out.append(Disagreement(f"scripts.{hook}", before, after))
        for field, wanted, shipped in cls._dependency_views(registry, packaged):
            if wanted != shipped:
                out.append(Disagreement(field, cls._render(wanted), cls._render(shipped)))
        if cls._bins(registry) != cls._bins(packaged):
            out.append(
                Disagreement(
                    "bin", cls._render(cls._bins(registry)), cls._render(cls._bins(packaged))
                )
            )
        return out

    @classmethod
    def check(cls, target: Path) -> list[Finding]:
        """Findings for a published npm tarball whose registry manifest is not its own.

        Online only: the caller decides that. Unreadable archives and unanswered questions produce
        nothing here, because the release comparison beside it already states what it could not ask.
        """
        from cordon_scanner.intel.registry_client import (
            REGISTRY_HOSTS,
            RegistryClient,
            RegistryError,
        )

        packaged = cls.packaged(target)
        if (
            not packaged
            or not cls._text(packaged.get("name"))
            or not cls._text(packaged.get("version"))
        ):
            return []
        name, version = cls._text(packaged["name"]), cls._text(packaged["version"])
        quoted = urllib.parse.quote(name, safe="@/")
        try:
            registry = RegistryClient._fetch(
                f"{REGISTRY_HOSTS['npm']}/{quoted}/{urllib.parse.quote(version, safe='')}"
            )
        except RegistryError:
            return []
        disagreements = cls.differences(registry, packaged)
        if not disagreements:
            return []
        return [cls._finding(target, name, version, disagreements)]

    @classmethod
    def _finding(cls, target: Path, name: str, version: str, found: list[Disagreement]) -> Finding:
        from cordon_scanner.core.engine import Engine

        runs = any(d.field.startswith("scripts.") for d in found)
        detail = "; ".join(
            f"{d.field}: registry says {d.registry or 'nothing'}, the tarball says {d.packaged or 'nothing'}"
            for d in found[:6]
        )
        return Engine.package_check(
            path=f"{target.name}!package/package.json",
            rule_id=RULE_ID,
            severity=Severity.CRITICAL if runs else Severity.HIGH,
            message=(
                f"The manifest npm serves for {name}@{version} is not the package.json in its tarball "
                f"({detail}). npm installs from the tarball, so what the registry shows is not what runs."
            )[:2000],
            remediation=(
                "Do not install this version. Read the tarball's own package.json, report the "
                "package to npm, and pin a version whose two manifests agree."
            ),
        )

    GYP_INSTALL: ClassVar[str] = "node-gyp rebuild"

    @classmethod
    def _dependency_views(
        cls, registry: dict[str, Any], packaged: dict[str, Any]
    ) -> list[tuple[str, dict[str, str], dict[str, str]]]:
        """Each dependency field as npm's publish normalises it, for both manifests."""
        views = []
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            before = cls._dependencies(registry.get(field))
            after = cls._dependencies(packaged.get(field))
            if field == "dependencies":
                # normalize-package-data merges optional dependencies into `dependencies`.
                before = {**cls._dependencies(registry.get("optionalDependencies")), **before}
                after = {**cls._dependencies(packaged.get("optionalDependencies")), **after}
            views.append((field, before, after))
        views.append(("bundleDependencies", cls._bundled(registry), cls._bundled(packaged)))
        return views

    @classmethod
    def _bundled(cls, manifest: dict[str, Any]) -> dict[str, str]:
        value = manifest.get("bundleDependencies", manifest.get("bundledDependencies"))
        if value is True:
            value = list(cls._dependencies(manifest.get("dependencies")))
        return dict.fromkeys(cls._dependencies(value), "")

    @classmethod
    def _version(cls, value: Any) -> str:
        return cls._text(value).lstrip("=v").strip()

    @classmethod
    def _spec(cls, value: Any) -> str:
        """A dependency range compared only when it is a registry range; npm rewrites git, URL
        and alias specs at publish, so for those the name alone is compared."""
        text = cls._text(value)
        return "" if any(mark in text for mark in (":", "/", "#")) else " ".join(text.split())

    @staticmethod
    def _text(value: Any) -> str:
        return value.strip() if isinstance(value, str) else ""

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @classmethod
    def _dependencies(cls, value: Any) -> dict[str, str]:
        if isinstance(value, list):
            return {item.strip(): "" for item in value if isinstance(item, str) and item.strip()}
        return {str(k).strip(): cls._spec(v) for k, v in cls._mapping(value).items()}

    @classmethod
    def _bins(cls, manifest: dict[str, Any]) -> dict[str, str]:
        value = manifest.get("bin")
        if isinstance(value, str):
            value = {cls._text(manifest.get("name")).rsplit("/", 1)[-1]: value}
        return {
            str(k).strip(): cls._text(v).removeprefix("./").lstrip("/")
            for k, v in cls._mapping(value).items()
        }

    @staticmethod
    def _render(entries: dict[str, str]) -> str:
        shown = ", ".join(f"{k}@{v}" if v else k for k, v in sorted(entries.items())[:8])
        return shown + (" ..." if len(entries) > 8 else "")


__all__ = ["RULE_ID", "Disagreement", "ManifestConfusion"]
