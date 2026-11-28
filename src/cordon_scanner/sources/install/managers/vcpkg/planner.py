"""vcpkg (manifest mode): every source archive the manifest's ports download, held to the SHA-512 the portfile states, scanned before vcpkg builds anything.

`vcpkg install` builds each port from source: a portfile and its patches run, and so does the code it downloads (CMake, configure scripts).
In manifest mode the `builtin-baseline` commit of microsoft/vcpkg decides which port versions install, so the ports tree read out of that commit
(through git, not the working tree) is the trusted description. From the manifest the planner follows the dependencies and the features that are
requested or default, reads each port's portfile (`portfile.py`) and holds each archive it downloads to the portfile's own SHA-512. Anything it
cannot read to a hash is refused: classic mode, `overrides`, a registry or overlay other than the builtin tree, a version constraint the baseline
does not meet, a port that fetches another way.

vcpkg then runs with its asset sources set to a folder of the scanned archives, each named by its SHA-512, and with every other origin blocked
(`x-block-origin`), and with binary caching off, so what it builds from is what was scanned (https://learn.microsoft.com/vcpkg/users/assetcaching).
The seeding follows that documentation; it has not been run against the real tool (the tool downloads CMake first, which was not approved).
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.sources.install.managers.vcpkg.portfile import Portfile
from cordon_scanner.sources.install.plan import InstallPlan, InstallRefused, PackageFile

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from cordon_scanner.sources.install.managers.vcpkg.ports import VcpkgPorts


class VcpkgPlanner:
    NAME: ClassVar[re.Pattern[str]] = re.compile(r"[a-z0-9]++(?:-[a-z0-9]++)*+")
    COMMIT: ClassVar[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
    #: Flags that name another source of ports, triplets, binaries or assets.
    REFUSED_FLAGS: ClassVar[tuple[str, ...]] = (
        "--overlay-ports",
        "--overlay-triplets",
        "--binarysource",
        "--x-asset-sources",
        "--x-use-aria2",
    )
    #: Environment variables that do the same.
    REFUSED_ENVIRONMENT: ClassVar[tuple[str, ...]] = (
        "VCPKG_OVERLAY_PORTS",
        "VCPKG_OVERLAY_TRIPLETS",
    )
    CONFIGURATION: ClassVar[frozenset[str]] = frozenset(
        {"registries", "overlay-ports", "overlay-triplets", "default-registry"}
    )
    VERSION_KEYS: ClassVar[tuple[str, ...]] = (
        "version",
        "version-semver",
        "version-date",
        "version-string",
    )
    MAX_PORTS: ClassVar[int] = 3000

    @classmethod
    def verb(cls, args: Sequence[str]) -> str:
        for word in args:
            if not word.startswith("-"):
                return word
        return ""

    @classmethod
    def installs(cls, args: Sequence[str]) -> bool:
        return cls.verb(args) == "install"

    @classmethod
    def manifest_root(cls, args: Sequence[str], project: Path) -> Path:
        for arg in args:
            if arg.startswith("--x-manifest-root="):
                return Path(arg.split("=", 1)[1])
        return project

    @classmethod
    def baseline(cls, manifest: Mapping[str, object]) -> str:
        value = manifest.get("builtin-baseline")
        if not isinstance(value, str) or cls.COMMIT.fullmatch(value) is None:
            raise InstallRefused(
                "vcpkg.json has no builtin-baseline (a 40-character commit of microsoft/vcpkg): without one vcpkg installs whatever "
                "the ports tree holds today. Add one with `vcpkg x-update-baseline --add-initial-baseline`, then run this again"
            )
        return value

    @classmethod
    def read_manifest(cls, args: Sequence[str], root: Path) -> dict[str, object]:
        """The manifest of the project, after the refusals that do not need the ports tree."""
        words = [a for a in args if not a.startswith("-")][1:]
        if words:
            raise InstallRefused(
                "`vcpkg install <port>` (classic mode) installs the ports tree's current state with no baseline: use manifest mode "
                "(a vcpkg.json with a builtin-baseline) so every port is held to a hash"
            )
        for arg in args:
            if arg.startswith(cls.REFUSED_FLAGS):
                raise InstallRefused(
                    f"{arg.split('=')[0]} names a source of ports or files Cordon does not hold to a hash"
                )
        path = root / "vcpkg.json"
        if not path.is_file():
            raise InstallRefused("no vcpkg.json here: Cordon guards manifest mode only")
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise InstallRefused("vcpkg.json is not valid JSON") from exc
        if not isinstance(manifest, dict):
            raise InstallRefused("vcpkg.json is not an object")
        configuration = root / "vcpkg-configuration.json"
        inline = manifest.get("vcpkg-configuration")
        sources = []
        if configuration.is_file():
            try:
                sources.append(json.loads(configuration.read_text(encoding="utf-8")))
            except ValueError as exc:
                raise InstallRefused("vcpkg-configuration.json is not valid JSON") from exc
        if isinstance(inline, dict):
            sources.append(inline)
        for source in sources:
            named = cls.CONFIGURATION & set(source) if isinstance(source, dict) else set()
            if named:
                raise InstallRefused(
                    f"the vcpkg configuration sets {sorted(named)[0]}: a registry or overlay other than the builtin ports tree is not held to a hash"
                )
        if manifest.get("overrides"):
            raise InstallRefused(
                "vcpkg.json has `overrides`, which select port versions from the version database: Cordon reads the baseline's versions only"
            )
        return manifest

    @classmethod
    def edges(cls, entries: object, port: str) -> list[tuple[str, list[str], bool, str]]:
        """(name, features, default-features, minimum version) of each dependency a `dependencies` list names."""
        out: list[tuple[str, list[str], bool, str]] = []
        if not isinstance(entries, list):
            return out
        for entry in entries:
            if isinstance(entry, str):
                name, features, defaults, minimum = entry, [], True, ""
            elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                name = entry["name"]
                features = [
                    f if isinstance(f, str) else str(f.get("name", ""))
                    for f in entry.get("features", [])
                    if isinstance(f, (str, dict))
                ]
                defaults = entry.get("default-features", True) is not False
                minimum = str(entry.get("version>=", ""))
            else:
                raise InstallRefused(
                    f"{port[:60]}: a dependency entry is neither a name nor an object"
                )
            if cls.NAME.fullmatch(name) is None:
                raise InstallRefused(f"{port[:60]}: {name[:60]!r} is not a vcpkg port name")
            out.append((name, features, defaults, minimum))
        return out

    @classmethod
    def version_of(cls, document: Mapping[str, object], port: str) -> str:
        for key in cls.VERSION_KEYS:
            value = document.get(key)
            if isinstance(value, str) and value:
                return value
        raise InstallRefused(f"{port}: its vcpkg.json states no version")

    @staticmethod
    def at_least(have: str, want: str) -> bool:
        """Whether version `have` is `want` or later: dotted numbers compare by number, anything else only by equality."""
        pattern = re.compile(r"\d++(?:[.-]\d++)*+")
        if have == want:
            return True
        if pattern.fullmatch(have) and pattern.fullmatch(want):
            return [int(p) for p in re.split(r"[.-]", have)] >= [
                int(p) for p in re.split(r"[.-]", want)
            ]
        return False

    @classmethod
    def plan(
        cls, args: Sequence[str], project: Path, open_ports: Callable[[str], VcpkgPorts]
    ) -> InstallPlan:
        """The plan for `args` run in `project`; `open_ports(baseline)` opens the ports tree of that commit (`VcpkgPorts`)."""
        manifest = cls.read_manifest(args, cls.manifest_root(args, project))
        ports = open_ports(cls.baseline(manifest))
        try:
            versions, required_by = cls.closure(manifest, ports.read)
            return cls.files(versions, required_by, ports.read)
        finally:
            ports.close()

    @classmethod
    def closure(
        cls, manifest: Mapping[str, object], read: Callable[[str], bytes | None]
    ) -> tuple[dict[str, str], dict[str, set[str]]]:
        """The port -> version of every port the manifest installs, and what asked for each: dependencies, plus the features asked for or default."""
        wanted: dict[str, set[str]] = {}
        required_by: dict[str, set[str]] = {}
        queue: list[tuple[str, str]] = []

        def request(parent: str, edge: tuple[str, list[str], bool, str]) -> None:
            name, features, defaults, minimum = edge
            asked = set(features) | ({"default"} if defaults else set())
            required_by.setdefault(name, set()).add(parent)
            known = wanted.get(name)
            if known is None or not asked <= known or minimum:
                wanted[name] = (known or set()) | asked
                queue.append((name, minimum))

        for edge in cls.edges(manifest.get("dependencies"), "vcpkg.json"):
            request("vcpkg.json", edge)
        table = manifest.get("features")
        if isinstance(table, dict):
            # Every feature of the project itself (`--x-feature` may name any of them).
            for body in table.values():
                for edge in cls.edges(
                    body.get("dependencies") if isinstance(body, dict) else None, "vcpkg.json"
                ):
                    request("vcpkg.json", edge)
        versions: dict[str, str] = {}
        processed: dict[str, set[str]] = {}
        while queue:
            name, minimum = queue.pop()
            if len(wanted) > cls.MAX_PORTS:
                raise InstallRefused(f"the manifest needs more than {cls.MAX_PORTS} ports")
            document = cls.document(name, read)
            versions[name] = cls.version_of(document, name)
            if minimum and not cls.at_least(versions[name], minimum):
                raise InstallRefused(
                    f"{name}: the baseline holds {versions[name]}, but a dependency asks for {minimum} or later: vcpkg would take another "
                    "version from the version database, which Cordon does not read. Move the baseline forward (`vcpkg x-update-baseline`)"
                )
            for entries in cls.bodies(
                name, document, wanted[name], processed.setdefault(name, set())
            ):
                for edge in cls.edges(entries, name):
                    request(name, edge)
        return versions, required_by

    @classmethod
    def document(cls, name: str, read: Callable[[str], bytes | None]) -> dict[str, object]:
        raw = read(f"ports/{name}/vcpkg.json")
        if raw is None:
            raise InstallRefused(f"{name}: no such port in the baseline's ports tree")
        try:
            document = json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise InstallRefused(f"{name}: its vcpkg.json is not valid JSON") from exc
        if not isinstance(document, dict):
            raise InstallRefused(f"{name}: its vcpkg.json is not an object")
        return document

    @classmethod
    def bodies(
        cls, name: str, document: Mapping[str, object], asked: set[str], seen: set[str]
    ) -> list[object]:
        """The `dependencies` lists not read yet for a port: its own, and each enabled feature's (the requested ones and, when
        `default` was asked, the port's default features)."""
        defaults = {
            f if isinstance(f, str) else str(f.get("name", ""))
            for f in document.get("default-features", [])  # type: ignore[attr-defined]
            if isinstance(f, (str, dict))
        }
        enabled = (asked - {"default"}) | (defaults if "default" in asked else set())
        fresh = (enabled - seen) | ({"core"} if "core" not in seen else set())
        seen |= fresh
        out: list[object] = [document.get("dependencies")] if "core" in fresh else []
        table = document.get("features")
        for feature in sorted(fresh - {"core"}):
            found = table.get(feature) if isinstance(table, dict) else None
            if isinstance(found, dict):
                out.append(found.get("dependencies"))
        return out

    @classmethod
    def files(
        cls,
        versions: Mapping[str, str],
        required_by: Mapping[str, set[str]],
        read: Callable[[str], bytes | None],
    ) -> InstallPlan:
        plan = InstallPlan("vcpkg")
        for name in sorted(versions):
            portfile = read(f"ports/{name}/portfile.cmake")
            if portfile is None:
                continue
            for source in Portfile.sources(
                portfile.decode("utf-8", "replace"), name, versions[name]
            ):
                plan.files.append(
                    PackageFile(
                        "vcpkg",
                        name,
                        versions[name],
                        source.url,
                        "sha512",
                        source.sha512,
                        required_by=tuple(sorted(required_by.get(name, ()))),
                    )
                )
        return plan

    @classmethod
    def seed(cls, plan: InstallPlan, files: Path, seed: Path) -> None:
        """Copies each scanned archive to `seed/<its SHA-512>`: how vcpkg's asset cache finds a file."""
        seed.mkdir(mode=0o700, parents=True, exist_ok=True)
        for file in plan.files:
            shutil.copyfile(files / file.filename, seed / file.digest.hex())

    @classmethod
    def environment(cls, seed: Path, base: Mapping[str, str]) -> dict[str, str]:
        """vcpkg's environment for the run: its assets from `seed` only, every other origin blocked, binary caching off."""
        for name in cls.REFUSED_ENVIRONMENT:
            if base.get(name):
                raise InstallRefused(
                    f"{name} is set: it names ports or triplets Cordon does not hold to a hash"
                )
        env = dict(base)
        env["X_VCPKG_ASSET_SOURCES"] = f"clear;x-azurl,{seed.as_uri()},,read;x-block-origin"
        env["VCPKG_BINARY_SOURCES"] = "clear"
        env["VCPKG_DISABLE_METRICS"] = "1"
        return env


__all__ = ["VcpkgPlanner"]
