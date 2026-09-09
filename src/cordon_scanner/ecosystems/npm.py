"""npm, pnpm and yarn.

The manifest is parsed as JSON, never scanned line by line. That distinction is
load-bearing: a line-oriented reader silently assumes pretty-printed input, and
any tool that rewrites `package.json` can emit it on a single line. The check
then finds nothing while a postinstall script sits in plain sight. Reformatting
is not an exotic evasion, it is an accident that happens routinely, and a
parser a whitespace change can blind is not a check.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon_scanner.core.content import FileContent

SCOPE_FIELDS = {
    "dependencies": Scope.RUNTIME,
    "devDependencies": Scope.DEV,
    "optionalDependencies": Scope.OPTIONAL,
    "peerDependencies": Scope.PEER,
}


class NpmEcosystem(BaseEcosystem):
    @staticmethod
    def _name_from_location(location: str) -> str:
        """Recover a package name from a node_modules path."""
        _, _, tail = location.rpartition("node_modules/")
        return tail or location

    @staticmethod
    def _str_or_none(value: object) -> str | None:
        return str(value) if isinstance(value, str) and value else None

    id = "npm"
    purl_type = "npm"
    manifest_globs: tuple[str, ...] = ("**/package.json",)
    lockfile_globs: tuple[str, ...] = (
        "**/package-lock.json",
        "**/npm-shrinkwrap.json",
        "**/pnpm-lock.yaml",
        "**/yarn.lock",
    )
    registry_hosts: frozenset[str] = frozenset(
        {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com"}
    )

    # Everything npm, pnpm and yarn will execute around an install. `prepare`
    # and `prepublishOnly` are included because they run on `npm install` in a
    # git checkout, which surprises people who assume only `postinstall` matters.
    lifecycle_keys = frozenset(
        {
            "preinstall",
            "install",
            "postinstall",
            "prepare",
            "prepublish",
            "prepublishOnly",
            "prepack",
            "postpack",
            "postpublish",
            "dependencies",
        }
    )

    def normalize_name(self, name: str) -> str:
        """npm names are case-insensitive and scope-aware.

        The scope is preserved. `@acme/utils` and `utils` are different
        packages, and folding the scope away would make a scoped internal
        package look identical to an unscoped public one -- which is precisely
        the confusion a dependency-confusion attack exploits.
        """
        return name.strip().lower()

    # -- Manifest --------------------------------------------------------

    def parse_manifest(self, content: FileContent) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return Manifest(
                path=content.path,
                ecosystem=self.id,
                parse_error=f"invalid JSON: {exc}",
            )
        declared: list[DeclaredDependency] = []
        for field_name, scope in SCOPE_FIELDS.items():
            section = data.get(field_name)
            if not isinstance(section, dict):
                continue
            for name, spec in sorted(section.items()):
                if isinstance(spec, str):
                    declared.append(
                        DeclaredDependency(
                            name=str(name),
                            spec=spec,
                            scope=scope,
                            field_name=field_name,
                        )
                    )

        scripts = data.get("scripts")
        hooks: tuple[Hook, ...] = ()
        if isinstance(scripts, dict):
            hooks = tuple(self.lifecycle_hooks(scripts, content.path))

        overrides: dict[str, str] = {}
        for key in ("overrides", "resolutions"):
            section = data.get(key)
            if isinstance(section, dict):
                for name, spec in section.items():
                    if isinstance(spec, str):
                        overrides[str(name)] = spec

        return Manifest(
            path=content.path,
            ecosystem=self.id,
            name=str(data["name"]) if isinstance(data.get("name"), str) else None,
            version=str(data["version"]) if isinstance(data.get("version"), str) else None,
            dependencies=tuple(declared),
            hooks=hooks,
            overrides=overrides,
            private=bool(data.get("private", False)),
            repository=_repository_of(data),
        )

    # -- Lockfiles -------------------------------------------------------

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        name = content.basename
        if name in {"package-lock.json", "npm-shrinkwrap.json"}:
            return self._parse_npm_lock(content)
        if name == "pnpm-lock.yaml":
            return self._parse_pnpm_lock(content)
        if name == "yarn.lock":
            return self._parse_yarn_lock(content)
        return LockGraph(
            path=content.path, ecosystem=self.id, parse_error=f"unsupported lockfile: {name}"
        )

    def _parse_npm_lock(self, content: FileContent) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=self.id, parse_error=f"invalid JSON: {exc}"
            )

        entries: list[LockEntry] = []

        # Lockfile v2 and v3 use a flat `packages` map keyed by install path.
        packages = data.get("packages")
        if isinstance(packages, dict):
            for location, meta in sorted(packages.items()):
                if not location or not isinstance(meta, dict):
                    continue  # "" is the root project itself
                name = meta.get("name") or NpmEcosystem._name_from_location(location)
                if not name:
                    continue
                entries.append(
                    LockEntry(
                        name=str(name),
                        version=str(meta.get("version", "")),
                        integrity=NpmEcosystem._str_or_none(meta.get("integrity")),
                        resolved_from=NpmEcosystem._str_or_none(meta.get("resolved")),
                        scope=Scope.DEV if meta.get("dev") else Scope.RUNTIME,
                        dependencies=tuple(sorted((meta.get("dependencies") or {}).keys())),
                        # Depth one under node_modules means a direct dependency.
                        direct=location.count("node_modules/") == 1,
                    )
                )
            return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

        # Lockfile v1 nests under `dependencies`.
        deps = data.get("dependencies")
        if isinstance(deps, dict):
            entries.extend(self._walk_v1(deps, depth=0))

        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    def _walk_v1(self, section: dict[str, Any], depth: int) -> list[LockEntry]:
        out: list[LockEntry] = []
        for name, meta in sorted(section.items()):
            if not isinstance(meta, dict):
                continue
            out.append(
                LockEntry(
                    name=str(name),
                    version=str(meta.get("version", "")),
                    integrity=NpmEcosystem._str_or_none(meta.get("integrity")),
                    resolved_from=NpmEcosystem._str_or_none(meta.get("resolved")),
                    scope=Scope.DEV if meta.get("dev") else Scope.RUNTIME,
                    dependencies=tuple(sorted((meta.get("requires") or {}).keys()))
                    if isinstance(meta.get("requires"), dict)
                    else (),
                    direct=depth == 0,
                )
            )
            nested = meta.get("dependencies")
            if isinstance(nested, dict):
                out.extend(self._walk_v1(nested, depth + 1))
        return out

    _PNPM_KEY = re.compile(r"^\s{2}(/?[^:]+):\s*$")
    _PNPM_FIELD = re.compile(r"^\s{4,}(\w+):\s*(.*)$")
    _PNPM_RESOLUTION = re.compile(r"resolution:\s*\{([^}]*)\}")

    def _parse_pnpm_lock(self, content: FileContent) -> LockGraph:
        """Parse pnpm's lockfile.

        Deliberately line-oriented rather than fed to the general YAML reader:
        pnpm lockfiles are machine-generated with a stable shape, and they are
        large enough that a general parser is measurably slower for no gain.

        The fields that matter are the resolution integrity hash and the
        registry the package came from. A missing integrity hash means nothing
        verifies what is downloaded; a non-registry resolution means the
        ecosystem's own protections do not apply.
        """
        entries: list[LockEntry] = []
        current: str | None = None
        integrity: str | None = None
        tarball: str | None = None
        is_dev = False

        def flush() -> None:
            nonlocal current, integrity, tarball, is_dev
            if current:
                name, _, version = current.rpartition("@")
                name = name.strip("/").lstrip("/")
                if name:
                    entries.append(
                        LockEntry(
                            name=name,
                            version=version,
                            integrity=integrity,
                            resolved_from=tarball,
                            scope=Scope.DEV if is_dev else Scope.RUNTIME,
                        )
                    )
            current, integrity, tarball, is_dev = None, None, None, False

        in_packages = False
        for line in content.text.splitlines():
            if line.startswith("packages:"):
                in_packages = True
                continue
            if not in_packages:
                continue
            if line and not line[0].isspace():
                flush()
                in_packages = False
                continue

            key = self._PNPM_KEY.match(line)
            if key:
                flush()
                current = key.group(1).strip().strip("'\"")
                continue

            resolution = self._PNPM_RESOLUTION.search(line)
            if resolution:
                body = resolution.group(1)
                for part in body.split(","):
                    k, _, v = part.partition(":")
                    k, v = k.strip(), v.strip().strip("'\"")
                    if k == "integrity":
                        integrity = v
                    elif k == "tarball":
                        tarball = v
                continue

            field = self._PNPM_FIELD.match(line)
            if field and field.group(1) == "dev":
                is_dev = field.group(2).strip() == "true"

        flush()
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))

    _YARN_HEADER = re.compile(r'^"?([^"@\s][^@]*)@')
    _YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?')
    _YARN_RESOLVED = re.compile(r'^\s+resolved:?\s+"?([^"\s]+)"?')
    _YARN_INTEGRITY = re.compile(r'^\s+integrity:?\s+"?([^"\s]+)"?')
    _YARN_CHECKSUM = re.compile(r'^\s+checksum:\s+"?([^"\s]+)"?')

    def _parse_yarn_lock(self, content: FileContent) -> LockGraph:
        """Parse yarn's lockfile, both the v1 and berry shapes."""
        entries: list[LockEntry] = []
        name: str | None = None
        version = ""
        resolved: str | None = None
        integrity: str | None = None

        def flush() -> None:
            nonlocal name, version, resolved, integrity
            if name and version:
                entries.append(
                    LockEntry(
                        name=name,
                        version=version,
                        integrity=integrity,
                        resolved_from=resolved,
                    )
                )
            name, version, resolved, integrity = None, "", None, None

        for line in content.text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line[0].isspace():
                flush()
                header = self._YARN_HEADER.match(line.strip())
                if header:
                    name = header.group(1).strip()
                continue
            for pattern, target in (
                (self._YARN_VERSION, "version"),
                (self._YARN_RESOLVED, "resolved"),
                (self._YARN_INTEGRITY, "integrity"),
                (self._YARN_CHECKSUM, "integrity"),
            ):
                match = pattern.match(line)
                if match:
                    if target == "version":
                        version = match.group(1)
                    elif target == "resolved":
                        resolved = match.group(1)
                    else:
                        integrity = match.group(1)
                    break

        flush()
        return LockGraph(path=content.path, ecosystem=self.id, entries=tuple(entries))


__all__ = ["NpmEcosystem"]


def _repository_of(data: dict[str, object]) -> str | None:
    """The source repository a `package.json` claims.

    npm accepts either a string or an object with a `url`, and both are common.
    Returned verbatim; normalising for comparison is the caller's job, because
    what counts as "the same repository" is a question about the comparison
    rather than about the manifest.
    """
    field = data.get("repository")
    if isinstance(field, str) and field:
        return field
    if isinstance(field, dict):
        url = field.get("url")
        if isinstance(url, str) and url:
            return url
    return None
