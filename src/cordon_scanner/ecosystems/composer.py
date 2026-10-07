"""Composer / PHP.

```
  composer.json   require, require-dev, platform requirements (php, ext-*, lib-*), repositories,
                  provide/replace/conflict, stability flags, inline aliases, scripts,
                  config.allow-plugins
  composer.lock   packages and packages-dev as resolved, with their source, dist, aliases,
                  plugin type and abandonment
  auth.json       repository credentials: read for which hosts are configured, never for values
```

Composer installs nothing it is not told to; the lock is the resolution, and what a package does
at install time is its plugin class (a `composer-plugin`) or the root's `scripts`.
"""

from __future__ import annotations

import fnmatch
import json
import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.models import Hook, Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.core.content import FileContent


class ComposerPlatform:
    """Platform requirements: what the PHP runtime provides, not packages Composer installs."""

    NAMES: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:php(?:-64bit|-ipv6|-zts|-debug)?|hhvm|ext-[\w.\-]+|lib-[\w.\-]+|composer(?:-plugin-api|-runtime-api)?)$",
        re.IGNORECASE,
    )

    @staticmethod
    def includes(name: str) -> bool:
        return bool(ComposerPlatform.NAMES.match(name.strip()))


class ComposerManifest:
    LIFECYCLE: ClassVar[frozenset[str]] = frozenset(
        {
            "pre-install-cmd",
            "post-install-cmd",
            "pre-update-cmd",
            "post-update-cmd",
            "post-autoload-dump",
            "post-root-package-install",
            "post-create-project-cmd",
            "pre-autoload-dump",
            "pre-package-install",
            "post-package-install",
            "pre-package-update",
            "post-package-update",
        }
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str, lifecycle_hooks: Any) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid JSON: {exc}")
        declared: list[DeclaredDependency] = []
        for section, scope in (("require", Scope.RUNTIME), ("require-dev", Scope.DEV)):
            table = data.get(section)
            if table is not None and not isinstance(table, dict):
                return BaseEcosystem._err(content, ecosystem, f"`{section}` is not an object")
            for name, spec in sorted((table or {}).items()):
                text = str(spec).strip()
                if ComposerPlatform.includes(str(name)):
                    declared.append(
                        DeclaredDependency(
                            name=str(name).lower(),
                            spec=text,
                            scope=Scope.PLATFORM,
                            field_name=section,
                        )
                    )
                    continue
                declared.append(
                    DeclaredDependency(
                        name=str(name),
                        spec=text,
                        scope=scope,
                        field_name=section,
                        note=ComposerManifest.branch_note(text),
                    )
                )
        sources: list[str] = []
        repositories = data.get("repositories")
        listed = (
            repositories.values()
            if isinstance(repositories, dict)
            else repositories
            if isinstance(repositories, list)
            else []
        )
        for repository in listed:
            if isinstance(repository, dict):
                kind = str(repository.get("type", ""))
                url = repository.get("url")
                if kind and isinstance(url, str):
                    sources.append(f"repository {kind}: {url}")
                elif (
                    repository.get("packagist") is False or repository.get("packagist.org") is False
                ):
                    sources.append("repository packagist.org: disabled")
            elif repository is False:
                sources.append("repository packagist.org: disabled")
        scripts = data.get("scripts")
        hooks: tuple[Hook, ...] = ()
        if isinstance(scripts, dict):
            flat = {
                str(k): (" && ".join(str(x) for x in v) if isinstance(v, list) else str(v))
                for k, v in scripts.items()
            }
            hooks = tuple(lifecycle_hooks(flat, content.path))
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=BaseEcosystem._s(data.get("name")),
            version=BaseEcosystem._s(data.get("version")),
            dependencies=tuple(declared),
            hooks=hooks,
            sources=tuple(sources),
        )

    @staticmethod
    def branch_note(spec: str) -> str | None:
        """Why a branch requirement has no version: only a lock says which commit it took."""
        constraint = spec.split(" as ", 1)[0].strip()
        branch, _, commit = constraint.partition("#")
        if not (branch.startswith("dev-") or branch.endswith("-dev")):
            return None
        if re.fullmatch(r"[0-9a-fA-F]{40}", commit):
            return f"the branch {branch} pinned to commit {commit[:12]}"
        return f"the branch {branch}: only composer.lock records which commit it resolved to"

    @staticmethod
    def allowed_plugins(data: Mapping[str, Any]) -> Any:
        """`config.allow-plugins`: True, False, or `{pattern: bool}`. Composer 2.2 and later run
        a plugin only when this allows it."""
        config = data.get("config")
        if not isinstance(config, dict):
            return None
        return config.get("allow-plugins")

    @staticmethod
    def plugin_allowed(name: str, allowed: Any) -> bool | None:
        if allowed is True or allowed is False:
            return allowed
        if isinstance(allowed, dict):
            for pattern, value in allowed.items():
                if fnmatch.fnmatchcase(name.lower(), str(pattern).lower()):
                    return bool(value)
            return False
        return None


class ComposerLock:
    """`composer.lock`. A package from Packagist carries Packagist's `notification-url`; one
    from a VCS or path repository does not, and its source is that repository."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        if "packages" not in data and "packages-dev" not in data:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no `packages` list"
            )
        aliases: dict[str, list[str]] = {}
        for alias in data.get("aliases") or []:
            if isinstance(alias, dict) and alias.get("package") and alias.get("alias"):
                aliases.setdefault(str(alias["package"]).lower(), []).append(str(alias["alias"]))
        entries: list[LockEntry] = []
        for section, scope in (("packages", Scope.RUNTIME), ("packages-dev", Scope.DEV)):
            packages = data.get(section)
            if packages is not None and not isinstance(packages, list):
                return LockGraph(
                    path=content.path, ecosystem=ecosystem, parse_error=f"`{section}` is not a list"
                )
            for package in packages or []:
                if not isinstance(package, dict) or not package.get("name"):
                    continue
                entries.append(ComposerLock._entry(package, scope, aliases))
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))

    @staticmethod
    def _entry(
        package: dict[str, Any], scope: Scope, aliases: Mapping[str, list[str]]
    ) -> LockEntry:
        name = str(package["name"])
        raw_dist, raw_source = package.get("dist"), package.get("source")
        dist: dict[str, Any] = raw_dist if isinstance(raw_dist, dict) else {}
        source: dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
        local = (
            str(dist.get("type", "")).lower() == "path"
            or str(source.get("type", "")).lower() == "path"
        )
        from_packagist = "packagist.org" in str(package.get("notification-url", ""))
        resolved_from = None
        if not from_packagist and not local:
            # A VCS repository: the git URL at the locked commit.
            url = source.get("url") or dist.get("url")
            reference = source.get("reference") or dist.get("reference")
            if isinstance(url, str):
                resolved_from = (
                    f"git+{url}#{reference}" if source.get("type") == "git" and reference else url
                )
        require = package.get("require")
        edges = tuple(
            sorted(
                str(n)
                for n in (require if isinstance(require, dict) else {})
                if not ComposerPlatform.includes(str(n))
            )
        )
        conditions = [f"alias {a}" for a in aliases.get(name.lower(), ())]
        abandoned = package.get("abandoned")
        deprecated = None
        if abandoned is True:
            deprecated = "abandoned"
        elif isinstance(abandoned, str) and abandoned:
            deprecated = f"abandoned; use {abandoned} instead"
        shasum = dist.get("shasum")
        return LockEntry(
            name=name,
            version=str(package.get("version", "")),
            # Packagist's GitHub zipballs carry an empty `shasum`: Composer records none and
            # checks none for them. A non-empty one is a real SHA-1 of the archive.
            integrity=f"sha1:{shasum}" if isinstance(shasum, str) and shasum else None,
            resolved_from=resolved_from,
            scope=scope,
            dependencies=edges,
            local=local,
            platform=tuple(conditions),
            license=" OR ".join(str(x) for x in package["license"])
            if isinstance(package.get("license"), list) and package["license"]
            else None,
            deprecated=deprecated,
        )

    @staticmethod
    def plugins(content: FileContent) -> list[tuple[str, str]]:
        """`(name, plugin class)` for each locked `composer-plugin`."""
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError):
            return []
        out = []
        for section in ("packages", "packages-dev"):
            for package in data.get(section) or []:
                if (
                    isinstance(package, dict)
                    and str(package.get("type", "")) == "composer-plugin"
                    and package.get("name")
                ):
                    extra = package.get("extra") if isinstance(package.get("extra"), dict) else {}
                    out.append((str(package["name"]), str((extra or {}).get("class") or "")))
        return out


class ComposerAuth:
    """`auth.json`: which hosts credentials are configured for, by kind. A value never leaves this
    function -- not in a source, a name or an error message."""

    KINDS: ClassVar[tuple[str, ...]] = (
        "http-basic",
        "bearer",
        "github-oauth",
        "gitlab-oauth",
        "gitlab-token",
        "bitbucket-oauth",
        "forgejo-token",
    )

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError):
            # The decoder's message can quote the document; this one must not.
            return BaseEcosystem._err(content, ecosystem, "not valid JSON")
        sources = []
        for kind in ComposerAuth.KINDS:
            table = data.get(kind)
            if isinstance(table, dict):
                for host in sorted(table):
                    if re.fullmatch(r"[A-Za-z0-9.\-]{1,253}(?::\d{1,5})?", str(host)):
                        sources.append(f"credentials {kind}: {host}")
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))


class ComposerEcosystem(BaseEcosystem):
    id = "composer"
    purl_type = "composer"
    manifest_globs: tuple[str, ...] = ("**/composer.json", "**/composer.lock", "**/auth.json")
    lockfile_globs: tuple[str, ...] = ("**/composer.lock",)
    registry_hosts: frozenset[str] = frozenset(
        {"packagist.org", "repo.packagist.org", "api.github.com", "codeload.github.com"}
    )
    records_integrity = False
    """Packagist's archives carry no checksum in the lock (`"shasum": ""`): Composer itself checks
    none, so its absence is not a hash that went missing. A private repository that serves one has
    it recorded and compared."""
    integrity_companion = True

    lifecycle_keys = ComposerManifest.LIFECYCLE

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        directory = content.path.rpartition("/")[0]
        if content.basename == "auth.json":
            return ComposerAuth.parse(content, self.id)
        if content.basename == "composer.lock":
            beside = f"{directory}/composer.json" if directory else "composer.json"
            return self._plugin_hooks(content, files.get(beside))
        return ComposerManifest.parse(content, self.id, self.lifecycle_hooks)

    def _plugin_hooks(self, lock: FileContent, manifest: FileContent | None) -> Manifest:
        """A `composer-plugin` runs its class's `activate()` during `composer install`, before the
        application's own code: Composer's install hook. Reported when the project's
        `config.allow-plugins` lets it run, or when no composer.json says either way."""
        try:
            BaseEcosystem._json_object(lock.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(lock, self.id, f"invalid JSON: {exc}")
        allowed: Any = None
        if manifest is not None:
            try:
                allowed = ComposerManifest.allowed_plugins(
                    BaseEcosystem._json_object(manifest.text)
                )
            except (json.JSONDecodeError, ValueError):
                allowed = None
        hooks = []
        for name, plugin_class in ComposerLock.plugins(lock):
            verdict = ComposerManifest.plugin_allowed(name, allowed)
            if verdict is False:
                continue  # Composer refuses to run it
            hooks.append(
                Hook(
                    kind="plugin",
                    path=lock.path,
                    name=name,
                    command=(
                        f"composer runs {plugin_class or 'its plugin class'} on install"
                        + (" (allowed by config.allow-plugins)" if verdict else "")
                    ),
                    ecosystem=self.id,
                )
            )
        return Manifest(path=lock.path, ecosystem=self.id, hooks=tuple(hooks))

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return ComposerLock.parse(content, self.id)


__all__ = [
    "ComposerAuth",
    "ComposerEcosystem",
    "ComposerLock",
    "ComposerManifest",
    "ComposerPlatform",
]
