"""CRAN / R.

```
  DESCRIPTION         Depends (R and packages), Imports, LinkingTo, Suggests, Enhances, Remotes,
                      biocViews, SystemRequirements -- Debian control format
  renv.lock           R version and repositories, Bioconductor version, and every package with
                      its Source (Repository | Bioconductor | GitHub | ... | Local), remote
                      fields, hash, and requirements (renv < 1.1: `Requirements`; 1.1 and later:
                      the package's own Depends / Imports / LinkingTo)
  renv/settings.json  renv's configuration: snapshot type, Bioconductor, dependency fields
  PACKAGES            a CRAN-like repository's index (drat, miniCRAN): packages it serves
```

R's base packages (`methods`, `utils`, ...) ship with R itself and are never dependencies.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Collection, Mapping
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
    from cordon_scanner.core.content import FileContent


BASE_PACKAGES: frozenset[str] = frozenset(
    {
        "base",
        "compiler",
        "datasets",
        "graphics",
        "grDevices",
        "grid",
        "methods",
        "parallel",
        "splines",
        "stats",
        "stats4",
        "tcltk",
        "tools",
        "translations",
        "utils",
    }
)


class Dcf:
    """Debian control format: `Field: value`, continuation lines indented."""

    FIELD: ClassVar[re.Pattern[str]] = re.compile(r"^([A-Za-z][\w@./\-]*):\s?(.*)$")

    @staticmethod
    def records(text: str) -> list[dict[str, str]]:
        """Every record (blank-line separated), or ValueError when a line is neither a field nor
        a continuation."""
        out: list[dict[str, str]] = []
        current: dict[str, str] = {}
        last = ""
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                if current:
                    out.append(current)
                current, last = {}, ""
                continue
            if line[0] in " \t":
                if not last:
                    raise ValueError(f"line {number}: a continuation with no field before it")
                current[last] += " " + line.strip()
                continue
            found = Dcf.FIELD.match(line)
            if not found:
                raise ValueError(f"line {number}: not a `Field: value` line")
            last = found.group(1)
            current[last] = found.group(2).strip()
        if current:
            out.append(current)
        return out


class Description:
    FIELDS: ClassVar[tuple[tuple[str, Scope], ...]] = (
        ("Depends", Scope.RUNTIME),
        ("Imports", Scope.RUNTIME),
        ("LinkingTo", Scope.BUILD),
        ("Suggests", Scope.DEV),
        ("Enhances", Scope.OPTIONAL),
    )
    ENTRY: ClassVar[re.Pattern[str]] = re.compile(
        r"^([A-Za-z][A-Za-z0-9._]*)\s*(?:\(\s*([^)]*?)\s*\))?$"
    )

    @staticmethod
    def remotes(value: str) -> dict[str, str]:
        """`Remotes:` entries as `package -> spec`: `github::owner/repo@ref`, `owner/repo`,
        `bioc::release/Pkg`, `url::...`, `git::...`, `local::...`."""
        out: dict[str, str] = {}
        for raw in value.split(","):
            remote = raw.strip()
            if not remote:
                continue
            kind, _, target = remote.partition("::") if "::" in remote else ("github", "", remote)
            reference = ""
            if "@" in target and kind in ("github", "gitlab", "bitbucket"):
                target, _, reference = target.partition("@")
            name = target.rstrip("/").rpartition("/")[2].removesuffix(".git") or target
            if kind in ("github", "gitlab", "bitbucket"):
                host = {
                    "github": "github.com",
                    "gitlab": "gitlab.com",
                    "bitbucket": "bitbucket.org",
                }[kind]
                out[name] = f"git+https://{host}/{target}" + (f"#{reference}" if reference else "")
            elif kind == "git":
                out[name] = f"git+{target}"
            elif kind == "bioc":
                out[name] = "registry:bioconductor"
            elif kind == "url":
                out[name] = target
            elif kind == "local":
                out[name] = f"path:{target}"
        return out

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            records = Dcf.records(content.text)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable DESCRIPTION: {exc}")
        if not records or "Package" not in records[0]:
            return BaseEcosystem._err(content, ecosystem, "a DESCRIPTION has no `Package` field")
        fields = records[0]
        missing = [f for f in ("Version", "License") if f not in fields]
        if missing:
            # Fields R requires of every package: one without them is incomplete, most often
            # cut short before the dependency fields that follow them.
            return BaseEcosystem._err(
                content, ecosystem, f"a DESCRIPTION without the required {', '.join(missing)}"
            )
        remotes = Description.remotes(fields.get("Remotes", ""))
        bioconductor = "biocViews" in fields
        declared: list[DeclaredDependency] = []
        for field, scope in Description.FIELDS:
            for chunk in fields.get(field, "").split(","):
                if not chunk.strip():
                    continue
                found = Description.ENTRY.match(chunk.strip())
                if not found:
                    # `R (>= 4` -- an entry that is not `name` or `name (requirement)` is a
                    # damaged field, not one to skip.
                    return BaseEcosystem._err(
                        content, ecosystem, f"an entry in {field} is not `name (requirement)`"
                    )
                name, requirement = found.group(1), (found.group(2) or "").strip()
                if name == "R":
                    declared.append(
                        DeclaredDependency(
                            name="R",
                            spec=requirement or "*",
                            scope=Scope.PLATFORM,
                            field_name=field,
                        )
                    )
                    continue
                if name in BASE_PACKAGES:
                    continue
                remote = remotes.get(name)
                spec = (
                    remote if remote and not remote.startswith("registry:") else requirement or "*"
                )
                declared.append(
                    DeclaredDependency(
                        name=name,
                        spec=spec,
                        scope=scope,
                        field_name=field + (" (Remotes)" if remote else ""),
                        source=remote if remote and remote.startswith("registry:") else None,
                        note=f"a {field} dependency: renv locks it only when snapshot.dev is on"
                        if field in ("Suggests", "Enhances")
                        else None,
                    )
                )
        for requirement in re.split(r"[,;]", fields.get("SystemRequirements", "")):
            text = requirement.strip()
            if text:
                # A system library or tool the package needs from the operating system.
                name = re.sub(r"\s+", "-", text.split("(")[0].strip().lower())[:64]
                declared.append(
                    DeclaredDependency(
                        name=name, spec=text, scope=Scope.PLATFORM, field_name="SystemRequirements"
                    )
                )
        hooks: tuple[Hook, ...] = ()
        if fields.get("NeedsCompilation", "").strip().lower() == "yes":
            # Compiled when installed from source: the package's C, C++ or Fortran is built, by
            # its own Makevars, on the installing machine.
            hooks = (
                Hook(
                    kind="build",
                    path=content.path,
                    name="NeedsCompilation",
                    command="R CMD INSTALL compiles src/",
                    ecosystem=ecosystem,
                ),
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=fields.get("Package"),
            version=fields.get("Version"),
            dependencies=tuple(declared),
            sources=("repository bioconductor",) if bioconductor else (),
            hooks=hooks,
        )

    #: What `R CMD INSTALL` runs from a source package before and after building it.
    INSTALL_SCRIPTS: ClassVar[tuple[str, ...]] = (
        "configure",
        "configure.win",
        "cleanup",
        "cleanup.win",
    )

    @staticmethod
    def with_install_scripts(manifest: Manifest, files: Collection[str]) -> Manifest:
        """A source package's `configure` and `cleanup` beside its DESCRIPTION: shell scripts
        `R CMD INSTALL` runs on the installing machine, unasked, as an npm `postinstall` runs.
        Reported as install hooks; a `src/` directory as compiled code, when NeedsCompilation
        did not already say so."""
        if manifest.parse_error:
            return manifest
        directory = manifest.path.rpartition("/")[0]
        prefix = f"{directory}/" if directory else ""
        hooks = list(manifest.hooks)
        for script in Description.INSTALL_SCRIPTS:
            if f"{prefix}{script}" in files:
                hooks.append(
                    Hook(
                        kind="install",
                        path=manifest.path,
                        name="install",
                        command=f"sh {prefix}{script}",
                        ecosystem=manifest.ecosystem,
                    )
                )
        if not hooks and any(path.startswith(f"{prefix}src/") for path in files):
            hooks.append(
                Hook(
                    kind="build",
                    path=manifest.path,
                    name="src",
                    command="R CMD INSTALL compiles src/",
                    ecosystem=manifest.ecosystem,
                )
            )
        return dataclasses.replace(manifest, hooks=tuple(hooks)) if hooks else manifest


class RenvLock:
    TOOLS: ClassVar[frozenset[str]] = frozenset({"renv", "BiocManager", "BiocVersion"})

    @staticmethod
    def requirements(package: dict[str, Any]) -> tuple[str, ...]:
        names: set[str] = set()
        listed = package.get("Requirements")
        if isinstance(listed, list):
            names.update(str(x) for x in listed)
        for field in ("Depends", "Imports", "LinkingTo"):
            value = package.get(field)
            items = (
                value
                if isinstance(value, list)
                else str(value).split(",")
                if isinstance(value, str)
                else []
            )
            for item in items:
                found = Description.ENTRY.match(str(item).strip())
                if found:
                    names.add(found.group(1))
        return tuple(sorted(n for n in names if n != "R" and n not in BASE_PACKAGES))

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error=f"invalid JSON: {exc}"
            )
        packages = data.get("Packages")
        if not isinstance(packages, dict):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no `Packages` object"
            )
        entries: list[LockEntry] = []
        for key, package in sorted(packages.items()):
            if not isinstance(package, dict):
                continue
            name = str(package.get("Package") or key)
            if name in RenvLock.TOOLS:
                # The tool that wrote the lock, and Bioconductor's installer that renv records to
                # restore Bioconductor packages: tools, not the project's dependencies.
                entries.append(
                    LockEntry(name=name, version=str(package.get("Version", "")), scope=Scope.TOOL)
                )
                continue
            source = str(package.get("Source", "Repository"))
            resolved_from = None
            local = False
            if source in ("GitHub", "GitLab", "Bitbucket"):
                host = {
                    "GitHub": "github.com",
                    "GitLab": "gitlab.com",
                    "Bitbucket": "bitbucket.org",
                }[source]
                user, repo = package.get("RemoteUsername", ""), package.get("RemoteRepo", name)
                sha = package.get("RemoteSha") or package.get("RemoteRef") or ""
                resolved_from = f"git+https://{host}/{user}/{repo}#{sha}"
            elif source == "Git":
                resolved_from = f"git+{package.get('RemoteUrl', '')}#{package.get('RemoteSha', '')}"
            elif source == "Bioconductor":
                resolved_from = "registry:bioconductor"
            elif source in ("Local", "Cellar"):
                local = True
            elif source == "URL":
                resolved_from = BaseEcosystem._s(package.get("RemoteUrl"))
            digest = package.get("Hash")
            entries.append(
                LockEntry(
                    name=name,
                    version=str(package.get("Version", "")),
                    # renv's hash of the package's DESCRIPTION record: what renv checks a
                    # restored package against.
                    # A value that is not an md5 is kept, and reported as malformed.
                    integrity=f"md5:{digest}" if isinstance(digest, str) and digest else None,
                    resolved_from=resolved_from,
                    local=local,
                    dependencies=RenvLock.requirements(package),
                )
            )
        # A snapshot records only what is reachable from the project, and marks nothing direct: a
        # package no other locked package requires is one the project asked for.
        required = {n.lower() for e in entries for n in e.dependencies}
        entries = [
            LockEntry(
                name=e.name,
                version=e.version,
                integrity=e.integrity,
                resolved_from=e.resolved_from,
                local=e.local,
                scope=e.scope,
                dependencies=e.dependencies,
                direct=e.scope is not Scope.TOOL and e.name.lower() not in required,
            )
            for e in entries
        ]
        raw_r = data.get("R")
        r: dict[str, Any] = raw_r if isinstance(raw_r, dict) else {}
        if isinstance(r.get("Version"), str):
            entries.append(
                LockEntry(name="R", version=str(r["Version"]), scope=Scope.PLATFORM, direct=True)
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            entries=tuple(entries),
            integrity_elsewhere=not any(e.integrity for e in entries),
        )


class RenvSettings:
    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = BaseEcosystem._json_object(content.text)
        except (json.JSONDecodeError, ValueError) as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid JSON: {exc}")
        sources = []
        for key in ("snapshot.type", "bioconductor.version", "ppm.enabled"):
            value = data.get(key)
            if value is not None:
                sources.append(f"renv {key}: {value}")
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))


class PackagesIndex:
    """`PACKAGES`: a CRAN-like repository's index. It lists what a repository serves, not what a
    project depends on, so it declares nothing; it is read so that a damaged one is reported."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            records = Dcf.records(content.text)
        except ValueError:
            return Manifest(path=content.path, ecosystem=ecosystem)  # not a repository index
        served = [r["Package"] for r in records if "Package" in r and "Version" in r]
        if not served:
            return Manifest(path=content.path, ecosystem=ecosystem)
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            sources=(f"repository index serving {len(served)} package(s)",),
        )


class CranEcosystem(BaseEcosystem):
    """CRAN, Bioconductor and R remotes, through DESCRIPTION and renv."""

    id = "cran"
    purl_type = "cran"
    manifest_globs: tuple[str, ...] = ("**/DESCRIPTION", "**/renv/settings.json", "**/PACKAGES")
    lockfile_globs: tuple[str, ...] = ("**/renv.lock",)
    registry_hosts: frozenset[str] = frozenset(
        {
            "cran.r-project.org",
            "cloud.r-project.org",
            "packagemanager.posit.co",
            "packagemanager.rstudio.com",
            "bioconductor.org",
        }
    )
    records_integrity = False
    """renv records a hash of each package's DESCRIPTION, not of an archive, and recent renv
    versions write none: there is no archive hash to find missing."""

    def normalize_name(self, name: str) -> str:
        """Folded to lower case, although CRAN itself is case-sensitive: a pair of CRAN packages
        differing only in case is close to unknown, while swapping the case of a well-known name
        is a standard typosquat."""
        return name.strip().lower()

    def is_registry_host(self, url: str | None) -> bool:
        """Bioconductor is R's second public repository, not a departure from the registry."""
        if url and url.lower() == "registry:bioconductor":
            return True
        return super().is_registry_host(url)

    def parse_manifest(self, content: FileContent) -> Manifest:
        if content.basename == "settings.json":
            return RenvSettings.parse(content, self.id)
        if content.basename == "PACKAGES":
            return PackagesIndex.parse(content, self.id)
        return Description.parse(content, self.id)

    def parse_in_tree(self, content: FileContent, files: Mapping[str, Any]) -> Manifest:
        return self.hooks_from_tree(self.parse_manifest(content), files)

    def hooks_from_tree(self, manifest: Manifest, paths: Collection[str]) -> Manifest:
        """A source package's `configure` and `cleanup` are files beside DESCRIPTION."""
        if not manifest.path.endswith("DESCRIPTION"):
            return manifest
        return Description.with_install_scripts(manifest, paths)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        return RenvLock.parse(content, self.id)


__all__ = [
    "BASE_PACKAGES",
    "CranEcosystem",
    "Dcf",
    "Description",
    "PackagesIndex",
    "RenvLock",
    "RenvSettings",
]
