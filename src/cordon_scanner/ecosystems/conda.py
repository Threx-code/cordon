"""Conda.

```
  environment.yml     channels (in priority order), dependencies as match specs
                      (`name=version=build`, `channel::name`, ranges), a `pip:` subsection (PyPI),
                      platform selectors (`# [linux]`)
  meta.yaml           a conda-build recipe: requirements build/host/run and test, with its Jinja
                      `{% set %}` values substituted (nothing else of the template is evaluated)
  conda-lock.yml      every package per platform: manager (conda | pip), url, md5 and sha256,
                      dependencies (virtual packages among them)
  explicit export     `@EXPLICIT` and one package URL per line, `#md5` or `#sha256:...`
```

A pip entry in an environment or a lock is a PyPI package, recorded as one.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.core.datayaml import DataYaml
from cordon_scanner.core.models import Scope
from cordon_scanner.ecosystems.base import (
    BaseEcosystem,
    DeclaredDependency,
    LockEntry,
    LockGraph,
    Manifest,
)

if TYPE_CHECKING:
    from cordon_scanner.core.content import FileContent


class MatchSpec:
    """A conda match spec: `numpy>=1.26,<2.1`, `pandas=2.2.*`, `openssl=3.*=*_0`,
    `conda-forge::numpy`, `numpy 1.26.* py312*`."""

    PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^(?:(?P<channel>[\w.\-/:]+)::)?(?P<name>[A-Za-z0-9_][A-Za-z0-9_.\-]*)\s*(?P<rest>.*)$"
    )

    @staticmethod
    def parse(text: str) -> tuple[str, str, str | None, str | None] | None:
        """`(name, version spec, build, channel)`."""
        found = MatchSpec.PATTERN.match(text.strip())
        if not found:
            return None
        rest = found.group("rest").strip()
        build = None
        if rest.startswith("=") and not rest.startswith("=="):
            parts = rest[1:].split("=")
            version = parts[0]
            build = parts[1] if len(parts) > 1 else None
            # Conda's single `=` is fuzzy: `scipy=1.13` matches 1.13.x. Only `==` is exact.
            if version and not version.endswith("*"):
                version = f"{version}.*"
        elif " " in rest:
            version, _, build = rest.partition(" ")
            build = build.strip() or None
        else:
            version = rest
        version = version.strip() or "*"
        return found.group("name"), version, build, found.group("channel")


class CondaFile:
    """The filename of a conda package, `name-version-build.conda` or `.tar.bz2`, and the URL it
    sits under: `.../<channel>/<subdir>/<file>`."""

    @staticmethod
    def parse(url: str) -> tuple[str, str, str, str, str] | None:
        """`(name, version, build, subdir, channel)`."""
        path = url.split("#", 1)[0].rstrip("/")
        parts = path.split("/")
        if len(parts) < 3:
            return None
        filename, subdir = parts[-1], parts[-2]
        channel = parts[-3]
        stem = filename.removesuffix(".conda").removesuffix(".tar.bz2")
        pieces = stem.rsplit("-", 2)
        if len(pieces) != 3 or stem == filename:
            return None
        return pieces[0], pieces[1], pieces[2], subdir, channel


class Environment:
    SELECTOR: ClassVar[re.Pattern[str]] = re.compile(r"^\s*-\s*(.+?)\s*#\s*\[([^\]]{1,64})\]")

    @staticmethod
    def selectors(text: str) -> dict[str, str]:
        """`spec -> selector` for each dependency line carrying a `# [linux]`-style selector,
        which the data reader drops with the comment."""
        out: dict[str, str] = {}
        for line in text.splitlines():
            found = Environment.SELECTOR.match(line)
            if found:
                out[found.group(1).strip().strip("'\"")] = found.group(2).strip()
        return out

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid environment file: {exc}")
        if not isinstance(data, dict):
            return BaseEcosystem._err(content, ecosystem, "an environment file is a mapping")
        dependencies = data.get("dependencies")
        if dependencies is None:
            # Nothing to create: a file cut short most often ends before this key.
            return BaseEcosystem._err(
                content, ecosystem, "no `dependencies`: an environment with nothing in it"
            )
        if not isinstance(dependencies, list):
            return BaseEcosystem._err(content, ecosystem, "`dependencies` is not a list")
        if any(item is None for item in dependencies):
            # A bare `- `, which conda refuses: most often a file cut short mid-list, with
            # everything after it lost.
            return BaseEcosystem._err(content, ecosystem, "an empty entry in `dependencies`")
        selectors = Environment.selectors(content.text)
        declared: list[DeclaredDependency] = []
        for item in dependencies or []:
            if isinstance(item, dict) and isinstance(item.get("pip"), list):
                from cordon_scanner.ecosystems.pypi import PypiRequirement

                for requirement in item["pip"]:
                    parsed = PypiRequirement.parse(str(requirement))
                    if parsed is None:
                        continue
                    name, _extras, spec, marker, _url = parsed
                    declared.append(
                        DeclaredDependency(
                            name=name,
                            spec=spec or "*",
                            field_name="dependencies.pip",
                            ecosystem="pypi",
                            platform=(f"marker {marker}",) if marker else (),
                        )
                    )
                continue
            if not isinstance(item, str):
                continue
            parsed_spec = MatchSpec.parse(item)
            if parsed_spec is None:
                continue
            name, version, build, channel = parsed_spec
            conditions = []
            if build:
                conditions.append(f"build {build}")
            if item.strip() in selectors:
                conditions.append(f"selector {selectors[item.strip()]}")
            # Conda installs Python itself as a package of the environment: runtime, not platform.
            declared.append(
                DeclaredDependency(
                    name=name,
                    spec=version,
                    scope=Scope.RUNTIME,
                    field_name="dependencies",
                    platform=tuple(conditions),
                    source=f"registry:{channel}" if channel else None,
                )
            )
        pip_section = any(
            isinstance(i, dict) and isinstance(i.get("pip"), list) for i in dependencies
        )
        if pip_section and not any(d.name == "pip" and d.ecosystem is None for d in declared):
            # conda installs pip itself for a pip: subsection that does not list it ("I'm adding
            # one for you, but still nagging you"), from the environment's channels.
            declared.append(
                DeclaredDependency(
                    name="pip",
                    spec="*",
                    scope=Scope.RUNTIME,
                    field_name="dependencies",
                    note="not listed: conda installs pip itself to install the pip: subsection",
                )
            )
        channels = data.get("channels")
        sources = tuple(
            f"channel {i + 1}: {c}"
            for i, c in enumerate(channels if isinstance(channels, list) else [])
        )
        variables = data.get("variables")
        if isinstance(variables, dict) and variables:
            # Set in the environment when it is activated. Named, never valued: a value here is as
            # likely a token as a path, and the secret detectors read the file for those.
            sources = (
                *sources,
                f"sets {', '.join(sorted(str(k) for k in variables))} on activation",
            )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=BaseEcosystem._s(data.get("name")),
            dependencies=tuple(declared),
            sources=sources,
        )


class Condarc:
    """`.condarc`: the channels conda searches, and how strictly it keeps to their order.

    `channel_priority: strict` takes a package from the first channel that has it at all. Flexible
    (the default before conda 23.10) or disabled lets the solver take it from a later channel --
    so with a private channel first and a public one after, a public package of the same name can
    be chosen. Recorded with the channels, in order.
    """

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid .condarc: {exc}")
        if data is None:
            return Manifest(path=content.path, ecosystem=ecosystem)
        if not isinstance(data, dict):
            return BaseEcosystem._err(content, ecosystem, ".condarc is not a map")
        channels = [str(c) for c in data.get("channels") or () if isinstance(c, (str, int))]
        priority = data.get("channel_priority")
        sources = [f"channel {i + 1}: {c}" for i, c in enumerate(channels)]
        if isinstance(priority, str):
            sources.append(f"channel_priority {priority.strip().lower()}")
        elif priority is False:
            sources.append("channel_priority disabled")
        return Manifest(path=content.path, ecosystem=ecosystem, sources=tuple(sources))


class Recipe:
    """`meta.yaml`, a conda-build recipe: a Jinja template of YAML. `{% set x = "..." %}` values
    are substituted into `{{ x }}`; anything else Jinja would compute is left out, never run."""

    SET: ClassVar[re.Pattern[str]] = re.compile(
        r"""\{%-?\s*set\s+(\w+)\s*=\s*(["'])([^"'\n]{0,256})\2\s*-?%\}"""
    )
    EXPRESSION: ClassVar[re.Pattern[str]] = re.compile(r"\{\{\s*([\w.]+)(?:\s*\|[^}]*)?\s*\}\}")

    @staticmethod
    def render(text: str) -> str:
        values = {m.group(1): m.group(3) for m in Recipe.SET.finditer(text)}
        lines = []
        for line in text.splitlines():
            if re.match(r"^\s*\{%.*%\}\s*$", line):
                continue
            line = Recipe.EXPRESSION.sub(lambda m: values.get(m.group(1), "UNRESOLVED"), line)
            lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> Manifest:
        rendered = Recipe.render(content.text)
        try:
            data = DataYaml.load(rendered, source=content.path)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"not a readable recipe: {exc}")
        if not isinstance(data, dict) or "package" not in data:
            # `meta.yaml` is a common name; one with no `package` is not a conda recipe, and is
            # not this reader's to complain about.
            return Manifest(path=content.path, ecosystem=ecosystem)
        selectors = Environment.selectors(content.text)
        declared: list[DeclaredDependency] = []
        requirements = (
            data.get("requirements") if isinstance(data.get("requirements"), dict) else {}
        )
        sections = [("build", Scope.BUILD), ("host", Scope.BUILD), ("run", Scope.RUNTIME)]
        lists = [(s, scope, (requirements or {}).get(s)) for s, scope in sections]
        test = data.get("test") if isinstance(data.get("test"), dict) else {}
        lists.append(("test.requires", Scope.TEST, (test or {}).get("requires")))
        for section, scope, items in lists:
            for item in items if isinstance(items, list) else []:
                text = str(item)
                if text.startswith("{{") or "UNRESOLVED" in text:
                    continue  # a compiler('c') or a value only Jinja could compute
                parsed = MatchSpec.parse(text)
                if parsed is None:
                    continue
                name, version, build, _channel = parsed
                conditions = [f"build {build}"] if build else []
                if text in selectors:
                    conditions.append(f"selector {selectors[text]}")
                declared.append(
                    DeclaredDependency(
                        name=name,
                        spec=version,
                        scope=scope,
                        field_name=f"requirements.{section}",
                        platform=tuple(conditions),
                    )
                )
        package = data["package"] if isinstance(data["package"], dict) else {}
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=BaseEcosystem._s(package.get("name")),
            version=BaseEcosystem._s(package.get("version")),
            dependencies=tuple(declared),
        )


class CondaLock:
    VIRTUAL: ClassVar[re.Pattern[str]] = re.compile(r"^__\w+$")

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = DataYaml.load(content.text, source=content.path)
        except ValueError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"invalid conda-lock file: {exc}",
            )
        if not isinstance(data, dict) or not isinstance(data.get("package"), list):
            return LockGraph(
                path=content.path, ecosystem=ecosystem, parse_error="no `package` list"
            )
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        platforms = [str(p) for p in (metadata or {}).get("platforms") or []]
        groups: dict[tuple[str, str, str, str | None], dict[str, Any]] = {}
        virtual: dict[str, str] = {}
        for package in data["package"]:
            if not isinstance(package, dict) or not package.get("name"):
                continue
            manager = str(package.get("manager", "conda"))
            url = str(package.get("url", ""))
            parsed = CondaFile.parse(url) if manager == "conda" else None
            build = parsed[2] if parsed else None
            key = (manager, str(package["name"]), str(package.get("version", "")), build)
            slot = groups.setdefault(
                key,
                {
                    "platforms": set(),
                    "url": url,
                    "hash": None,
                    "edges": set(),
                    "optional": package.get("optional") is True,
                    "category": str(package.get("category", "main")),
                },
            )
            slot["platforms"].add(str(package.get("platform", "")))
            hashes = package.get("hash") if isinstance(package.get("hash"), dict) else {}
            sha = (hashes or {}).get("sha256")
            md5 = (hashes or {}).get("md5")
            slot["hash"] = slot["hash"] or (
                f"sha256:{sha}" if sha else f"md5:{md5}" if md5 else None
            )
            dependencies = (
                package.get("dependencies") if isinstance(package.get("dependencies"), dict) else {}
            )
            for name, requirement in (dependencies or {}).items():
                if CondaLock.VIRTUAL.match(str(name)):
                    virtual.setdefault(str(name), str(requirement))
                else:
                    slot["edges"].add(str(name))
        entries: list[LockEntry] = []
        for (manager, name, version, build), slot in sorted(
            groups.items(), key=lambda item: str(item[0])
        ):
            # The artefact's own subdir and build (from its URL) identify it; the platforms of the
            # lock it serves, when not all of them, are where it applies.
            conditions: list[str] = []
            channel = None
            if manager == "conda":
                parsed = CondaFile.parse(slot["url"])
                channel = parsed[4] if parsed else None
                if parsed:
                    conditions.append(f"subdir {parsed[3]}")
            if build:
                conditions.append(f"build {build}")
            subset = sorted(p for p in slot["platforms"] if p)
            if platforms and set(subset) != set(platforms):
                conditions.extend(f"platform {p}" for p in subset)
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=slot["hash"],
                    # The artefact's own URL on the public channels: where it was resolved from,
                    # and what names its channel (conda-forge and main are different builds).
                    resolved_from=None
                    if manager == "pip" or channel is None
                    else str(slot["url"]).split("#", 1)[0]
                    if channel in ("conda-forge", "main", "defaults")
                    else f"registry:{channel}",
                    scope=Scope.OPTIONAL if slot["optional"] else Scope.RUNTIME,
                    dependencies=tuple(sorted(slot["edges"])),
                    platform=tuple(conditions),
                    ecosystem="pypi" if manager == "pip" else None,
                )
            )
        for name, requirement in sorted(virtual.items()):
            # A virtual package (`__glibc`, `__osx`, `__cuda`) is the system the environment
            # needs, never installed.
            entries.append(
                LockEntry(
                    name=name,
                    version="",
                    scope=Scope.PLATFORM,
                    platform=(f"requires {requirement}",),
                )
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class ExplicitExport:
    """`conda list --explicit` / `conda-lock render --kind explicit`: `@EXPLICIT`, then a URL per
    package with `#<md5>` or `#sha256:<hex>`."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        lines = [
            line.strip()
            for line in content.text.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not lines or lines[0] != "@EXPLICIT":
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="not an explicit export: no `@EXPLICIT` line",
            )
        entries: list[LockEntry] = []
        unreadable = 0
        for line in lines[1:]:
            url, _, fragment = line.partition("#")
            parsed = CondaFile.parse(url)
            if parsed is None:
                unreadable += 1
                continue
            name, version, build, subdir, channel = parsed
            digest = None
            if fragment.startswith("sha256:"):
                digest = fragment
            elif re.fullmatch(r"[0-9a-fA-F]{32}", fragment):
                digest = f"md5:{fragment}"
            elif fragment:
                digest = f"sha256:{fragment}" if len(fragment) == 64 else f"md5:{fragment}"
            entries.append(
                LockEntry(
                    name=name,
                    version=version,
                    integrity=digest,
                    resolved_from=url.split("#", 1)[0]
                    if channel in ("conda-forge", "main", "defaults")
                    else f"registry:{channel}",
                    platform=(f"subdir {subdir}", f"build {build}"),
                )
            )
        if unreadable and not entries:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"{unreadable} line(s) are not package URLs",
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))


class CondaEcosystem(BaseEcosystem):
    """Conda: environment files, recipes, conda-lock files and explicit exports."""

    id = "conda"
    purl_type = "conda"
    manifest_globs: tuple[str, ...] = (
        "**/environment.yml",
        "**/environment.yaml",
        "**/meta.yaml",
        "**/.condarc",
    )
    lockfile_globs: tuple[str, ...] = (
        "**/conda-lock.yml",
        "**/conda-lock.yaml",
        "**/explicit*.txt",
        "**/conda-*.lock",
    )
    registry_hosts: frozenset[str] = frozenset(
        {"anaconda.org", "conda.anaconda.org", "repo.anaconda.com"}
    )

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def qualifiers(self, platform: tuple[str, ...]) -> str:
        """`?build=...&subdir=...`: two builds of one version are two artefacts."""
        found: dict[str, str] = {}
        for condition in platform:
            kind, _, value = condition.partition(" ")
            if kind in ("build", "subdir") and value and " " not in value and len(found) < 2:
                found.setdefault(kind, value)
        return ("?" + "&".join(f"{k}={v}" for k, v in sorted(found.items()))) if found else ""

    def parse_manifest(self, content: FileContent) -> Manifest:
        if content.basename == "meta.yaml":
            return Recipe.parse(content, self.id)
        if content.basename == ".condarc":
            return Condarc.parse(content, self.id)
        return Environment.parse(content, self.id)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename.startswith("conda-lock."):
            return CondaLock.parse(content, self.id)
        return ExplicitExport.parse(content, self.id)


__all__ = [
    "CondaEcosystem",
    "CondaFile",
    "CondaLock",
    "Environment",
    "ExplicitExport",
    "MatchSpec",
    "Recipe",
]
