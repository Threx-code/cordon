"""Helm charts.

```
  Chart.yaml           a chart (apiVersion v2): name, version, type, kubeVersion, and its
                       dependencies -- name, version constraint, repository (https://, oci://,
                       file://, or `@name` / `alias:name` for a repository added with `helm repo
                       add`), alias, condition, tags
  requirements.yaml    the same dependencies, for an apiVersion v1 chart
  Chart.lock           the versions `helm dependency update` resolved, with a digest of the
  requirements.lock    dependency list they were resolved from
  charts/<name>.tgz    a dependency as downloaded: its SHA-256 is the digest a repository's
                       index.yaml publishes for it, read here as the entry's hash
  charts/<name>/       a chart unpacked in the parent: a dependency whether or not Chart.yaml
                       lists it
```

Helm has no central registry: every repository is its own, over HTTPS or OCI. A chart's
templates and values are Kubernetes resources, which the configuration detectors judge; their
findings stay apart from the chart dependencies here.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
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
    from collections.abc import Mapping

    from cordon_scanner.core.content import FileContent


class ChartRepository:
    @staticmethod
    def source(repository: str) -> tuple[str | None, str | None]:
        """`(spec override, source)`: a `file://` path is the repository's own chart; an
        `@name` / `alias:name` is a repository added by name, whose URL the chart does not hold."""
        if repository.startswith("file://"):
            return f"path:{repository.removeprefix('file://')}", None
        if repository.startswith(("@", "alias:")):
            return None, f"registry:{repository.removeprefix('alias:').removeprefix('@')}"
        return None, repository or None


class ChartFile:
    """Chart.yaml and requirements.yaml."""

    @staticmethod
    def load(content: FileContent) -> dict[str, Any]:
        data = DataYaml.load(content.text, source=content.path)
        if not isinstance(data, dict):
            raise ValueError("not a mapping")
        return data

    @staticmethod
    def dependency(entry: Mapping[str, Any], field_name: str) -> DeclaredDependency | None:
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            return None
        repository = str(entry.get("repository") or "")
        local, source = ChartRepository.source(repository)
        conditions: list[str] = []
        if isinstance(entry.get("condition"), str):
            conditions.append(f"condition {entry['condition']}")
        tags = entry.get("tags")
        if isinstance(tags, list) and tags:
            conditions.append(f"tags {', '.join(str(t) for t in tags)}")
        alias = entry.get("alias")
        return DeclaredDependency(
            name=name,
            spec=local or str(entry.get("version") or "*"),
            scope=Scope.RUNTIME,
            field_name=field_name,
            alias=alias if isinstance(alias, str) else None,
            source=source,
            platform=tuple(conditions),
            note=f"installed only where {' or '.join(conditions)} enables it"
            if conditions
            else None,
        )

    @staticmethod
    def parse(content: FileContent, ecosystem: str, files: Mapping[str, FileContent]) -> Manifest:
        try:
            data = ChartFile.load(content)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid {content.basename}: {exc}")
        chart = content.basename in ("Chart.yaml", "Chart.yml")
        if chart and (not data.get("name") or not data.get("version")):
            return BaseEcosystem._err(content, ecosystem, "a Chart.yaml without name and version")
        listed = data.get("dependencies") or []
        if not isinstance(listed, list):
            return BaseEcosystem._err(content, ecosystem, "`dependencies` is not a list")
        directory = content.path.rpartition("/")[0]
        sibling = files.get(f"{directory}/requirements.yaml" if directory else "requirements.yaml")
        if chart and str(data.get("apiVersion", "v1")) == "v1" and sibling is not None:
            # An apiVersion v1 chart keeps its dependencies in requirements.yaml.
            try:
                requirements = ChartFile.load(sibling)
            except ValueError as exc:
                return BaseEcosystem._err(
                    content, ecosystem, f"invalid requirements.yaml beside it: {exc}"
                )
            extra = requirements.get("dependencies")
            listed = [*listed, *(extra if isinstance(extra, list) else [])]
        declared = [
            d
            for d in (
                ChartFile.dependency(e, "dependencies") for e in listed if isinstance(e, dict)
            )
            if d is not None
        ]
        if chart:
            kube = data.get("kubeVersion")
            if isinstance(kube, str):
                declared.append(
                    DeclaredDependency(
                        name="kubernetes", spec=kube, scope=Scope.PLATFORM, field_name="kubeVersion"
                    )
                )
            # A chart unpacked under charts/ is a dependency whether Chart.yaml lists it or not --
            # a directory in the repository, not a path inside a downloaded archive (`.tgz!`).
            prefix = f"{directory}/charts/" if directory else "charts/"
            named = {d.alias or d.name for d in declared} | {d.name for d in declared}
            for path in sorted(files):
                rest = path[len(prefix) :] if path.startswith(prefix) else ""
                if (
                    "!" not in path
                    and rest.count("/") == 1
                    and rest.endswith(("/Chart.yaml", "/Chart.yml"))
                ):
                    subchart = rest.split("/")[0]
                    if subchart not in named:
                        declared.append(
                            DeclaredDependency(
                                name=subchart,
                                spec=f"path:./charts/{subchart}",
                                field_name="charts/",
                            )
                        )
        sources = (
            [f"chart type {data['type']}"] if chart and isinstance(data.get("type"), str) else []
        )
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            name=BaseEcosystem._s(data.get("name")),
            version=str(data["version"]) if data.get("version") is not None else None,
            dependencies=tuple(declared),
            sources=tuple(sources),
        )


class ChartLock:
    """Chart.lock and requirements.lock."""

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        try:
            data = ChartFile.load(content)
        except ValueError as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"invalid {content.basename}: {exc}",
            )
        listed = data.get("dependencies")
        if not isinstance(listed, list) or not isinstance(data.get("digest"), str):
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error="a chart lock without its dependencies and digest",
            )
        entries: list[LockEntry] = []
        for entry in listed:
            if (
                not isinstance(entry, dict)
                or not isinstance(entry.get("name"), str)
                or entry.get("version") is None
            ):
                return LockGraph(
                    path=content.path,
                    ecosystem=ecosystem,
                    parse_error="a locked dependency without name and version",
                )
            repository = str(entry.get("repository") or "")
            local, source = ChartRepository.source(repository)
            entries.append(
                LockEntry(
                    name=entry["name"],
                    version=str(entry["version"]),
                    resolved_from=None if local else source,
                    local=bool(local),
                    direct=True,
                )
            )
        return LockGraph(path=content.path, ecosystem=ecosystem, entries=tuple(entries))

    @staticmethod
    def digest(content: FileContent, ecosystem: str) -> Manifest:
        """The lock's digest, as a source: what `helm dependency build` compares with the chart's
        dependencies to tell whether the lock is still theirs."""
        try:
            data = ChartFile.load(content)
        except ValueError as exc:
            return BaseEcosystem._err(content, ecosystem, f"invalid {content.basename}: {exc}")
        digest = data.get("digest")
        return Manifest(
            path=content.path,
            ecosystem=ecosystem,
            sources=(f"lock digest {digest}",) if isinstance(digest, str) else (),
        )


class ChartArchive:
    """charts/<name>-<version>.tgz: a downloaded dependency, identified by its own Chart.yaml
    (read from the archive in memory, never extracted) and hashed whole."""

    MAX_CHART_BYTES: ClassVar[int] = 256 * 1024
    MAX_MEMBERS: ClassVar[int] = 10_000

    @staticmethod
    def parse(content: FileContent, ecosystem: str) -> LockGraph:
        raw = content.raw
        digest = hashlib.sha256(raw).hexdigest()
        try:
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
                for index, member in enumerate(archive):
                    if index > ChartArchive.MAX_MEMBERS:
                        break
                    if (
                        member.isfile()
                        and member.name.count("/") == 1
                        and member.name.endswith("/Chart.yaml")
                        and member.size <= ChartArchive.MAX_CHART_BYTES
                    ):
                        handle = archive.extractfile(member)
                        text = (
                            handle.read(ChartArchive.MAX_CHART_BYTES).decode("utf-8", "replace")
                            if handle
                            else ""
                        )
                        data = DataYaml.load(text, source=content.path)
                        if (
                            isinstance(data, dict)
                            and data.get("name")
                            and data.get("version") is not None
                        ):
                            entry = LockEntry(
                                name=str(data["name"]),
                                version=str(data["version"]),
                                integrity=f"sha256:{digest}",
                            )
                            return LockGraph(
                                path=content.path,
                                ecosystem=ecosystem,
                                entries=(entry,),
                                companion=True,
                                owner_levels=1,
                            )
        except (tarfile.TarError, gzip.BadGzipFile, EOFError, OSError, ValueError) as exc:
            return LockGraph(
                path=content.path,
                ecosystem=ecosystem,
                parse_error=f"not a readable chart archive: {type(exc).__name__}",
                companion=True,
                owner_levels=1,
            )
        return LockGraph(
            path=content.path,
            ecosystem=ecosystem,
            parse_error="a chart archive without its Chart.yaml",
            companion=True,
            owner_levels=1,
        )


class HelmEcosystem(BaseEcosystem):
    """Chart dependencies."""

    id = "helm"
    purl_type = "helm"
    # requirements.yaml is Ansible's name too: an apiVersion v1 chart's is read through the
    # Chart.yaml beside it, not claimed by name.
    manifest_globs: tuple[str, ...] = ("**/Chart.yaml", "**/Chart.lock", "**/requirements.lock")
    lockfile_globs: tuple[str, ...] = ("**/Chart.lock", "**/requirements.lock", "**/charts/*.tgz")
    registry_hosts: frozenset[str] = frozenset()
    records_integrity = False
    """A lock records no hash per chart; a downloaded archive in charts/ is hashed when present."""

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def is_registry_host(self, url: str | None) -> bool:
        """Every chart repository is its own registry, served over HTTPS or OCI; a named one
        (`@name`) is the organisation's."""
        if not url:
            return False
        return url.startswith(("https://", "oci://", "registry:"))

    def parse_manifest(self, content: FileContent) -> Manifest:
        return self.parse_in_tree(content, {content.path: content})

    def parse_in_tree(self, content: FileContent, files: Mapping[str, FileContent]) -> Manifest:
        if content.basename in ("Chart.lock", "requirements.lock"):
            return ChartLock.digest(content, self.id)
        return ChartFile.parse(content, self.id, files)

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        if content.basename.endswith(".tgz"):
            return ChartArchive.parse(content, self.id)
        return ChartLock.parse(content, self.id)


__all__ = ["ChartArchive", "ChartFile", "ChartLock", "ChartRepository", "HelmEcosystem"]
