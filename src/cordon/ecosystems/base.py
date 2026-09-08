"""The ecosystem contract.

An ecosystem adapter teaches Cordon how one package manager describes
dependencies: where its manifests live, how to read them, what its lockfile
means, and which paths in it execute during installation.

Two decisions govern every implementation.

**Parse, never invoke.** The graph is built by reading the lockfile, never by
running the ecosystem's own resolver. Running `npm ls` or `pip install` would
execute untrusted tooling against attacker-controlled metadata inside the tool
whose entire purpose is avoiding that, and it would make results
non-reproducible because a resolver consults a live registry.

**Name normalisation is per-ecosystem.** Registries disagree about what makes
two names the same: PyPI folds separators and case, npm folds case, Maven
composes group and artifact, Go encodes capitals. Typosquat detection is
meaningless without this, and it is where most tools generate their false
positives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from cordon.core.models import Dependency, Hook, Scope

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from cordon.core.content import FileContent


@dataclass(frozen=True, slots=True)
class DeclaredDependency:
    """A dependency as written in a manifest, before resolution.

    Distinct from :class:`~cordon.core.models.Dependency`, which is resolved.
    The declared form carries the version *range* and the source the author
    asked for, and comparing the two is how a stale security pin is detected.
    """

    name: str
    spec: str
    scope: Scope = Scope.RUNTIME
    field_name: str = ""

    @property
    def is_non_registry(self) -> bool:
        """Whether this resolves from somewhere other than the registry.

        A git URL, archive URL or filesystem path bypasses the lockfile's
        integrity hashes, advisory matching and any release-age cooldown in a
        single move. The dependency may be entirely legitimate; the point is
        that none of the ecosystem's own protections apply to it.
        """
        lowered = self.spec.strip().lower()
        return lowered.startswith(
            (
                "git+",
                "git:",
                "github:",
                "gitlab:",
                "bitbucket:",
                "http://",
                "https://",
                "file:",
                "link:",
                "portal:",
                "path:",
                "../",
                "./",
                "/",
            )
        )

    @property
    def is_unpinned(self) -> bool:
        """Whether the spec admits versions the author has not seen.

        Not a vulnerability on its own, and normal in a library. It matters for
        an application, where it means the artefact that was tested and the
        artefact that ships can differ.
        """
        spec = self.spec.strip()
        if not spec or spec in {"*", "latest", "", "any"}:
            return True
        return spec.startswith(("^", "~", ">", "<")) and "==" not in spec


@dataclass(frozen=True, slots=True)
class Manifest:
    """A parsed dependency manifest."""

    path: str
    ecosystem: str
    name: str | None = None
    version: str | None = None
    dependencies: tuple[DeclaredDependency, ...] = ()
    hooks: tuple[Hook, ...] = ()
    overrides: Mapping[str, str] = field(default_factory=dict)
    """Version pins forced across the tree. Read because a pin written to
    satisfy an advisory can fall behind it and then hold a vulnerable version in
    place while reading as protective."""
    private: bool = False
    parse_error: str | None = None
    """Set when the file could not be parsed. Reported as an OPERATIONAL
    finding: a manifest that cannot be read is a manifest whose contents were
    not checked, and that must never look like a clean result."""


@dataclass(frozen=True, slots=True)
class LockEntry:
    """One resolved package in a lockfile."""

    name: str
    version: str
    integrity: str | None = None
    resolved_from: str | None = None
    scope: Scope = Scope.RUNTIME
    dependencies: tuple[str, ...] = ()
    direct: bool = False


@dataclass(frozen=True, slots=True)
class LockGraph:
    """A parsed lockfile."""

    path: str
    ecosystem: str
    entries: tuple[LockEntry, ...] = ()
    parse_error: str | None = None

    def __len__(self) -> int:
        return len(self.entries)


@runtime_checkable
class Ecosystem(Protocol):
    """One package ecosystem."""

    id: str
    purl_type: str
    manifest_globs: tuple[str, ...]
    lockfile_globs: tuple[str, ...]
    registry_hosts: frozenset[str]

    def parse_manifest(self, content: FileContent) -> Manifest: ...

    def parse_lockfile(self, content: FileContent) -> LockGraph: ...

    def normalize_name(self, name: str) -> str:
        """Fold a name to its canonical form for comparison."""
        ...

    def to_dependencies(
        self, graph: LockGraph, *, project: str | None = None
    ) -> tuple[Dependency, ...]:
        """Flatten a parsed lockfile into dependency records."""
        ...

    def is_registry_host(self, url: str | None) -> bool:
        """Whether a resolved URL points at this ecosystem's registry."""
        ...


class BaseEcosystem:
    """Shared behaviour. Implementing the protocol directly is equally valid."""

    @staticmethod
    def _err(content: FileContent, eco: str, message: str) -> Manifest:
        return Manifest(path=content.path, ecosystem=eco, parse_error=message)

    @staticmethod
    def _table_spec(value: object) -> str:
        if isinstance(value, dict):
            for key in ("version", "git", "url", "path", "hosted"):
                if key in value:
                    return str(value[key])
            return "*"
        return str(value)

    @staticmethod
    def _s(value: object) -> str | None:
        return str(value) if isinstance(value, str) and value else None

    id: str = "base"
    purl_type: str = "generic"
    manifest_globs: tuple[str, ...] = ()
    lockfile_globs: tuple[str, ...] = ()
    registry_hosts: frozenset[str] = frozenset()

    # Lifecycle keys that execute around installation. An allowlist model is
    # used against these rather than a blocklist of dangerous commands: the
    # attack is *adding* a script, so enumerating known-bad commands is always a
    # step behind whoever is writing the next one.
    lifecycle_keys: frozenset[str] = frozenset()

    def normalize_name(self, name: str) -> str:
        return name.strip().lower()

    def parse_manifest(self, content: FileContent) -> Manifest:
        raise NotImplementedError

    def parse_lockfile(self, content: FileContent) -> LockGraph:
        raise NotImplementedError

    def purl(self, name: str, version: str | None = None) -> str:
        """Build a Package URL.

        The cross-ecosystem identity, so findings, advisories and threat
        intelligence correlate without per-ecosystem special cases.
        """
        base = f"pkg:{self.purl_type}/{name}"
        return f"{base}@{version}" if version else base

    def to_dependencies(
        self, graph: LockGraph, *, project: str | None = None
    ) -> tuple[Dependency, ...]:
        """Convert a lockfile into domain dependencies, computing depth.

        Depth is derived by walking outward from the direct dependencies rather
        than trusting any field in the file, because depth feeds the risk score
        and a lockfile is attacker-controlled input like everything else.
        """
        by_name = {entry.name: entry for entry in graph.entries}
        depths: dict[str, int] = {}
        parents: dict[str, set[str]] = {}

        frontier = [(e.name, 0) for e in graph.entries if e.direct]
        if not frontier:
            # No direct markers: treat everything as depth zero rather than
            # silently reporting a flat graph as deeply nested.
            frontier = [(e.name, 0) for e in graph.entries]

        seen: set[str] = set()
        while frontier:
            name, depth = frontier.pop(0)
            if name in seen and depths.get(name, 99) <= depth:
                continue
            seen.add(name)
            depths[name] = min(depths.get(name, depth), depth)
            entry = by_name.get(name)
            if entry is None:
                continue
            for child in entry.dependencies:
                parents.setdefault(child, set()).add(name)
                if depths.get(child, 99) > depth + 1:
                    frontier.append((child, depth + 1))

        return tuple(
            Dependency(
                purl=self.purl(entry.name, entry.version),
                ecosystem=self.id,
                name=entry.name,
                version=entry.version,
                direct=entry.direct,
                depth=depths.get(entry.name, 0),
                scope=entry.scope,
                resolved_from=entry.resolved_from,
                integrity=entry.integrity,
                parents=tuple(sorted(parents.get(entry.name, ()))),
                project=project,
            )
            for entry in sorted(graph.entries, key=lambda e: (e.name, e.version))
        )

    def is_registry_host(self, url: str | None) -> bool:
        """Whether a resolution points at this ecosystem's own registry.

        Any scheme counts, not only http. Checking for ``http://`` alone
        classified ``git+ssh://...`` as "not a URL, therefore the registry",
        which is exactly backwards: a git-over-SSH dependency is one of the
        clearest cases of resolution outside the registry, and treating it as
        internal silently disabled the provenance check for it.
        """
        if not url:
            return True  # nothing recorded means the default registry

        lowered = url.lower()

        # Anything naming a location outside the registry: a VCS reference, a
        # filesystem path, or a link protocol. Checked before the "no scheme"
        # shortcut, since `file:` and `git:` carry no `//`.
        if lowered.startswith(
            ("git@", "git:", "git+", "ssh://", "file:", "link:", "portal:", "path:")
        ):
            return False

        # A bare name with no scheme is a registry reference by definition.
        if "://" not in lowered:
            return True

        host = lowered.split("://", 1)[1].split("/", 1)[0]
        host = host.rpartition("@")[2]  # strip any userinfo
        return any(known in host for known in self.registry_hosts)

    def lifecycle_hooks(self, scripts: Mapping[str, str], path: str) -> Iterable[Hook]:
        """Hooks among a manifest's scripts.

        Only the lifecycle keys, not every script. A `test` script runs when
        somebody chooses to run tests; a `postinstall` script runs whether they
        wanted it to or not.
        """
        for key, command in sorted(scripts.items()):
            if key in self.lifecycle_keys:
                yield Hook(
                    kind=key,
                    path=path,
                    name=key,
                    command=str(command),
                    ecosystem=self.id,
                )


__all__ = [
    "BaseEcosystem",
    "DeclaredDependency",
    "Ecosystem",
    "LockEntry",
    "LockGraph",
    "Manifest",
]
