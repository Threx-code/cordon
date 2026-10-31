"""Which of a scan target's files the dependency inventory reads to know what gets installed.

What the inventory reads is what a scan is complete about: a dependency file it reads and cannot
parse leaves that file's dependencies out of the graph, and the scan incomplete
(`Dependencies.build`, `Dependencies.readable_manifest`). So the scope is drawn by role, here, once:

- A directory on disk is a repository: every dependency file the walk found is read, as before.
- An archive that is not a published package -- a repository snapshot, a source tree -- is read as
  the same tree would be on disk: the walker's own pruned directories (`node_modules`, virtualenvs,
  build caches) are skipped, by the walker's own lists, so archive and disk cannot drift apart.
- A published package (`PackageFormat.of`) is installed from its root manifest and lockfile and the
  workspace members its root lockfile declares. A lockfile nested elsewhere in it is the maintainers'
  environment, a manifest under its tests or vendored sources describes some other project, and its
  CI workflows and container files never run for whoever installs it: none of them is read for
  dependencies, so none of them can leave its scan incomplete. Their content is still scanned.

Measured before it was drawn this way (review 98, 27-PERFORMANCE and the shared plan, 2026-10-29): of
324 real units whose scan carried an unparsed dependency file, 191 would have turned incomplete when
every such file counted, most over files no installer reads (zlib's contrib inside boost, a source
archive's CI YAML).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.engine.pipeline.install_scripts import InstallScripts
from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.files.walk import DEFAULT_PRUNE_DIRS, INSTALLED_CODE_PRUNE_DIRS

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import FileUnit


@dataclass
class DependencyScope:
    """The inventory's scope for one scan. `members` grows as the root lockfiles are read."""

    archive: bool
    published: str
    root: str | None
    members: set[str] = field(default_factory=set)
    scripted: set[str] = field(default_factory=set)
    """Nested directories the package's own install scripts install (`install_scripts.py`)."""
    scripted_unresolved: bool = False
    """An install script installs somewhere it does not name: every nested project counts."""

    #: Ecosystems whose files run in a repository's own automation and never for a package's
    #: installer: a workflow, a container build.
    REPOSITORY_ONLY: ClassVar[frozenset[str]] = frozenset({"actions", "image"})
    PRUNED: ClassVar[frozenset[str]] = DEFAULT_PRUNE_DIRS | INSTALLED_CODE_PRUNE_DIRS
    _SEPARATOR = re.compile(r"[/!]")

    @staticmethod
    def of(units: Iterable[FileUnit], *, published: str, archive: bool) -> DependencyScope:
        """The scope for a target: `published` is `PackageFormat.of`'s answer for an archive."""
        if not (archive and published):
            return DependencyScope(archive=archive, published="", root=None)
        # The package's root: the shallowest directory holding a dependency file it is installed by.
        roots = [
            DependencyScope.directory(u.path)
            for u in units
            if DependencyScope._dependency_file(u.path) and not DependencyScope._pruned(u.path)
        ]
        root = min(roots, key=lambda d: (len(DependencyScope._SEPARATOR.findall(d)), d), default="")
        scope = DependencyScope(archive=True, published=published, root=root)
        scope._read_install_scripts(units)
        return scope

    def _read_install_scripts(self, units: Iterable[FileUnit]) -> None:
        """The nested projects the root's install scripts install, and theirs in turn: installing a
        project runs its own lifecycle scripts too."""
        units = list(units)
        manifests = {
            DependencyScope.directory(u.path): u.content.raw
            for u in units
            if u.path.rsplit("/", 1)[-1] == "package.json" and not DependencyScope._pruned(u.path)
        }
        files = {u.path: u for u in units}
        todo = [self.root] if self.root in manifests else []
        seen: set[str] = set()
        while todo:
            directory = todo.pop()
            if directory in seen:
                continue
            seen.add(directory)
            scripts = InstallScripts.of(manifests[directory])
            self.scripted_unresolved = (
                self.scripted_unresolved
                or scripts.unresolved
                or any(
                    InstallScripts.installs(files[program].content.raw)
                    for program in (
                        f"{directory}/{p}" if directory else p for p in scripts.programs
                    )
                    if program in files
                )
            )
            for relative in scripts.directories:
                nested = f"{directory}/{relative}" if directory else relative
                self.scripted.add(nested)
                if nested in manifests:
                    todo.append(nested)

    @staticmethod
    def directory(path: str) -> str:
        """The directory a member sits in, an archive's own `!` counting as one."""
        cut = max(path.rfind("/"), path.rfind("!"))
        return path[:cut] if cut >= 0 else ""

    @staticmethod
    def _dependency_file(path: str) -> str | None:
        return EcosystemRegistry.lockfile_ecosystem(path) or EcosystemRegistry.manifest_ecosystem(
            path
        )

    @staticmethod
    def _pruned(path: str) -> bool:
        return any(
            part in DependencyScope.PRUNED for part in DependencyScope._SEPARATOR.split(path)[:-1]
        )

    def reads(self, path: str) -> bool:
        """Whether the inventory reads this file for the dependencies it declares or resolves."""
        if not self.archive:
            return True
        if self.published and self._installed_with_package(path):
            return True
        if DependencyScope._pruned(path):
            return False
        if not self.published:
            return True
        if DependencyScope._dependency_file(path) in DependencyScope.REPOSITORY_ONLY:
            return False
        where = DependencyScope.directory(path)
        if self.scripted_unresolved or where in self.scripted:
            # Installed by the package's own install script: what it declares is installed.
            return True
        return where == self.root or where in self.members

    def _installed_with_package(self, path: str) -> bool:
        """A nested file the package's own ecosystem installs with it (`installed_with_package`)."""
        prefix = f"{self.root}/" if self.root else ""
        if not path.startswith(prefix):
            return False
        ecosystem = EcosystemRegistry.get(DependencyScope._dependency_file(path) or "")
        patterns = getattr(ecosystem, "installed_with_package", ())
        relative = path[len(prefix) :]
        return any(PathGlob.matches(relative, pattern) for pattern in patterns)

    @staticmethod
    def everything() -> DependencyScope:
        """Every dependency file, as the inventory read them before it had a scope."""
        return DependencyScope(archive=False, published="", root=None)

    def narrows(self, units: Iterable[FileUnit]) -> bool:
        """Whether this scope leaves any of the target's dependency files unread."""
        return self.archive and any(
            DependencyScope._dependency_file(u.path) and not self.reads(u.path) for u in units
        )

    def ordered(self, units: list[FileUnit]) -> list[FileUnit]:
        """A published package's root files first, so its lockfiles declare the members before any
        member's own file is asked about; any other target in its own order."""
        if not self.published:
            return units
        root = [u for u in units if DependencyScope.directory(u.path) == self.root]
        return root + [u for u in units if DependencyScope.directory(u.path) != self.root]

    def note_members(self, workspace_members: Iterable[tuple[str, str]]) -> None:
        """The workspace members the root lockfiles declared so far: `(directory, ecosystem)`."""
        if self.published:
            self.members.update(directory for directory, _ in workspace_members)


__all__ = ["DependencyScope"]
