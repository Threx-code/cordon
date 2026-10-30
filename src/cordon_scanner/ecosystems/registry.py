"""Ecosystem selection.

Matching a file to an ecosystem is done by path pattern, and the order matters
in one specific case: a pinned ``requirements.txt`` is both a manifest and a
lockfile, so it is registered under both and interpreted according to which
question is being asked.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.base import BaseEcosystem, Ecosystem, ReleaseFile
from cordon_scanner.ecosystems.infra.infra import INFRA_ECOSYSTEMS
from cordon_scanner.ecosystems.others import (
    BazelEcosystem,
    CocoaPodsEcosystem,
    ComposerEcosystem,
    ConanEcosystem,
    CondaEcosystem,
    CranEcosystem,
    GitHubActionsEcosystem,
    GradleEcosystem,
    HexEcosystem,
    NuGetEcosystem,
    PubEcosystem,
    RubyGemsEcosystem,
    SwiftEcosystem,
)
from cordon_scanner.ecosystems.packages.cargo import CargoEcosystem
from cordon_scanner.ecosystems.packages.go import GoEcosystem
from cordon_scanner.ecosystems.packages.jvm.maven import MavenEcosystem
from cordon_scanner.ecosystems.packages.npm import NpmEcosystem
from cordon_scanner.ecosystems.packages.pypi import PypiEcosystem
from cordon_scanner.foundation.files.globs import PathGlob
from cordon_scanner.foundation.paths import ContainerPaths

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from cordon_scanner.ecosystems.base import ImageReferences
    from cordon_scanner.ecosystems.infra import image as _ecosystems_infra_image
    from cordon_scanner.foundation.dependencies import InstalledEcosystemFacts, InstallTool

    ImageReference: ImageReferences = _ecosystems_infra_image.ImageReference

_MAX_ANSWERS = 1 << 20
"""Past this many distinct paths the memo starts over, so its memory stays bounded."""


@dataclass(frozen=True, slots=True)
class _GlobIndex:
    """Path-to-ecosystem lookup, arranged for the common answer: no.

    Every registered pattern has the shape `**/<something>`, and almost all of
    those are a literal filename. The linear form asked, for each file, whether
    any of forty patterns matched it -- so a fifty-thousand-file repository ran
    three and a half million glob evaluations to discover that none of its
    files was a manifest. That single question was the largest cost in a warm
    scan of a monorepo, larger than reading the files.

    The index sorts the patterns once into the three shapes they actually take:

    `exact`    `**/package.json` -- a dict lookup on the basename.
    `suffix`   `**/*.gemspec`    -- a dict lookup on the extension.
    `residual` `**/requirements*.txt`, `**/requirements/*.txt` -- anything with
               structure left in it, still matched by glob, but only when the
               two cheap lookups have already failed.

    Ordering is preserved by construction rather than by luck: entries are
    added in ecosystem order and an earlier ecosystem is never overwritten by a
    later one, which is what the linear scan did by returning on first match.
    Whether that ordering is fully equivalent for a given set of registered
    patterns is not assumed -- `manifest_ecosystem_scan` is kept as the
    reference and a test compares the two.
    """

    exact: Mapping[str, str]
    suffix: Mapping[str, str]
    residual: tuple[tuple[str, str], ...]
    bounds: tuple[tuple[str, str], ...] = ()
    """For each residual pattern, what its last segment fixes about a file name: the literal text
    before its first wildcard and after its last. A name that does not start and end with them
    cannot match, and saying so is a string comparison rather than a glob walk -- which is the
    answer for nearly every file, since most are no manifest. Empty when nothing is fixed."""
    rank: Mapping[str, int] = field(default_factory=dict)
    """Each ecosystem's place in the registration order, which decides between two that both
    claim a path, as the linear scan did by returning on the first match. The index looked up
    exact names first whatever their order, so `.github/workflows/requirements.yml` was read as
    an Ansible requirements file rather than the workflow it is."""
    answers: dict[str, str | None] = field(default_factory=dict, compare=False, repr=False)
    """Each path's answer, once. A scan asks about the same path from many places -- the graph's
    workspace, lockfile-reference, hook-path, source and manifest-join passes each walk every
    file -- and a path that is no manifest falls through to the residual globs every time. In a
    50,000-file warm scan that was most of the run (5.0s became 12.5s when those passes
    multiplied). The answer depends on the path alone and the index never changes."""

    @staticmethod
    def build(registered: Sequence[tuple[str, Sequence[str]]]) -> _GlobIndex:
        exact: dict[str, str] = {}
        suffix: dict[str, str] = {}
        residual: list[tuple[str, str]] = []

        for eco_id, patterns in registered:
            for pattern in patterns:
                body = pattern[3:] if pattern.startswith("**/") else pattern
                if "/" in body or "?" in body or "[" in body:
                    residual.append((pattern, eco_id))
                elif body.startswith("*.") and "*" not in body[1:] and body[1:].count(".") == 1:
                    # One extension only: the lookup keys on the last `.`, so `*.opam.locked`
                    # filed under `.opam.locked` could never be found. Those go to the residual,
                    # and so does `*-deployment.yaml`, which is a name ending, not an extension:
                    # filed under `-deployment.yaml` it matched nothing.
                    suffix.setdefault(body[1:], eco_id)
                elif "*" in body:
                    residual.append((pattern, eco_id))
                else:
                    exact.setdefault(body, eco_id)

        return _GlobIndex(
            exact=exact,
            suffix=suffix,
            residual=tuple(residual),
            bounds=tuple(_GlobIndex._name_bounds(pattern) for pattern, _ in residual),
            rank={eco_id: order for order, (eco_id, _) in reversed(list(enumerate(registered)))},
        )

    @staticmethod
    def _name_bounds(pattern: str) -> tuple[str, str]:
        last = pattern.rpartition("/")[2]
        if "**" in last:
            return "", ""
        wild = [i for i, c in enumerate(last) if c in "*?["]
        if not wild:
            return last, last
        closing = last.rfind("]")
        end = max(wild[-1], closing)
        return last[: wild[0]], last[end + 1 :]

    def lookup(self, path: str) -> str | None:
        try:
            return self.answers[path]
        except KeyError:
            pass
        found = self._lookup(path)
        if len(self.answers) >= _MAX_ANSWERS:
            self.answers.clear()
        self.answers[path] = found
        return found

    def _lookup(self, path: str) -> str | None:
        # `basename`, not `rpartition("/")`. An archive member at the root
        # has no separator, so the "basename" became `pkg.zip!package.json`
        # and matched no glob -- a one-line evasion by repackaging.
        inner = ContainerPaths.within_container(path)
        name = inner.rpartition("/")[2]
        candidates = [self.exact.get(name)]
        # `>= 0`, not `> 0`. A file named exactly `.csproj` has its dot at
        # position zero, and `*.csproj` matches it, because the `*` in a glob
        # matches the empty string. Whether a bare dotfile should be read as a
        # project file is a fair question and a separate one; this index is a
        # performance change and must answer exactly what the scan it replaced
        # answered.
        dot = name.rfind(".")
        if dot >= 0:
            candidates.append(self.suffix.get(name[dot:]))
        found = min(
            (c for c in candidates if c is not None),
            key=lambda eco_id: self.rank.get(eco_id, 0),
            default=None,
        )
        # A residual pattern can still win, but only one from an earlier ecosystem.
        limit = self.rank.get(found, 0) if found is not None else None
        for (pattern, eco_id), (head, tail) in zip(self.residual, self.bounds, strict=True):
            if limit is not None and self.rank.get(eco_id, 0) >= limit:
                continue
            if not (name.startswith(head) and name.endswith(tail)):
                continue
            if len(name) < len(head) + len(tail) and head != tail:
                continue
            if PathGlob.matches(inner, pattern):
                return eco_id
        return found


class EcosystemRegistry:
    """Selects the ecosystem that owns a given path.

    Holds the ecosystem instances and the lookups over them together, because
    the order of the tuple is part of the behaviour: a pinned
    ``requirements.txt`` is both a manifest and a lockfile, and which answer
    comes back depends on which question is asked. Separating the data from the
    lookups makes that ordering look incidental when it is not.

    The instances are stateless, so one shared tuple serves every scan.
    """

    ECOSYSTEMS: ClassVar[tuple[Ecosystem, ...]] = (
        NpmEcosystem(),
        PypiEcosystem(),
        CargoEcosystem(),
        GoEcosystem(),
        MavenEcosystem(),
        GradleEcosystem(),
        NuGetEcosystem(),
        ComposerEcosystem(),
        RubyGemsEcosystem(),
        CocoaPodsEcosystem(),
        PubEcosystem(),
        SwiftEcosystem(),
        HexEcosystem(),
        CranEcosystem(),
        ConanEcosystem(),
        CondaEcosystem(),
        BazelEcosystem(),
        GitHubActionsEcosystem(),
        *INFRA_ECOSYSTEMS,
    )

    BY_ID: ClassVar[dict[str, Ecosystem]] = {eco.id: eco for eco in ECOSYSTEMS}

    _MANIFEST_INDEX: ClassVar[_GlobIndex | None] = None
    _LOCKFILE_INDEX: ClassVar[_GlobIndex | None] = None

    @classmethod
    def manifest_index(cls) -> _GlobIndex:
        if cls._MANIFEST_INDEX is None:
            cls._MANIFEST_INDEX = _GlobIndex.build(
                [(eco.id, eco.manifest_globs) for eco in cls.ECOSYSTEMS]
            )
        return cls._MANIFEST_INDEX

    @classmethod
    def lockfile_index(cls) -> _GlobIndex:
        if cls._LOCKFILE_INDEX is None:
            cls._LOCKFILE_INDEX = _GlobIndex.build(
                [(eco.id, eco.lockfile_globs) for eco in cls.ECOSYSTEMS]
            )
        return cls._LOCKFILE_INDEX

    @staticmethod
    def manifest_ecosystem(path: str) -> str | None:
        """Which ecosystem's manifest this path is, if any."""
        return EcosystemRegistry.manifest_index().lookup(path)

    @staticmethod
    def lockfile_ecosystem(path: str) -> str | None:
        """Which ecosystem's lockfile this path is, if any."""
        return EcosystemRegistry.lockfile_index().lookup(path)

    @staticmethod
    def manifest_ecosystem_scan(path: str) -> str | None:
        """The linear form the index replaced. Kept as the reference.

        Not dead code: a test asserts the index agrees with it across every
        registered pattern and a corpus of ordinary paths, which is what makes
        the index safe to change or extend. A third-party ecosystem registering
        an ambiguous pattern shows up there rather than as a file quietly
        attributed to the wrong ecosystem.
        """
        for eco in EcosystemRegistry.ECOSYSTEMS:
            if any(PathGlob.matches(path, pattern) for pattern in eco.manifest_globs):
                return eco.id
        return None

    @staticmethod
    def lockfile_ecosystem_scan(path: str) -> str | None:
        """The linear form the index replaced. See `manifest_ecosystem_scan`."""
        for eco in EcosystemRegistry.ECOSYSTEMS:
            if any(PathGlob.matches(path, pattern) for pattern in eco.lockfile_globs):
                return eco.id
        return None

    @classmethod
    def get(cls, ecosystem_id: str) -> Ecosystem | None:
        return cls.BY_ID.get(ecosystem_id)

    @classmethod
    def all_ecosystems(cls) -> Sequence[Ecosystem]:
        return cls.ECOSYSTEMS

    @classmethod
    def declared_dependencies(cls, files: Sequence[ReleaseFile], ecosystem: str) -> frozenset[str]:
        """The runtime dependencies a published release declares, as its ecosystem reads them;
        none for an ecosystem that does not declare a way to read them."""
        implementation = cls.get(ecosystem)
        if isinstance(implementation, BaseEcosystem):
            return implementation.declared_dependencies(files)
        return frozenset()


class VsCodeExtensionNames(BaseEcosystem):
    """What an editor extension's name declares (`publisher.name`): its facts only. Extensions are
    not a registered package ecosystem, but their names have a namespace."""

    id = "vscode"

    def namespace(self, name: str, alias: str | None = None) -> str | None:
        return name.split(".", 1)[0] if "." in name else None


class RegistryFacts:
    """`foundation.dependencies`' ecosystem ports, answered by each ecosystem's own declarations
    (an unknown ecosystem has the defaults: `BaseEcosystem`); installed through the
    `cordon_scanner.ecosystem_facts` entry point."""

    _DECLARED_ONLY: ClassVar[Mapping[str, BaseEcosystem]] = MappingProxyType(
        {"vscode": VsCodeExtensionNames()}
    )
    _UNKNOWN: ClassVar[BaseEcosystem] = BaseEcosystem()

    @staticmethod
    def _of(ecosystem: str) -> BaseEcosystem:
        """The ecosystem's declarations: registered, declared-only, or the defaults (an ecosystem
        implementing the protocol directly, not through `BaseEcosystem`, has the defaults)."""
        registered = EcosystemRegistry.get(ecosystem)
        if isinstance(registered, BaseEcosystem):
            return registered
        return RegistryFacts._DECLARED_ONLY.get(ecosystem, RegistryFacts._UNKNOWN)

    @staticmethod
    def is_registry_host(ecosystem: str, url: str) -> bool:
        implementation = EcosystemRegistry.get(ecosystem)
        return implementation is not None and implementation.is_registry_host(url)

    @staticmethod
    def lockfile_ecosystem(path: str) -> str | None:
        return EcosystemRegistry.lockfile_ecosystem(path)

    @staticmethod
    def namespace(ecosystem: str, name: str, alias: str | None = None) -> str | None:
        if not name and not alias:
            return None
        return RegistryFacts._of(ecosystem).namespace(name, alias)

    @staticmethod
    def is_builtin(ecosystem: str, name: str) -> bool:
        return RegistryFacts._of(ecosystem).is_builtin(name)

    @staticmethod
    def coordinate_separator(ecosystem: str) -> str | None:
        return RegistryFacts._of(ecosystem).coordinate_separator()

    @staticmethod
    def pinned_by_digest(ecosystem: str) -> bool:
        return RegistryFacts._of(ecosystem).pinned_by_digest()

    @staticmethod
    def is_mutable_version(ecosystem: str, version: str) -> bool:
        return RegistryFacts._of(ecosystem).is_mutable_version(version)

    @staticmethod
    def admits_lowest(ecosystem: str, declared_spec: str) -> bool:
        return RegistryFacts._of(ecosystem).admits_lowest(declared_spec)

    @staticmethod
    def is_held_version(ecosystem: str, version: str) -> bool:
        return RegistryFacts._of(ecosystem).is_held_version(version)

    @staticmethod
    def has_install_scripts(ecosystem: str) -> bool:
        return RegistryFacts._of(ecosystem).has_install_scripts()

    @staticmethod
    def has_scoped_names(ecosystem: str) -> bool:
        return RegistryFacts._of(ecosystem).has_scoped_names()

    @staticmethod
    def is_ci_step(ecosystem: str, name: str) -> bool:
        return RegistryFacts._of(ecosystem).is_ci_step(name)

    @staticmethod
    def squat_comparisons(ecosystem: str) -> tuple[str, ...]:
        return RegistryFacts._of(ecosystem).squat_comparisons()

    @staticmethod
    def pinned_project(ecosystem: str, pins: Sequence[tuple[str, str]]) -> dict[str, str] | None:
        return RegistryFacts._of(ecosystem).pinned_project(pins)

    @staticmethod
    def loose_project(ecosystem: str, names: Sequence[str]) -> dict[str, str] | None:
        return RegistryFacts._of(ecosystem).loose_project(names)

    @staticmethod
    def install_tool(ecosystem: str) -> Sequence[InstallTool]:
        return RegistryFacts._of(ecosystem).install_tool()

    @staticmethod
    def normalised_version(ecosystem: str, version: str) -> str:
        return RegistryFacts._of(ecosystem).normalised_version(version)

    @staticmethod
    def library_entries(
        ecosystem: str, members: Mapping[str, str], manifest: Mapping[str, Any], with_bin: bool
    ) -> set[str]:
        return RegistryFacts._of(ecosystem).library_entries(members, manifest, with_bin)

    @staticmethod
    def published_repository(ecosystem: str, manifest: Mapping[str, Any]) -> str:
        return RegistryFacts._of(ecosystem).published_repository(manifest)

    @staticmethod
    def completes_from_checksums(ecosystem: str) -> bool:
        return RegistryFacts._of(ecosystem).completes_from_checksums()

    @staticmethod
    def bracket_ranges(ecosystem: str) -> bool:
        return RegistryFacts._of(ecosystem).bracket_ranges()

    @staticmethod
    def archive_manifest(ecosystem: str) -> str | None:
        return RegistryFacts._of(ecosystem).archive_manifest()

    @staticmethod
    def compiled_is_inert(ecosystem: str) -> bool:
        return RegistryFacts._of(ecosystem).compiled_is_inert()

    @staticmethod
    def install_manifests(ecosystem: str) -> frozenset[str]:
        return RegistryFacts._of(ecosystem).install_manifests()

    @staticmethod
    def any_install_manifest() -> frozenset[str]:
        return frozenset().union(
            *(
                RegistryFacts._of(e.id).install_manifests()
                for e in EcosystemRegistry.all_ecosystems()
            )
        )

    @staticmethod
    def identity_in_metadata(ecosystem: str) -> bool:
        return RegistryFacts._of(ecosystem).identity_in_metadata()

    @staticmethod
    def release_manifest(ecosystem: str) -> re.Pattern[str] | None:
        return RegistryFacts._of(ecosystem).release_manifest()

    @staticmethod
    def release_identity(
        ecosystem: str, path: str, text: str, found: re.Match[str]
    ) -> tuple[str, str] | None:
        return RegistryFacts._of(ecosystem).release_identity(path, text, found)


#: What the engine uses of this layer by name, and the module that provides each: the one place
#: that knows, so the layer's modules can move without the engine changing. Each is imported
#: when it is first asked for (PEP 562), as the engine's own imports were.
ROLES: dict[str, tuple[str, str]] = {
    "ImageReference": ("cordon_scanner.ecosystems.infra.image", "ImageReference"),
}


def __getattr__(name: str) -> object:
    """The implementation of one of `ROLES`, imported on first use."""
    try:
        module, attribute = ROLES[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    found: object = importlib.import_module(module)
    for part in attribute.split("."):  # a class's member: `Class.MEMBER`
        found = getattr(found, part)
    return found


__all__ = [
    "ROLES",
    "EcosystemRegistry",
    "ImageReference",
    "RegistryFacts",
]

if TYPE_CHECKING:
    # The installed facts conform to every port the domain asks them through (`foundation`).
    _CONFORMS: InstalledEcosystemFacts = RegistryFacts()
