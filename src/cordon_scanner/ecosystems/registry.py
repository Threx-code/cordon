"""Ecosystem selection.

Matching a file to an ecosystem is done by path pattern, and the order matters
in one specific case: a pinned ``requirements.txt`` is both a manifest and a
lockfile, so it is registered under both and interpreted according to which
question is being asked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.core.paths import ContainerPaths
from cordon_scanner.core.walker import PathGlob
from cordon_scanner.ecosystems.base import Ecosystem
from cordon_scanner.ecosystems.infra import INFRA_ECOSYSTEMS
from cordon_scanner.ecosystems.npm import NpmEcosystem
from cordon_scanner.ecosystems.others import (
    BazelEcosystem,
    CargoEcosystem,
    CocoaPodsEcosystem,
    ComposerEcosystem,
    ConanEcosystem,
    CondaEcosystem,
    CranEcosystem,
    GitHubActionsEcosystem,
    GoEcosystem,
    GradleEcosystem,
    HexEcosystem,
    MavenEcosystem,
    NuGetEcosystem,
    PubEcosystem,
    RubyGemsEcosystem,
    SwiftEcosystem,
)
from cordon_scanner.ecosystems.pypi import PypiEcosystem

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


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
    rank: Mapping[str, int] = field(default_factory=dict)
    """Each ecosystem's place in the registration order, which decides between two that both
    claim a path, as the linear scan did by returning on the first match. The index looked up
    exact names first whatever their order, so `.github/workflows/requirements.yml` was read as
    an Ansible requirements file rather than the workflow it is."""
    """For each residual pattern, what its last segment fixes about a file name: the literal text
    before its first wildcard and after its last. A name that does not start and end with them
    cannot match, and saying so is a string comparison rather than a glob walk -- which is the
    answer for nearly every file, since most are no manifest. Empty when nothing is fixed."""
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


__all__ = ["EcosystemRegistry"]
