"""Ecosystem selection.

Matching a file to an ecosystem is done by path pattern, and the order matters
in one specific case: a pinned ``requirements.txt`` is both a manifest and a
lockfile, so it is registered under both and interpreted according to which
question is being asked.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING, ClassVar

from cordon.core.walker import PathGlob
from cordon.ecosystems.base import Ecosystem
from cordon.ecosystems.npm import NpmEcosystem
from cordon.ecosystems.others import (
    CargoEcosystem,
    CocoaPodsEcosystem,
    ComposerEcosystem,
    GoEcosystem,
    GradleEcosystem,
    MavenEcosystem,
    NuGetEcosystem,
    PubEcosystem,
    RubyGemsEcosystem,
)
from cordon.ecosystems.pypi import PypiEcosystem

if TYPE_CHECKING:
    from collections.abc import Sequence


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
    )

    BY_ID: ClassVar[dict[str, Ecosystem]] = {eco.id: eco for eco in ECOSYSTEMS}

    @staticmethod
    @lru_cache(maxsize=4096)
    def manifest_ecosystem(path: str) -> str | None:
        """Which ecosystem's manifest this path is, if any."""
        for eco in EcosystemRegistry.ECOSYSTEMS:
            if any(PathGlob.matches(path, pattern) for pattern in eco.manifest_globs):
                return eco.id
        return None

    @staticmethod
    @lru_cache(maxsize=4096)
    def lockfile_ecosystem(path: str) -> str | None:
        """Which ecosystem's lockfile this path is, if any."""
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
