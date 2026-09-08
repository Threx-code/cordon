"""Ecosystem selection.

Matching a file to an ecosystem is done by path pattern, and the order matters
in one specific case: a pinned ``requirements.txt`` is both a manifest and a
lockfile, so it is registered under both and interpreted according to which
question is being asked.
"""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from cordon.core.walker import _path_matches
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

ECOSYSTEMS: tuple[Ecosystem, ...] = (
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

BY_ID = {eco.id: eco for eco in ECOSYSTEMS}


@lru_cache(maxsize=4096)
def manifest_ecosystem(path: str) -> str | None:
    """Which ecosystem's manifest this path is, if any."""
    for eco in ECOSYSTEMS:
        if any(_path_matches(path, pattern) for pattern in eco.manifest_globs):
            return eco.id
    return None


@lru_cache(maxsize=4096)
def lockfile_ecosystem(path: str) -> str | None:
    """Which ecosystem's lockfile this path is, if any."""
    for eco in ECOSYSTEMS:
        if any(_path_matches(path, pattern) for pattern in eco.lockfile_globs):
            return eco.id
    return None


def get(ecosystem_id: str) -> Ecosystem | None:
    return BY_ID.get(ecosystem_id)


def all_ecosystems() -> Sequence[Ecosystem]:
    return ECOSYSTEMS


__all__ = [
    "BY_ID",
    "ECOSYSTEMS",
    "all_ecosystems",
    "get",
    "lockfile_ecosystem",
    "manifest_ecosystem",
]
