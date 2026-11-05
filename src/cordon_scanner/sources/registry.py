"""Where the engine finds the sources it reads a scan's files from.

The engine imports this layer only through its ports: `base`, the protocols, and this
module, the registry of what implements them. A detector, ecosystem or source the engine
does not name is found through `engine.registry` instead."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

#: What the engine uses of this layer by name, and the module that provides each: the one place
#: that knows, so the layer's modules can move without the engine changing. Each is imported
#: when it is first asked for (PEP 562), as the engine's own imports were.
ROLES: dict[str, tuple[str, str]] = {
    "ArchiveReader": ("cordon_scanner.sources.archive", "ArchiveReader"),
    "GitRepository": ("cordon_scanner.sources.git", "GitRepository"),
}

if TYPE_CHECKING:
    from cordon_scanner.sources import archive as _sources_archive
    from cordon_scanner.sources import git as _sources_git
    from cordon_scanner.sources.base import ArchiveReading, GitRepositories

    # Each implementation, as the engine sees it: by its protocol (the type checker proves the
    # implementation conforms) or, for a plain value, by the value's type.
    ArchiveReader: ArchiveReading = _sources_archive.ArchiveReader
    GitRepository: GitRepositories = _sources_git.GitRepository


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


__all__ = ["ROLES", "ArchiveReader", "GitRepository"]
