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
    "GitTreeSource": ("cordon_scanner.sources.git", "GitTreeSource"),
}

if TYPE_CHECKING:
    from cordon_scanner.sources.archive import ArchiveReader
    from cordon_scanner.sources.git import GitRepository, GitTreeSource


def __getattr__(name: str) -> object:
    """The implementation of one of `ROLES`, imported on first use."""
    try:
        module, attribute = ROLES[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return getattr(importlib.import_module(module), attribute)


__all__ = ["ROLES", "ArchiveReader", "GitRepository", "GitTreeSource"]
