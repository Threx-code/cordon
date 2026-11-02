"""What one archive walk has opened and met, moved out of `sources/archive.py` (its module bound) with
the import-library mark it now carries (notes/75)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NestedWalk:
    """What one `walk_archive` has opened, and what it met past the depth limit.

    A package that ships its own earlier `npm pack` tarballs carries each one at several depths;
    the copy past the limit holds the same bytes as one opened higher up, so its contents were
    examined. Only an archive no copy of which was opened is reported as unexamined."""

    opened: set[bytes] = field(default_factory=set)
    """sha256 of every nested archive opened and walked."""
    too_deep: list[tuple[bytes, tuple[str, str, str]]] = field(default_factory=list)
    """(sha256, rejection) for every nested archive met past the limit."""
    import_library: set[str] | None = None
    """Where given, the path of every member of an `ar` archive that is an import library whole
    (`ImportLibrary`, notes/75): the polyglot check does not read their DLL names as file names."""


__all__ = ["NestedWalk"]
