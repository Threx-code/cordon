"""A value's canonical digest: the same facts always hash the same, whatever order a set or a
mapping was built in. What the scan cache keys a scan's context by (`engine/cache.py`), here
on its own so the cache holds the store and this holds only the hashing."""

from __future__ import annotations

import hashlib
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


class Canonical:
    """Feeding a value into a digest canonically."""

    @staticmethod
    def feed(digest: Any, value: Any) -> None:
        """Feed `value` into `digest` canonically: sets sorted, dataclasses by field.

        Iterative, not recursive: a context carries parsed manifests, and their nesting is the
        scanned package's to choose. A value of a type this does not know is fed by its type and
        `repr`, which can only make two equal contexts hash apart -- a cache miss, never a
        wrong hit."""
        stack: list[Any] = [value]
        while stack:
            item = stack.pop()
            feeder = next((f for kind, f in FEEDERS.items() if isinstance(item, kind)), None)
            if feeder is not None:
                feeder(digest, item, stack)
            elif is_dataclass(item) and not isinstance(item, type):
                names = [f.name for f in fields(item)]
                digest.update(f"obj:{type(item).__qualname__}:{len(names)}:".encode())
                for name in reversed(names):
                    stack.append(getattr(item, name))
                    stack.append(name)
            else:
                digest.update(f"other:{type(item).__qualname__}:{item!r};".encode())

    @staticmethod
    def text(value: Any) -> str:
        """One set member or mapping key as a string to sort and hash by."""
        if isinstance(value, (str, int, float, bool, bytes)) or value is None:
            return f"{type(value).__name__}:{value!r}"
        digest = hashlib.sha256()
        Canonical.feed(digest, value)
        return digest.hexdigest()


class Feeders:
    """How `Canonical.feed` writes each kind of value into a digest. A value is fed as the first
    kind in FEEDERS it is an instance of, so a subclass (an IntEnum, a PosixPath, a defaultdict)
    is fed as it always was: scalars, then enums, paths, sets, sequences, mappings."""

    @staticmethod
    def scalar(digest: Any, item: Any, stack: list[Any]) -> None:
        digest.update(f"{type(item).__name__}:{item!r};".encode())

    @staticmethod
    def enum(digest: Any, item: Any, stack: list[Any]) -> None:
        digest.update(f"enum:{type(item).__name__}.{item.name};".encode())

    @staticmethod
    def path(digest: Any, item: Any, stack: list[Any]) -> None:
        digest.update(f"path:{item.as_posix()};".encode())

    @staticmethod
    def members(digest: Any, item: Any, stack: list[Any]) -> None:
        members = sorted(Canonical.text(member) for member in item)
        digest.update(f"set:{len(members)}:".encode())
        for member in members:
            digest.update(member.encode("utf-8") + b"\0")

    @staticmethod
    def sequence(digest: Any, item: Any, stack: list[Any]) -> None:
        digest.update(f"seq:{len(item)}:".encode())
        stack.extend(reversed(item))

    @staticmethod
    def mapping(digest: Any, item: Any, stack: list[Any]) -> None:
        ordered = sorted(item.items(), key=lambda pair: Canonical.text(pair[0]))
        digest.update(f"map:{len(ordered)}:".encode())
        for key, member in reversed(ordered):
            stack.append(member)
            stack.append(key)


#: The kinds `_feed` knows, each with its feeder, in the order they are tried: the scalars come
#: before Enum, so an IntEnum is fed as its int, as it always was.
FEEDERS: dict[type, Callable[[Any, Any, list[Any]], None]] = {
    type(None): Feeders.scalar,
    bool: Feeders.scalar,
    int: Feeders.scalar,
    float: Feeders.scalar,
    str: Feeders.scalar,
    bytes: Feeders.scalar,
    Enum: Feeders.enum,
    Path: Feeders.path,
    frozenset: Feeders.members,
    set: Feeders.members,
    list: Feeders.sequence,
    tuple: Feeders.sequence,
    dict: Feeders.mapping,
}


__all__ = ["FEEDERS", "Canonical", "Feeders"]
