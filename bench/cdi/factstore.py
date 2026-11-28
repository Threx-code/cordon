"""Facts of a unit, kept by what made them: the unit's digest, the reader that read it and that reader's version, and the version of the terms they are read against.

A head that changes one reader changes that reader's version, so only its facts are made again; every other reader's facts are found where they were kept. A change of the term version makes
all of them again, because a fact means what its terms mean. The store holds what the readers return and nothing else: where it is kept (a mapping here, a volume in a run) is the caller's.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Collection, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Reader:
    """One reader of a unit: its name, the version of its code, and the function that reads the unit's content."""

    name: str
    version: str
    read: Callable[[bytes], Any]


@dataclass(frozen=True)
class Rebuilt:
    """What one rebuild of the legitimate store at a head made: the head it is of, the terms, and how many facts were made against kept."""

    head: str
    term_version: str
    readers: dict[str, str]
    units: int
    made: int
    kept: int
    unread: tuple[str, ...]
    """The units whose content could not be read: they hold no facts, and are named here rather than read as having none."""


class FactStore:
    """`facts(digest, content)` is every reader's facts for one unit, made only where the kept ones do not match the key."""

    def __init__(
        self,
        readers: list[Reader],
        term_version: str,
        kept: MutableMapping[str, str] | None = None,
        head: str | None = None,
    ) -> None:
        self.readers = readers
        self.term_version = term_version
        self.head = head
        """The commit whose readers these are; None for a store not pinned to one."""
        self.kept: MutableMapping[str, str] = kept if kept is not None else {}
        self.made: list[tuple[str, str]] = []
        """Each (unit digest, reader name) made again in this store's life, in order."""

    @staticmethod
    def key(digest: str, reader: Reader, term_version: str) -> str:
        text = f"{digest}\0{reader.name}\0{reader.version}\0{term_version}"
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def facts(self, digest: str, content: bytes) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for reader in self.readers:
            key = self.key(digest, reader, self.term_version)
            found = self.kept.get(key)
            if found is None:
                found = json.dumps(reader.read(content), sort_keys=True)
                self.kept[key] = found
                self.made.append((digest, reader.name))
            out[reader.name] = json.loads(found)
        return out

    def rebuild(
        self,
        units: Mapping[str, bytes | None],
        readers: list[Reader],
        term_version: str,
        head: str,
    ) -> tuple[FactStore, Rebuilt]:
        """The store of the legitimate units at `head`: every unit read by `readers` under `term_version`, a fact made again only where the kept
        ones do not match its key. A unit whose content is None is unread: it is named in the record and holds no facts. This store is not changed."""
        store = FactStore(readers, term_version, self.kept, head)
        unread = []
        for digest in sorted(units):
            content = units[digest]
            if content is None:
                unread.append(digest)
            else:
                store.facts(digest, content)
        read = len(units) - len(unread)
        total = read * len(readers)
        record = Rebuilt(
            head=head,
            term_version=term_version,
            readers={reader.name: reader.version for reader in readers},
            units=len(units),
            made=len(store.made),
            kept=total - len(store.made),
            unread=tuple(unread),
        )
        return store, record

    def refuses(self, reads: Collection[str], term_version: str, head: str | None = None) -> str | None:
        """Why a candidate may not be measured against this store, or None.

        A candidate that reads a fact no reader of this store makes, or reads terms of another version than the store was
        made under, would be tested on facts that do not hold what it reads: it is refused, never read as absent."""
        new = sorted(set(reads) - {reader.name for reader in self.readers})
        if new:
            return f"the candidate reads facts this store does not have: {', '.join(new)}; rebuild the store at the candidate's head"
        if head is not None and self.head is not None and head != self.head:
            return f"the candidate is of head {head}, the store is of {self.head}; rebuild the store at the candidate's head"
        if term_version != self.term_version:
            return f"the candidate reads terms of version {term_version}, the store holds {self.term_version}; rebuild the store"
        return None


__all__ = ["FactStore", "Reader", "Rebuilt"]
