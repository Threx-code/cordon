"""Facts of a unit, kept by what made them: the unit's digest, the reader that read it and that reader's version, and the version of the terms they are read against.

A head that changes one reader changes that reader's version, so only its facts are made again; every other reader's facts are found where they were kept. A change of the term version makes
all of them again, because a fact means what its terms mean. The store holds what the readers return and nothing else: where it is kept (a mapping here, a volume in a run) is the caller's.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Reader:
    """One reader of a unit: its name, the version of its code, and the function that reads the unit's content."""

    name: str
    version: str
    read: Callable[[bytes], Any]


class FactStore:
    """`facts(digest, content)` is every reader's facts for one unit, made only where the kept ones do not match the key."""

    def __init__(
        self,
        readers: list[Reader],
        term_version: str,
        kept: MutableMapping[str, str] | None = None,
    ) -> None:
        self.readers = readers
        self.term_version = term_version
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


__all__ = ["FactStore", "Reader"]
