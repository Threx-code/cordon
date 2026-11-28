"""The Go module proxy's record: `proxy.golang.org/<module>/@v/list` (every version), `<module>/@v/<version>.info` for the newest ones
(`Time`), and the newest version's `go.mod` for its `retract` directives (a retracted version is the module author's own withdrawal).
A module with more versions than a record reads times for keeps the older ones without a time of their own. The proxy names no publisher."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.registries.record_sources.base import (
    Document,
    PublisherKind,
    RecordBuilder,
    RecordSource,
    Release,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.intel.registries.registry_record import RegistryRecord


API = "https://proxy.golang.org"
PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~/-]*")
VERSION = re.compile(r"v[0-9][0-9A-Za-z.+_-]*")
INFOS = 62


class GomodSource(RecordSource):
    ecosystem: ClassVar[str] = "gomod"
    publisher_kind: ClassVar[PublisherKind] = "none"

    @staticmethod
    def escaped(text: str) -> str:
        """The proxy's case encoding: each upper-case letter is `!` and its lower-case form."""
        return "".join(f"!{c.lower()}" if c.isupper() else c for c in text)

    @staticmethod
    def sort_key(version: str) -> tuple[Any, ...]:
        core = re.split(r"[-+]", version.removeprefix("v"), maxsplit=1)
        numbers = tuple(int(p) if p.isdigit() else 0 for p in core[0].split("."))
        return (*numbers, "-" not in version)

    def root(self, name: str) -> str | None:
        if not PATH.fullmatch(name) or ".." in name or "//" in name or len(name) > 214:
            return None
        return f"{API}/{self.escaped(name)}/@v"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        root = self.root(name)
        if root is None or (version and not VERSION.fullmatch(version)):
            return ()
        return (Document(f"{root}/list", kind="text"),)

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        root = self.root(name)
        listing = next(iter(documents.values()), None)
        if root is None or not isinstance(listing, str):
            return ()
        versions = sorted((v for v in listing.split() if VERSION.fullmatch(v)), key=self.sort_key)
        wanted = [v for v in versions[-INFOS:] if v != version]
        if version in versions:
            wanted.append(version)
        docs = [Document(f"{root}/{self.escaped(v)}.info", required=False) for v in wanted]
        if versions:
            docs.append(
                Document(f"{root}/{self.escaped(versions[-1])}.mod", kind="text", required=False)
            )
        return tuple(docs)

    @classmethod
    def retracted(cls, mod: Any) -> list[tuple[tuple[Any, ...], tuple[Any, ...]]]:
        """The version ranges a `go.mod` retracts, as (low, high) sort keys; a single version is a range of one.
        Read line by line, with plain splits: a `retract (` block runs to its closing `)`."""
        if not isinstance(mod, str):
            return []
        found = []
        inside = False
        for raw in mod.splitlines():
            line = raw.split("//", 1)[0].strip()
            if inside:
                if line.startswith(")"):
                    inside = False
                    continue
                text = line
            elif line.startswith("retract"):
                text = line[len("retract") :].strip()
                if text.startswith("("):
                    inside = text.strip("( ") == ""
                    text = text.strip("( )") if not inside else ""
            else:
                continue
            tokens = [
                t
                for t in text.replace("[", " ").replace("]", " ").replace(",", " ").split()
                if t.startswith("v") and t[1:2].isdigit()
            ]
            if tokens:
                found.append((cls.sort_key(tokens[0]), cls.sort_key(tokens[-1])))
        return found

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        mod = next((d for u, d in documents.items() if u.endswith(".mod")), None)
        ranges = self.retracted(mod)
        releases = []
        for url, document in documents.items():
            if not url.endswith(".info") or not isinstance(document, dict):
                continue
            number = document.get("Version")
            when = RegistryRecord._when(document.get("Time"))
            if isinstance(number, str) and when is not None:
                key = self.sort_key(number)
                gone = "retracted" if any(low <= key <= high for low, high in ranges) else ""
                releases.append(Release(number, when, withdrawn=gone))
        return RecordBuilder.from_history(self, name, version, releases, manifest_known=False)
