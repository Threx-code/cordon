"""Packagist's registry record: `repo.packagist.org/p2/<vendor>/<package>.json` (Composer's minified metadata: every version with its
`time`, newest first, each entry giving only what differs from the one before it; `abandoned` where the maintainers marked it)."""

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

API = "https://repo.packagist.org/p2"
#: Composer's own rule for a package name: lower-case `vendor/package`, words joined by `.`, `-` or `_`.
NAME = re.compile(r"[a-z0-9]++(?:[_.-][a-z0-9]++)*+/[a-z0-9]++(?:(?:[_.]|-{1,2})[a-z0-9]++)*+")


class ComposerSource(RecordSource):
    ecosystem: ClassVar[str] = "composer"
    #: Packagist's metadata names no account that published a release.
    publisher_kind: ClassVar[PublisherKind] = "none"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not NAME.fullmatch(name) or len(name) > 214:
            return ()
        return (Document(f"{API}/{name}.json"),)

    @staticmethod
    def expand(versions: list[Any]) -> list[dict[str, Any]]:
        """Composer's minified list made whole: each entry is the one before it with its own keys applied (`__unset` removes one)."""
        out: list[dict[str, Any]] = []
        current: dict[str, Any] = {}
        for entry in versions:
            if not isinstance(entry, dict):
                continue
            current = dict(current)
            for key, value in entry.items():
                if value == "__unset":
                    current.pop(key, None)
                else:
                    current[key] = value
            out.append(current)
        return out

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = RegistryRecord._mapping(next(iter(documents.values()), None))
        listed = RegistryRecord._mapping(document.get("packages")).get(name)
        releases: list[Release] = []
        this: dict[str, Any] = {}
        for entry in self.expand(listed) if isinstance(listed, list) else ():
            when = RegistryRecord._when(entry.get("time"))
            number = entry.get("version")
            if when is None or not isinstance(number, str):
                continue
            releases.append(
                Release(number, when, withdrawn="abandoned" if entry.get("abandoned") else "")
            )
            if number == version:
                this = entry
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            has_repository=bool(this.get("source") or this.get("homepage")),
            has_readme=False,
            description_length=len(str(this.get("description") or "")),
            has_author=bool(this.get("authors")),
        )
