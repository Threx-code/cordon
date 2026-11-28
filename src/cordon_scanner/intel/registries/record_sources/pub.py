"""pub.dev's registry record: `pub.dev/api/packages/<name>` (every version with its time and `retracted`) and
`.../<name>/publisher` (the verified publisher that owns the package, where it has one)."""

from __future__ import annotations

import urllib.parse
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

API = "https://pub.dev/api/packages"


class PubSource(RecordSource):
    ecosystem: ClassVar[str] = "pub"
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        quoted = urllib.parse.quote(name, safe="")
        return (Document(f"{API}/{quoted}"), Document(f"{API}/{quoted}/publisher", required=False))

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document, publisher_doc = ([*documents.values(), None, None])[:2]
        publisher = str(RegistryRecord._mapping(publisher_doc).get("publisherId") or "")
        releases = []
        this: dict[str, Any] = {}
        listed = RegistryRecord._mapping(document).get("versions")
        for entry in listed if isinstance(listed, list) else ():
            when = RegistryRecord._when(entry.get("published") if isinstance(entry, dict) else None)
            number = entry.get("version") if isinstance(entry, dict) else None
            if when is None or not isinstance(number, str):
                continue
            releases.append(
                Release(
                    number, when, publisher, "retracted" if entry.get("retracted") is True else ""
                )
            )
            if number == version:
                this = RegistryRecord._mapping(entry.get("pubspec"))
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            has_repository=bool(this.get("repository") or this.get("homepage")),
            description_length=len(str(this.get("description") or "")),
            has_author=bool(this.get("author") or this.get("authors")),
        )
