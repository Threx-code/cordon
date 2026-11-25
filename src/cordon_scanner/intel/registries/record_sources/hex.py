"""Hex's registry record: `hex.pm/api/packages/<name>` (every release with its time, the owners and the retirements)."""

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

API = "https://hex.pm/api/packages"


class HexSource(RecordSource):
    ecosystem: ClassVar[str] = "hex"
    #: The package document names the owners; the account that published a release is on the release's own document.
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return (Document(f"{API}/{urllib.parse.quote(name, safe='')}"),)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = RegistryRecord._mapping(next(iter(documents.values()), None))
        retired = RegistryRecord._mapping(document.get("retirements"))
        releases = []
        for entry in document.get("releases") or ():
            when = RegistryRecord._when(
                entry.get("inserted_at") if isinstance(entry, dict) else None
            )
            number = entry.get("version") if isinstance(entry, dict) else None
            if when is not None and isinstance(number, str):
                releases.append(
                    Release(number, when, withdrawn="retired" if number in retired else "")
                )
        owners = tuple(
            sorted(
                str(o["username"])
                for o in document.get("owners") or ()
                if isinstance(o, dict) and o.get("username")
            )
        )
        meta = RegistryRecord._mapping(document.get("meta"))
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            created=RegistryRecord._when(document.get("inserted_at")),
            maintainers=len(owners),
            owners=owners,
            has_repository=bool(meta.get("links")),
            has_readme=False,
            description_length=len(str(meta.get("description") or "")),
            has_author=bool(meta.get("maintainers")),
            manifest_known=False,
        )
