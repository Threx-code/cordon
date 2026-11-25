"""crates.io's registry record: `crates.io/api/v1/crates/<name>` (every version with its time, its publisher and `yanked`) and
`.../<name>/owners` (the crate's owners)."""

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

API = "https://crates.io/api/v1/crates"


class CargoSource(RecordSource):
    ecosystem: ClassVar[str] = "cargo"
    publisher_kind: ClassVar[PublisherKind] = "account"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        quoted = urllib.parse.quote(name, safe="")
        return (Document(f"{API}/{quoted}"), Document(f"{API}/{quoted}/owners", required=False))

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = next(iter(documents.values()), None)
        owners_document = list(documents.values())[1] if len(documents) > 1 else None
        crate = RegistryRecord._mapping(
            document.get("crate") if isinstance(document, dict) else None
        )
        listed = document.get("versions") if isinstance(document, dict) else None
        releases: list[Release] = []
        this: dict[str, Any] = {}
        for entry in listed if isinstance(listed, list) else ():
            when = RegistryRecord._when(
                entry.get("created_at") if isinstance(entry, dict) else None
            )
            number = entry.get("num") if isinstance(entry, dict) else None
            if when is None or not isinstance(number, str):
                continue
            by = RegistryRecord._mapping(entry.get("published_by"))
            releases.append(
                Release(
                    number,
                    when,
                    str(by.get("login") or ""),
                    "yanked" if entry.get("yanked") is True else "",
                )
            )
            if number == version:
                this = entry
        users = RegistryRecord._mapping(owners_document).get("users") if owners_document else None
        owners = (
            tuple(sorted(str(u["login"]) for u in users if isinstance(u, dict) and u.get("login")))
            if isinstance(users, list)
            else ()
        )
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            created=RegistryRecord._when(crate.get("created_at")),
            maintainers=len(owners),
            owners=owners,
            has_repository=bool(this.get("repository") or crate.get("repository")),
            has_readme=bool(this.get("readme_path")),
            description_length=len(str(this.get("description") or "")),
            has_author=False,
        )
