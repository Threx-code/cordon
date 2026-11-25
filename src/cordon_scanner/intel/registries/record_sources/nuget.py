"""NuGet's registry record: the registration index `api.nuget.org/v3/registration5-gz-semver2/<id>/index.json` (pages of every version
with its `published` time and `listed`; a page that is not inline is a document of its own). A package with no registration page is
unknown. The registry names the package's owners only through its search service, which a record does not need: no publisher is named."""

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

API = "https://api.nuget.org/v3/registration5-gz-semver2"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
PAGE = re.compile(
    re.escape(API)
    + r"/[a-z0-9][a-z0-9_.-]*/(?:page/[0-9A-Za-z.+-]+/[0-9A-Za-z.+-]+\.json|index\.json#page/[0-9A-Za-z.+-]+/[0-9A-Za-z.+-]+)"
)
#: A listed package published before 1970 is NuGet's sentinel for "unlisted", not a date.
SENTINEL_YEAR = 1900


class NugetSource(RecordSource):
    ecosystem: ClassVar[str] = "nuget"
    publisher_kind: ClassVar[PublisherKind] = "none"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not NAME.fullmatch(name) or ".." in name or len(name) > 100:
            return ()
        return (Document(f"{API}/{name.lower()}/index.json"),)

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        index = RegistryRecord._mapping(next(iter(documents.values()), None))
        pages = []
        for page in index.get("items") or ():
            if isinstance(page, dict) and "items" not in page:
                url = page.get("@id")
                if (
                    isinstance(url, str)
                    and url.startswith(f"{API}/{name.lower()}/")
                    and "#" not in url
                ):
                    pages.append(Document(url))
        return tuple(pages)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        entries: list[dict[str, Any]] = []
        for document in documents.values():
            doc = RegistryRecord._mapping(document)
            for page in doc.get("items") or ():
                inline = page.get("items") if isinstance(page, dict) else None
                for item in (
                    inline
                    if isinstance(inline, list)
                    else ([page] if isinstance(page, dict) else ())
                ):
                    entry = RegistryRecord._mapping(
                        item.get("catalogEntry") if isinstance(item, dict) else None
                    )
                    if entry:
                        entries.append(entry)
        releases = []
        this: dict[str, Any] = {}
        for entry in entries:
            when = RegistryRecord._when(entry.get("published"))
            number = entry.get("version")
            if not isinstance(number, str):
                continue
            if number == version:
                this = entry
            if when is None or when.year <= SENTINEL_YEAR:
                continue
            releases.append(
                Release(
                    number, when, withdrawn="" if entry.get("listed") is not False else "unlisted"
                )
            )
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            has_repository=bool(this.get("projectUrl")),
            description_length=len(str(this.get("description") or "")),
            has_author=bool(this.get("authors")),
        )
