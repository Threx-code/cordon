"""Maven Central's registry record, for `group:artifact` (Maven, and Gradle, which resolves from it): the Central search index
(`search.maven.org/solrsearch/select`, one document per version with its `timestamp`), a page of 200 at a time. Central names no
account that published a release (a namespace is verified once, not per release), and it removes nothing."""

from __future__ import annotations

import re
import urllib.parse
from datetime import UTC, datetime
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


API = "https://search.maven.org/solrsearch/select"
PART = re.compile(r"[A-Za-z0-9_.-]+")
PAGE = 200
PAGES = 20


class MavenSource(RecordSource):
    ecosystem: ClassVar[str] = "maven"
    publisher_kind: ClassVar[PublisherKind] = "none"

    @staticmethod
    def coordinate(name: str) -> tuple[str, str] | None:
        parts = name.split(":")
        if (
            len(parts) != 2
            or not all(PART.fullmatch(p) for p in parts)
            or ".." in name
            or len(name) > 214
        ):
            return None
        return parts[0], parts[1]

    def page(self, name: str, start: int) -> Document:
        group, artifact = self.coordinate(name) or ("", "")
        query = urllib.parse.quote(f'g:"{group}" AND a:"{artifact}"', safe="")
        return Document(f"{API}?q={query}&core=gav&rows={PAGE}&start={start}&wt=json")

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        return (self.page(name, 0),) if self.coordinate(name) else ()

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        if not self.coordinate(name):
            return ()
        found = RegistryRecord._mapping(
            RegistryRecord._mapping(next(iter(documents.values()), None)).get("response")
        ).get("numFound")
        total = found if isinstance(found, int) else 0
        return tuple(
            self.page(name, start) for start in range(PAGE, min(total, PAGE * PAGES), PAGE)
        )

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        releases = []
        for document in documents.values():
            response = RegistryRecord._mapping(RegistryRecord._mapping(document).get("response"))
            for entry in response.get("docs") or ():
                number = entry.get("v") if isinstance(entry, dict) else None
                stamp = entry.get("timestamp") if isinstance(entry, dict) else None
                if isinstance(number, str) and isinstance(stamp, int):
                    releases.append(
                        Release(
                            number, datetime.fromtimestamp(stamp / 1000, UTC).replace(tzinfo=None)
                        )
                    )
        return RecordBuilder.from_history(self, name, version, releases, manifest_known=False)


class GradleSource(MavenSource):
    """Gradle resolves `group:artifact` from Maven Central: the same documents, under its own ecosystem."""

    ecosystem: ClassVar[str] = "gradle"
