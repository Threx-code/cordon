"""Editor extensions' registry record: Open VSX's query of every version of one extension.

`/api/-/query?extensionId=<publisher.name>&includeAllVersions=true` answers each version with its publish time and the
account that published it (`publishedBy`: a GitHub or Eclipse login), and whether the extension is deprecated, in one
document, paged by `offset` and `size`. The Marketplace is not read: its terms allow only Microsoft's own products
to use it (see the firewall's Open VSX adapter)."""

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


class OpenVsxSource(RecordSource):
    ecosystem: ClassVar[str] = "vscode"
    #: The account that published each version (`publishedBy.loginName`), as the registry names it.
    publisher_kind: ClassVar[PublisherKind] = "account"
    API: ClassVar[str] = "https://open-vsx.org/api/-/query"
    #: Versions asked per page; the query's own maximum page.
    PAGE: ClassVar[int] = 100
    MAX_PAGES: ClassVar[int] = 6

    @staticmethod
    def ident(name: str) -> str | None:
        from cordon_scanner.ecosystems.editors.vscode import ExtensionId

        parsed = ExtensionId.parse(name)
        return parsed[0] if parsed and not parsed[1] else None

    def page(self, ident: str, offset: int) -> Document:
        query = urllib.parse.urlencode(
            {
                "extensionId": ident,
                "includeAllVersions": "true",
                "offset": offset,
                "size": self.PAGE,
            }
        )
        return Document(f"{self.API}?{query}")

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        ident = self.ident(name)
        return (self.page(ident, 0),) if ident else ()

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        """The next page while the query says there are more versions than read so far."""
        ident = self.ident(name)
        if ident is None:
            return ()
        read = sum(
            len(d.get("extensions") or []) for d in documents.values() if isinstance(d, dict)
        )
        sizes = [
            d["totalSize"]
            for d in documents.values()
            if isinstance(d, dict) and isinstance(d.get("totalSize"), int)
        ]
        total: int = max(sizes, default=0)
        offset = read
        if read >= total or offset >= self.PAGE * self.MAX_PAGES:
            return ()
        return (self.page(ident, offset),)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        ident = self.ident(name)
        if ident is None:
            return None
        releases: list[Release] = []
        deprecated = False
        repository = False
        for document in documents.values():
            for entry in (document.get("extensions") or []) if isinstance(document, dict) else ():
                if (
                    not isinstance(entry, dict)
                    or f"{entry.get('namespace')}.{entry.get('name')}".lower() != ident
                ):
                    continue
                stamp = self.when(entry.get("timestamp"))
                release = entry.get("version")
                if stamp is None or not isinstance(release, str):
                    continue
                published = entry.get("publishedBy")
                login = published.get("loginName") if isinstance(published, dict) else ""
                releases.append(Release(release, stamp, str(login or "").lower()))
                deprecated = deprecated or entry.get("deprecated") is True
                repository = repository or bool(entry.get("repository"))
        if deprecated:
            releases = [
                Release(r.version, r.published, r.publisher, "deprecated") for r in releases
            ]
        return RecordBuilder.from_history(self, ident, version, releases, has_repository=repository)

    @staticmethod
    def when(text: Any) -> Any:
        from cordon_scanner.intel.registries.record_sources.git_hosted import GitHub

        return GitHub.when(text)


__all__ = ["OpenVsxSource"]
