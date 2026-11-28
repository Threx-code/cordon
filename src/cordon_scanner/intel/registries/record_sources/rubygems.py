"""RubyGems' registry record: `rubygems.org/api/v1/versions/<name>.json` (every version with its push time; a platform gem
is one release per platform, the earliest counts), `.../gems/<name>.json` (the newest release's manifest facts) and
`.../gems/<name>/owners.json`. The registry does not say which account pushed a release: the owners are the gem's, and a
yanked version is simply not listed."""

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

API = "https://rubygems.org/api/v1"


class RubygemsSource(RecordSource):
    ecosystem: ClassVar[str] = "rubygems"
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        quoted = urllib.parse.quote(name, safe="")
        return (
            Document(f"{API}/versions/{quoted}.json", array=True),
            Document(f"{API}/gems/{quoted}.json", required=False),
            Document(f"{API}/gems/{quoted}/owners.json", required=False, array=True),
        )

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        versions_doc, gem_doc, owners_doc = ([*documents.values(), None, None, None])[:3]
        earliest: dict[str, Any] = {}
        for entry in versions_doc if isinstance(versions_doc, list) else ():
            when = RegistryRecord._when(
                entry.get("created_at") if isinstance(entry, dict) else None
            )
            number = entry.get("number") if isinstance(entry, dict) else None
            if (
                when is not None
                and isinstance(number, str)
                and (number not in earliest or when < earliest[number])
            ):
                earliest[number] = when
        owners = tuple(
            sorted(
                str(o["handle"])
                for o in (owners_doc if isinstance(owners_doc, list) else ())
                if isinstance(o, dict) and o.get("handle")
            )
        )
        gem = RegistryRecord._mapping(gem_doc)
        current = str(gem.get("version") or "") == version
        return RecordBuilder.from_history(
            self,
            name,
            version,
            [Release(number, when) for number, when in earliest.items()],
            maintainers=len(owners),
            owners=owners,
            has_repository=current and bool(gem.get("source_code_uri") or gem.get("homepage_uri")),
            has_readme=current and len(str(gem.get("info") or "").strip()) > 40,
            description_length=len(str(gem.get("info") or "")) if current else 0,
            has_author=current and bool(gem.get("authors")),
            manifest_known=current,
        )
