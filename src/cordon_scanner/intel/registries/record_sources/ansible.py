"""Ansible Galaxy's registry record: `galaxy.ansible.com/api/v3/.../collections/index/<namespace>/<name>/versions/` (every
version with its time, a page at a time) and the collection's own document (`deprecated`). A collection is named `namespace.name`."""

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

HOST = "https://galaxy.ansible.com"
INDEX = "/api/v3/plugin/ansible/content/published/collections/index"
NAME = re.compile(r"([a-z][a-z0-9_]*)\.([a-z][a-z0-9_]*)")
#: A path the `links.next` of a page may name: this registry's own, and nothing else.
NEXT = re.compile(
    re.escape(INDEX) + r"/[a-z][a-z0-9_]*/[a-z][a-z0-9_]*/versions/\?[A-Za-z0-9=&_.-]*"
)


class AnsibleSource(RecordSource):
    ecosystem: ClassVar[str] = "ansible"
    #: Galaxy names the collection's namespace, not the account that uploaded a version.
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        parts = NAME.fullmatch(name)
        if parts is None:
            return ()
        namespace, collection = parts.groups()
        base = f"{HOST}{INDEX}/{namespace}/{collection}"
        return (
            Document(f"{base}/versions/?limit=100"),
            Document(f"{base}/", required=False),
        )

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        more: list[Document] = []
        for url, document in documents.items():
            link = RegistryRecord._mapping(RegistryRecord._mapping(document).get("links")).get(
                "next"
            )
            if "/versions/" in url and isinstance(link, str) and NEXT.fullmatch(link):
                more.append(Document(f"{HOST}{link}"))
        return tuple(more)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        namespace = name.split(".", 1)[0]
        listing, collection = ([*documents.values(), None, None])[:2]
        releases = []
        deprecated = bool(RegistryRecord._mapping(collection).get("deprecated"))
        for url, document in documents.items():
            if "/versions/" not in url:
                continue
            for entry in RegistryRecord._mapping(document).get("data") or ():
                when = RegistryRecord._when(
                    entry.get("created_at") if isinstance(entry, dict) else None
                )
                number = entry.get("version") if isinstance(entry, dict) else None
                if when is not None and isinstance(number, str):
                    releases.append(
                        Release(number, when, namespace, "deprecated" if deprecated else "")
                    )
        del listing
        return RecordBuilder.from_history(self, name, version, releases, manifest_known=False)
