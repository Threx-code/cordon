"""The registry record of a container image on Docker Hub: `hub.docker.com/v2/repositories/<namespace>/<name>` (when the repository was
registered, its owner) and its tags with `tag_last_pushed` and the account that last pushed each (`.../tags`, a page of 100 at a time).
A tag is a release; it moves when it is pushed again, so its time is the last push. An image from another registry (ghcr.io, quay.io,
a cloud's) is not on Hub and has no document here: its record is the OCI registry's (see the limits in the audit)."""

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

API = "https://hub.docker.com/v2/repositories"
HUB_HOSTS = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")
PART = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
NEXT = re.compile(
    re.escape(API) + r"/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*/tags\?page=\d+&page_size=\d+"
)
PAGES = 10


class ImageSource(RecordSource):
    ecosystem: ClassVar[str] = "image"
    publisher_kind: ClassVar[PublisherKind] = "account"

    @staticmethod
    def repository(name: str) -> tuple[str, str] | None:
        """`(namespace, repository)` on Hub, or None for a name on another registry or not a name."""
        for host in HUB_HOSTS:
            name = name.removeprefix(host)
        parts = name.split("/")
        if len(parts) == 1:
            parts = ["library", *parts]
        if len(parts) != 2 or not all(PART.fullmatch(p) for p in parts) or ".." in name:
            return None
        return parts[0], parts[1]

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        found = self.repository(name)
        if found is None or (version and not TAG.fullmatch(version)):
            return ()
        base = f"{API}/{found[0]}/{found[1]}"
        return (Document(f"{base}/tags?page=1&page_size=100"), Document(base, required=False))

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        more = []
        for url, document in documents.items():
            link = RegistryRecord._mapping(document).get("next")
            if (
                "/tags?" in url
                and isinstance(link, str)
                and NEXT.fullmatch(link)
                and len(documents) < PAGES + 1
            ):
                more.append(Document(link))
        return tuple(more)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        repository: dict[str, Any] = {}
        releases = []
        for url, document in documents.items():
            doc = RegistryRecord._mapping(document)
            if "/tags?" not in url:
                repository = doc
                continue
            for entry in doc.get("results") or ():
                when = RegistryRecord._when(
                    entry.get("tag_last_pushed") if isinstance(entry, dict) else None
                )
                tag = entry.get("name") if isinstance(entry, dict) else None
                if when is not None and isinstance(tag, str):
                    releases.append(
                        Release(
                            tag,
                            when,
                            str(entry.get("last_updater_username") or ""),
                            ""
                            if entry.get("tag_status", "active") == "active"
                            else str(entry.get("tag_status")),
                        )
                    )
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            created=RegistryRecord._when(repository.get("date_registered")),
            manifest_known=False,
        )
