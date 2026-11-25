"""conda's registry record: `api.anaconda.org/package/<channel>/<name>` (every file with its upload time and the channel that owns the
package; a version is as old as its earliest file). A package is named `name` (on conda-forge) or `channel/name`."""

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

API = "https://api.anaconda.org/package"
PART = re.compile(r"[a-z0-9][a-z0-9_.-]*")
DEFAULT_CHANNEL = "conda-forge"


class CondaSource(RecordSource):
    ecosystem: ClassVar[str] = "conda"
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    @staticmethod
    def address(name: str) -> tuple[str, str] | None:
        channel, _, package = name.rpartition("/") if "/" in name else (DEFAULT_CHANNEL, "", name)
        if (
            "/" in channel
            or ".." in name
            or not PART.fullmatch(channel)
            or not PART.fullmatch(package)
        ):
            return None
        return channel, package

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        address = self.address(name)
        if address is None or len(name) > 214:
            return ()
        return (Document(f"{API}/{address[0]}/{address[1]}"),)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = RegistryRecord._mapping(next(iter(documents.values()), None))
        owner = str(RegistryRecord._mapping(document.get("owner")).get("login") or "")
        earliest: dict[str, Any] = {}
        for entry in document.get("files") or ():
            when = RegistryRecord._when(
                entry.get("upload_time") if isinstance(entry, dict) else None
            )
            number = entry.get("version") if isinstance(entry, dict) else None
            if (
                when is not None
                and isinstance(number, str)
                and (number not in earliest or when < earliest[number])
            ):
                earliest[number] = when
        current = str(document.get("latest_version") or "") == version
        return RecordBuilder.from_history(
            self,
            name,
            version,
            [Release(number, when, owner) for number, when in earliest.items()],
            has_repository=current and bool(document.get("dev_url") or document.get("home")),
            description_length=len(str(document.get("summary") or "")) if current else 0,
            manifest_known=current,
        )
