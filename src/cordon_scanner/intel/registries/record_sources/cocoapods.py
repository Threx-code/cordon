"""CocoaPods trunk's registry record: `trunk.cocoapods.org/api/v1/pods/<name>` (every version with its time, and the pod's owners)."""

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

API = "https://trunk.cocoapods.org/api/v1/pods"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_+.-]*")


class CocoapodsSource(RecordSource):
    ecosystem: ClassVar[str] = "cocoapods"
    #: Trunk names the pod's owners, not the one who pushed a version.
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not NAME.fullmatch(name) or ".." in name or len(name) > 214:
            return ()
        return (Document(f"{API}/{urllib.parse.quote(name, safe='')}"),)

    @staticmethod
    def when(value: Any) -> datetime | None:
        """Trunk writes `2015-01-09 22:10:57 UTC`."""
        if not isinstance(value, str):
            return None
        try:
            return (
                datetime.strptime(value.removesuffix(" UTC"), "%Y-%m-%d %H:%M:%S")
                .replace(tzinfo=UTC)
                .replace(tzinfo=None)
            )
        except ValueError:
            return None

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = RegistryRecord._mapping(next(iter(documents.values()), None))
        releases = []
        for entry in document.get("versions") or ():
            when = self.when(entry.get("created_at") if isinstance(entry, dict) else None)
            number = entry.get("name") if isinstance(entry, dict) else None
            if when is not None and isinstance(number, str):
                releases.append(Release(number, when))
        owners = tuple(
            sorted(
                str(o["name"])
                for o in document.get("owners") or ()
                if isinstance(o, dict) and o.get("name")
            )
        )
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            maintainers=len(owners),
            owners=owners,
            manifest_known=False,
        )
