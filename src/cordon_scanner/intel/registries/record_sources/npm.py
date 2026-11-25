"""npm's registry record: the packument, `registry.npmjs.org/<name>`."""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.intel.registries.record_sources.base import (
    Document,
    PublisherKind,
    RecordSource,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.intel.registries.registry_record import RegistryRecord


class NpmSource(RecordSource):
    ecosystem: ClassVar[str] = "npm"
    publisher_kind: ClassVar[PublisherKind] = "account"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_client import REGISTRY_HOSTS

        return (Document(f"{REGISTRY_HOSTS['npm']}/{urllib.parse.quote(name, safe='@')}"),)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from dataclasses import replace

        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = next(iter(documents.values()), None)
        record = RegistryRecord.from_npm(document, version) if isinstance(document, dict) else None
        return replace(record, publisher_kind=self.publisher_kind) if record else None
