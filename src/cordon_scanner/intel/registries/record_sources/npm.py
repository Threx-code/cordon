"""npm's registry record: the packument, `registry.npmjs.org/<name>`."""

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


class NpmSource(RecordSource):
    ecosystem: ClassVar[str] = "npm"
    publisher_kind: ClassVar[PublisherKind] = "account"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_client import REGISTRY_HOSTS

        return (Document(f"{REGISTRY_HOSTS['npm']}/{urllib.parse.quote(name, safe='@')}"),)

    @staticmethod
    def history(document: dict[str, Any]) -> list[Release]:
        """Every release the packument times (`created` and `modified` are not releases), with the account that published it."""
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        versions = RegistryRecord._mapping(document.get("versions"))
        out = []
        for number, value in RegistryRecord._mapping(document.get("time")).items():
            when = RegistryRecord._when(value)
            if number in ("created", "modified") or when is None:
                continue
            user = RegistryRecord._mapping(
                RegistryRecord._mapping(versions.get(number)).get("_npmUser")
            )
            out.append(Release(str(number), when, str(user.get("name") or "")))
        return out

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from dataclasses import replace

        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = next(iter(documents.values()), None)
        if isinstance(document, dict):
            RecordBuilder.note(self.history(document))
        record = RegistryRecord.from_npm(document, version) if isinstance(document, dict) else None
        return replace(record, publisher_kind=self.publisher_kind) if record else None
