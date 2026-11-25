"""The Terraform Registry's record: a provider (`namespace/type`) from `registry.terraform.io/v2/providers/<id>?include=provider-versions`
(the id from the provider search by namespace and name), a module (`namespace/name/provider`) from `/v2/modules/.../...?include=module-versions`;
each version has its `published-at`. The registry names the namespace that owns the provider or module, not the account that published a version."""

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


API = "https://registry.terraform.io/v2"
PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


class TerraformSource(RecordSource):
    ecosystem: ClassVar[str] = "terraform"
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    @staticmethod
    def parts(name: str) -> tuple[str, ...] | None:
        found = name.split("/")
        if len(found) in (2, 3) and all(PART.fullmatch(p) for p in found):
            return tuple(found)
        return None

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        parts = self.parts(name)
        if parts is None:
            return ()
        if len(parts) == 3:
            return (
                Document(f"{API}/modules/{parts[0]}/{parts[1]}/{parts[2]}?include=module-versions"),
            )
        return (
            Document(
                f"{API}/providers?filter%5Bnamespace%5D={parts[0]}&filter%5Bname%5D={parts[1]}"
            ),
        )

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        parts = self.parts(name)
        if parts is None or len(parts) == 3:
            return ()
        data = RegistryRecord._mapping(next(iter(documents.values()), None)).get("data")
        first = data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else {}
        identifier = str(first.get("id") or "")
        if not identifier.isdigit():
            return ()
        return (Document(f"{API}/providers/{identifier}?include=provider-versions"),)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        parts = self.parts(name)
        if parts is None:
            return None
        last = RegistryRecord._mapping(list(documents.values())[-1])
        unlisted = bool(
            RegistryRecord._mapping(
                RegistryRecord._mapping(last.get("data")).get("attributes")
            ).get("unlisted")
        )
        releases = []
        for item in last.get("included") or ():
            attributes = RegistryRecord._mapping(
                item.get("attributes") if isinstance(item, dict) else None
            )
            when = RegistryRecord._when(attributes.get("published-at"))
            number = attributes.get("version")
            if when is not None and isinstance(number, str):
                releases.append(Release(number, when, parts[0], "unlisted" if unlisted else ""))
        return RecordBuilder.from_history(self, name, version, releases, manifest_known=False)
