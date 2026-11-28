"""PyPI's registry record: the JSON API, `pypi.org/pypi/<name>/json`."""

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


class PypiSource(RecordSource):
    ecosystem: ClassVar[str] = "pypi"
    #: The JSON names the project's owners and maintainers (`ownership.roles`), not the account that uploaded a release.
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_client import REGISTRY_HOSTS

        return (
            Document(f"{REGISTRY_HOSTS['pypi']}/pypi/{urllib.parse.quote(name, safe='')}/json"),
        )

    @staticmethod
    def history(document: dict[str, Any]) -> list[Release]:
        """Every release with files, at the time of its first upload; one whose files are all yanked is yanked."""
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        out = []
        for number, files in RegistryRecord._mapping(document.get("releases")).items():
            uploads = [f for f in files if isinstance(f, dict)] if isinstance(files, list) else []
            times = [
                t
                for f in uploads
                if (t := RegistryRecord._when(f.get("upload_time_iso_8601"))) is not None
            ]
            if times:
                yanked = all(f.get("yanked") for f in uploads)
                out.append(Release(str(number), min(times), "", "yanked" if yanked else ""))
        return out

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from dataclasses import replace

        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = next(iter(documents.values()), None)
        if isinstance(document, dict):
            RecordBuilder.note(self.history(document))
        record = RegistryRecord.from_pypi(document, version) if isinstance(document, dict) else None
        return replace(record, publisher_kind=self.publisher_kind) if record else None
