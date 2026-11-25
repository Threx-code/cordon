"""CRAN's registry record: `crandb.r-pkg.org/<name>/all` (every version with its publication date in `timeline`, each version's
manifest with its `Maintainer`, and `archived` where CRAN has removed the package)."""

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


API = "https://crandb.r-pkg.org"
NAME = re.compile(r"[A-Za-z][A-Za-z0-9.]*")


class CranSource(RecordSource):
    ecosystem: ClassVar[str] = "cran"
    #: CRAN's manifest names the maintainer who submitted the release.
    publisher_kind: ClassVar[PublisherKind] = "account"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if not NAME.fullmatch(name) or ".." in name or len(name) > 100:
            return ()
        return (Document(f"{API}/{name}/all"),)

    @staticmethod
    def maintainer(manifest: Any) -> str:
        """The maintainer's name: the e-mail address in `Name <address>` is not kept."""
        text = str(manifest.get("Maintainer") or "") if isinstance(manifest, dict) else ""
        return text.split("<", 1)[0].strip().strip('"').strip()

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        document = RegistryRecord._mapping(next(iter(documents.values()), None))
        manifests = RegistryRecord._mapping(document.get("versions"))
        archived = "archived" if document.get("archived") else ""
        releases = []
        for number, stamp in RegistryRecord._mapping(document.get("timeline")).items():
            when = RegistryRecord._when(stamp)
            if when is not None:
                releases.append(
                    Release(number, when, self.maintainer(manifests.get(number)), archived)
                )
        this = RegistryRecord._mapping(manifests.get(version))
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            has_repository=bool(this.get("URL") or this.get("BugReports")),
            description_length=len(str(this.get("Title") or "")),
            has_author=bool(this.get("Author") or this.get("Authors@R")),
        )
