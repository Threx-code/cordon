"""Artifact Hub's record of a Helm chart: `artifacthub.io/api/v1/packages/helm/<repository>/<chart>` (every version with its `ts`, the
repository and its organisation, `deprecated`). A chart named `repository/chart` is asked for directly; a bare `chart` is searched for and
used only when exactly one chart of that name (or exactly one official one) is listed: two different charts of one name give no record."""

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


API = "https://artifacthub.io/api/v1/packages"
PART = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")


class HelmSource(RecordSource):
    ecosystem: ClassVar[str] = "helm"
    publisher_kind: ClassVar[PublisherKind] = "namespace"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        parts = name.split("/")
        if not all(PART.fullmatch(p) for p in parts) or ".." in name:
            return ()
        if len(parts) == 2:
            return (Document(f"{API}/helm/{parts[0]}/{parts[1]}"),)
        if len(parts) == 1:
            return (Document(f"{API}/search?ts_query_web={parts[0]}&kind=0&limit=20&facets=false"),)
        return ()

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        if "/" in name:
            return ()
        listed = RegistryRecord._mapping(next(iter(documents.values()), None)).get("packages")
        same = [
            p
            for p in (listed if isinstance(listed, list) else ())
            if isinstance(p, dict) and str(p.get("name") or "").lower() == name
        ]
        official = [p for p in same if p.get("official")]
        chosen = same if len(same) == 1 else official if len(official) == 1 else []
        if len(chosen) != 1:
            return ()
        repository = RegistryRecord._mapping(chosen[0].get("repository")).get("name")
        if not isinstance(repository, str) or not PART.fullmatch(repository):
            return ()
        return (Document(f"{API}/helm/{repository}/{name}"),)

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        package = RegistryRecord._mapping(list(documents.values())[-1])
        if "available_versions" not in package:
            return None
        repository = RegistryRecord._mapping(package.get("repository"))
        publisher = str(repository.get("organization_name") or repository.get("name") or "")
        withdrawn = "deprecated" if package.get("deprecated") else ""
        releases = []
        for entry in package.get("available_versions") or ():
            number = entry.get("version") if isinstance(entry, dict) else None
            seconds = entry.get("ts") if isinstance(entry, dict) else None
            if isinstance(number, str) and isinstance(seconds, int):
                from datetime import UTC, datetime

                releases.append(
                    Release(
                        number,
                        datetime.fromtimestamp(seconds, UTC).replace(tzinfo=None),
                        publisher,
                        withdrawn,
                    )
                )
        current = str(package.get("version") or "") == version
        return RecordBuilder.from_history(
            self,
            name,
            version,
            releases,
            has_repository=current and bool(package.get("home_url")),
            description_length=len(str(package.get("description") or "")) if current else 0,
            manifest_known=current,
        )
