"""Hackage's registry record: `hackage.haskell.org/package/<name>.json` (every version with its state: normal, deprecated or
unpreferred) and, for the newest versions, `.../<name>-<version>/upload-time`. A package with more versions than a record reads
times for keeps the older ones without a time of their own (they are not counted as earlier releases)."""

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


API = "https://hackage.haskell.org/package"
NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
VERSION = re.compile(r"[0-9][0-9.]*")
TIMES = 63


class HackageSource(RecordSource):
    ecosystem: ClassVar[str] = "hackage"
    #: Hackage's page names the uploader, but its API does not serve it with the times.
    publisher_kind: ClassVar[PublisherKind] = "none"

    def documents(self, name: str, version: str) -> tuple[Document, ...]:
        if (
            not NAME.fullmatch(name)
            or ".." in name
            or len(name) > 100
            or (version and not VERSION.fullmatch(version))
        ):
            return ()
        return (Document(f"{API}/{name}.json"),)

    def followed(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> tuple[Document, ...]:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        states = RegistryRecord._mapping(next(iter(documents.values()), None))
        listed = [v for v in states if VERSION.fullmatch(v)]
        wanted = [v for v in listed[-TIMES:] if v != version]
        if version in states:
            wanted.append(version)
        return tuple(
            Document(f"{API}/{name}-{v}/upload-time", kind="text", required=False) for v in wanted
        )

    def record(
        self, name: str, version: str, documents: Mapping[str, Any]
    ) -> RegistryRecord | None:
        from cordon_scanner.intel.registries.registry_record import RegistryRecord

        states = RegistryRecord._mapping(next(iter(documents.values()), None))
        releases = []
        for url, text in documents.items():
            if not url.endswith("/upload-time") or not isinstance(text, str):
                continue
            number = url.rsplit("/", 2)[-2].removeprefix(f"{name}-")
            when = RegistryRecord._when(text.strip())
            state = str(states.get(number) or "normal")
            if when is not None:
                releases.append(Release(number, when, withdrawn="" if state == "normal" else state))
        return RecordBuilder.from_history(self, name, version, releases, manifest_known=False)
