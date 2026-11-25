"""Which `RecordSource` reads which ecosystem's registry record: one table, no branch per ecosystem.

An ecosystem is added by writing its source and listing it here and in `registry_record.ECOSYSTEMS`; a test holds the two
equal, and the structural guard (`tests/unit/ecosystems/coverage`) holds `ECOSYSTEMS` to all 28 before the feature is done."""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.intel.registries.record_sources import git_hosted
from cordon_scanner.intel.registries.record_sources.base import RecordSource
from cordon_scanner.intel.registries.record_sources.npm import NpmSource
from cordon_scanner.intel.registries.record_sources.pypi import PypiSource


class RecordSources:
    SOURCES: ClassVar[tuple[RecordSource, ...]] = (NpmSource(), PypiSource(), *git_hosted.SOURCES)

    @classmethod
    def of(cls, ecosystem: str) -> RecordSource | None:
        return next((s for s in cls.SOURCES if s.ecosystem == ecosystem), None)

    @classmethod
    def ecosystems(cls) -> frozenset[str]:
        return frozenset(s.ecosystem for s in cls.SOURCES)
