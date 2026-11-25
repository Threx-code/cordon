"""Which `RecordSource` reads which ecosystem's registry record: one table, no branch per ecosystem.

An ecosystem is added by writing its source and listing it here and in `registry_record.ECOSYSTEMS`; a test holds the two
equal, and the structural guard (`tests/unit/ecosystems/coverage`) holds `ECOSYSTEMS` to all 28 before the feature is done."""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.intel.registries.record_sources.ansible import AnsibleSource
from cordon_scanner.intel.registries.record_sources.base import RecordSource
from cordon_scanner.intel.registries.record_sources.cargo import CargoSource
from cordon_scanner.intel.registries.record_sources.cocoapods import CocoapodsSource
from cordon_scanner.intel.registries.record_sources.composer import ComposerSource
from cordon_scanner.intel.registries.record_sources.conda import CondaSource
from cordon_scanner.intel.registries.record_sources.hex import HexSource
from cordon_scanner.intel.registries.record_sources.npm import NpmSource
from cordon_scanner.intel.registries.record_sources.nuget import NugetSource
from cordon_scanner.intel.registries.record_sources.pub import PubSource
from cordon_scanner.intel.registries.record_sources.pypi import PypiSource
from cordon_scanner.intel.registries.record_sources.rubygems import RubygemsSource


class RecordSources:
    SOURCES: ClassVar[tuple[RecordSource, ...]] = (
        NpmSource(),
        PypiSource(),
        CargoSource(),
        RubygemsSource(),
        HexSource(),
        PubSource(),
        ComposerSource(),
        CocoapodsSource(),
        AnsibleSource(),
        CondaSource(),
        NugetSource(),
    )

    @classmethod
    def of(cls, ecosystem: str) -> RecordSource | None:
        return next((s for s in cls.SOURCES if s.ecosystem == ecosystem), None)

    @classmethod
    def ecosystems(cls) -> frozenset[str]:
        return frozenset(s.ecosystem for s in cls.SOURCES)
