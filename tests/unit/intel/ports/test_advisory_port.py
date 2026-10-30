"""The advisory port (`intel.base.Advisories`, `AdvisoryRecord`, `AdvisoryFileChecks`): the registry's
roles are the concrete classes, and a record carries every field the detectors read."""

from __future__ import annotations

from cordon_scanner.intel import registry
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase, AdvisoryFiles
from cordon_scanner.intel.advisories.shipped import ShippedAdvisories


class PortKit:
    RECORDS = (
        Advisory(
            ecosystem="npm",
            name="left-pad",
            versions=("1.0.0",),
            summary="s",
            identifier="GHSA-x",
            aliases=("CVE-1",),
            severity="HIGH",
        ),
    )


class TestTheAdvisoryPort:
    def test_the_roles_are_the_classes(self) -> None:
        assert registry.AdvisoryFiles is AdvisoryFiles
        assert registry.BundledAdvisories is ShippedAdvisories
        assert registry.AdvisoryFiles.tampered_files() == AdvisoryFiles.tampered_files()
        assert registry.AdvisoryFiles.refused_synced_files() == AdvisoryFiles.refused_synced_files()

    def test_a_database_answers_through_the_port(self) -> None:
        database = AdvisoryDatabase(PortKit.RECORDS)
        assert not database.is_empty
        assert database.covers("npm")
        assert database.matching("npm", "left-pad", "1.0.0") == PortKit.RECORDS
        assert database.for_package("npm", "left-pad") == PortKit.RECORDS
        assert isinstance(database.meta.record_count, int)

    def test_a_record_carries_what_the_detectors_read(self) -> None:
        record = PortKit.RECORDS[0]
        for field in (
            "ecosystem",
            "name",
            "identifier",
            "malicious",
            "reference",
            "summary",
            "severity",
            "aliases",
            "versions",
            "introduced",
            "fixed",
            "last_affected",
            "repositories",
        ):
            getattr(record, field)
        assert record.affects("1.0.0") and not record.affects("2.0.0")
