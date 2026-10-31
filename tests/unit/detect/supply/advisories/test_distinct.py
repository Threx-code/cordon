"""One finding per fact: two sources' records of one malicious release, or of one vulnerability,
are reported once, naming every identifier (`detect/supply/advisories/distinct.py`)."""

from __future__ import annotations

import random
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.detect.supply.advisories.detector import AdvisoryDetector
from cordon_scanner.detect.supply.advisories.distinct import DistinctAdvisories
from cordon_scanner.detect.supply.advisories.findings import (
    BUNDLED_MALWARE_RULE,
    MALICIOUS_RULE,
)
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Severity
from cordon_scanner.intel.advisories.advisories import Advisory, AdvisoryDatabase
from unit.engine.pipeline.test_not_installed import Tarball


class Records:
    @staticmethod
    def record(identifier: str, *, malicious: bool = False, **fields: object) -> Advisory:
        defaults: dict[str, object] = {"versions": ("1.0.0",)}
        defaults.update(fields)
        return Advisory(
            ecosystem="npm", name="p", malicious=malicious, identifier=identifier, **defaults
        )


class TestDistinctAdvisories:
    def test_every_malicious_record_about_a_release_is_one(self) -> None:
        kept = DistinctAdvisories.of(
            [Records.record("MAL-2", malicious=True), Records.record("GHSA-x", malicious=True)]
        )
        assert len(kept) == 1
        names = {kept[0].identifier, *kept[0].aliases}
        assert names == {"MAL-2", "GHSA-x"}

    def test_records_sharing_a_cve_are_one_vulnerability_at_the_higher_severity(self) -> None:
        kept = DistinctAdvisories.of(
            [
                Records.record("GHSA-a", aliases=("CVE-1",), severity="moderate"),
                Records.record("PYSEC-b", aliases=("CVE-1",), severity="critical"),
            ]
        )
        assert [(k.identifier, k.severity) for k in kept] == [("PYSEC-b", "critical")]
        assert set(kept[0].aliases) == {"CVE-1", "GHSA-a"}

    def test_a_chain_of_aliases_is_one_group(self) -> None:
        kept = DistinctAdvisories.of(
            [
                Records.record("A", aliases=("CVE-1",)),
                Records.record("C", aliases=("CVE-2",)),
                Records.record("B", aliases=("CVE-1", "CVE-2")),
            ]
        )
        assert len(kept) == 1
        assert {kept[0].identifier, *kept[0].aliases} == {"A", "B", "C", "CVE-1", "CVE-2"}

    def test_different_vulnerabilities_stay_apart_and_beside_the_malicious_one(self) -> None:
        kept = DistinctAdvisories.of(
            [
                Records.record("GHSA-a", aliases=("CVE-1",)),
                Records.record("GHSA-b", aliases=("CVE-2",)),
                Records.record("MAL-1", malicious=True),
            ]
        )
        assert sorted(k.identifier for k in kept) == ["GHSA-a", "GHSA-b", "MAL-1"]

    def test_an_exact_version_list_is_kept_over_a_range(self) -> None:
        listed = Records.record("GHSA-a")
        ranged = Records.record("GHSA-a", versions=(), introduced="0", fixed="2.0.0")
        assert DistinctAdvisories.of([ranged, listed])[0].is_range is False

    def test_the_choice_is_the_same_in_any_order(self) -> None:
        records = [
            Records.record("GHSA-a", aliases=("CVE-1",), severity="high"),
            Records.record("PYSEC-b", aliases=("CVE-1",), severity="high"),
            Records.record("OSV-c", aliases=("CVE-1",), severity="high"),
            Records.record("MAL-2", malicious=True),
            Records.record("MAL-1", malicious=True),
        ]
        rng = random.Random(20261031)  # noqa: S311 -- a shuffle, not key material
        first = None
        for _ in range(50):
            rng.shuffle(records)
            got = sorted(
                (k.identifier, tuple(sorted(k.aliases))) for k in DistinctAdvisories.of(records)
            )
            first = first or got
            assert got == first


class TestOneFindingPerFact:
    @staticmethod
    def scan(tmp_path: Path, members: dict[str, str]) -> list[tuple[str, Severity]]:
        records = (
            Advisory(
                ecosystem="npm",
                name="evilpkg",
                versions=("1.0.0",),
                malicious=True,
                summary="one",
                identifier="MAL-evilpkg",
            ),
            Advisory(
                ecosystem="npm",
                name="evilpkg",
                versions=("1.0.0",),
                malicious=True,
                summary="two",
                identifier="GHSA-evil",
            ),
        )
        config = Config.default().with_overrides(use_cache=False, severity_threshold=Severity.INFO)
        result = Scanner(config, detectors=(AdvisoryDetector(AdvisoryDatabase(records)),)).scan(
            Tarball.write(tmp_path, members)
        )
        return [(f.rule_id, f.severity) for f in result.findings if "MALWARE" in f.rule_id]

    def test_an_installed_release_two_sources_record_is_one_finding(self, tmp_path: Path) -> None:
        found = self.scan(
            tmp_path,
            {
                "package.json": '{"name": "x", "version": "1.0.0", "dependencies": {"evilpkg": "1.0.0"}}'
            },
        )
        assert found == [(MALICIOUS_RULE, Severity.CRITICAL)]

    def test_a_not_installed_release_two_sources_record_is_one_finding(
        self, tmp_path: Path
    ) -> None:
        found = self.scan(
            tmp_path,
            {
                "package.json": '{"name": "x", "version": "1.0.0"}',
                "examples/app/package.json": '{"name": "app", "version": "1.0.0"}',
                "examples/app/package-lock.json": Tarball.lock(evilpkg="1.0.0"),
            },
        )
        assert found == [(BUNDLED_MALWARE_RULE, Severity.HIGH)]
