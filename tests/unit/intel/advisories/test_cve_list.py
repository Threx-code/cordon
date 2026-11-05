"""The CVE List (`intel/cve_list`): ranges a CVE record states exactly, used where NVD gives none."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

from cordon_scanner.intel.advisories.cve_list import CveList
from cordon_scanner.intel.advisories.nvd_import import NvdImport


class Record:
    @staticmethod
    def make(
        identifier: str, affected: list[dict[str, Any]], adp: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        return {
            "cveMetadata": {"cveId": identifier, "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "affected": affected,
                    "descriptions": [{"lang": "en", "value": "A flaw.\nMore."}],
                    "metrics": [{"cvssV3_1": {"baseSeverity": "HIGH"}}],
                    "references": [
                        {"url": "https://github.com/acme/lib/commit/1", "tags": ["patch"]}
                    ],
                },
                "adp": adp or [],
            },
        }


class TestRanges:
    def test_a_cpe_and_its_affected_versions(self) -> None:
        record = Record.make(
            "CVE-2025-0001",
            [
                {
                    "cpes": ["cpe:2.3:a:acme:lib:*:*:*:*:*:*:*:*"],
                    "defaultStatus": "unaffected",
                    "versions": [
                        {
                            "version": "0",
                            "lessThan": "2.3.1",
                            "status": "affected",
                            "versionType": "semver",
                        },
                        {
                            "version": "3.0.0",
                            "lessThanOrEqual": "3.0.4",
                            "status": "affected",
                            "versionType": "semver",
                        },
                        {"version": "2.3.1", "status": "unaffected", "versionType": "semver"},
                    ],
                }
            ],
        )
        assert list(CveList.ranges(record)) == [
            ("acme:lib", {"versionEndExcluding": "2.3.1"}),
            ("acme:lib", {"versionStartIncluding": "3.0.0", "versionEndIncluding": "3.0.4"}),
        ]
        assert CveList.severity(record) == "high"
        assert CveList.description(record) == "A flaw."

    def test_versioned_cpes_name_their_own_versions(self) -> None:
        record = Record.make(
            "CVE-2025-0002",
            [
                {
                    "cpes": [
                        "cpe:2.3:a:fortinet:fortimanagercloud:7.6.4:*:*:*:*:*:*:*",
                        "cpe:/a:acme:tool:1.2",
                    ]
                }
            ],
        )
        # Each CPE carries its own version, and only its own.
        assert list(CveList.ranges(record)) == [
            ("fortinet:fortimanagercloud", {"v": "7.6.4"}),
            ("acme:tool", {"v": "1.2"}),
        ]

    def test_what_is_never_used(self) -> None:
        record = Record.make(
            "CVE-2025-0003",
            [
                # Free-text names alone: no CPE, no product.
                {
                    "vendor": "Apache Software Foundation",
                    "product": "Log4j",
                    "versions": [{"version": "2.0", "lessThan": "2.17", "status": "affected"}],
                },
                # Commits and distribution builds are not upstream versions.
                {
                    "cpes": ["cpe:2.3:a:acme:lib:*:*:*:*:*:*:*:*"],
                    "versions": [
                        {
                            "version": "abc",
                            "lessThan": "def",
                            "status": "affected",
                            "versionType": "git",
                        }
                    ],
                },
                {
                    "cpes": ["cpe:2.3:a:acme:lib:*:*:*:*:*:*:*:*"],
                    "versions": [
                        {"version": "1.0-1.el8", "status": "affected", "versionType": "rpm"}
                    ],
                },
                # Affected by default, with exceptions a range cannot hold.
                {
                    "cpes": ["cpe:2.3:a:acme:lib:*:*:*:*:*:*:*:*"],
                    "defaultStatus": "affected",
                    "versions": [{"version": "2.0", "status": "unaffected"}],
                },
                # An operating system's CPE is not an application's.
                {
                    "cpes": ["cpe:/o:redhat:enterprise_linux:8"],
                    "versions": [{"version": "8", "status": "affected"}],
                },
            ],
        )
        assert list(CveList.ranges(record)) == []

    def test_an_adps_cpe_counts(self) -> None:
        record = Record.make(
            "CVE-2025-0004",
            [{"vendor": "acme", "product": "lib"}],
            adp=[
                {
                    "affected": [
                        {
                            "cpes": ["cpe:2.3:a:acme:lib:*:*:*:*:*:*:*:*"],
                            "versions": [
                                {"version": "1.0", "lessThan": "1.5", "status": "affected"}
                            ],
                        }
                    ]
                }
            ],
        )
        assert list(CveList.ranges(record)) == [
            ("acme:lib", {"versionStartIncluding": "1.0", "versionEndExcluding": "1.5"})
        ]


class TestTheBaseline:
    def test_records_from_a_zip_of_a_zip(self) -> None:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as archive:
            archive.writestr(
                "cves/2025/0xxx/CVE-2025-0001.json", json.dumps(Record.make("CVE-2025-0001", []))
            )
            rejected = Record.make("CVE-2025-0009", [])
            rejected["cveMetadata"]["state"] = "REJECTED"
            archive.writestr("cves/2025/0xxx/CVE-2025-0009.json", json.dumps(rejected))
            archive.writestr("cves/delta.json", "{}")
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("cves.zip", inner.getvalue())
        found = [r["cveMetadata"]["cveId"] for r in CveList.read_bytes(outer.getvalue())]
        assert found == ["CVE-2025-0001"]


class TestTheMerge:
    def test_only_where_nvd_gives_no_range(self, monkeypatch) -> None:
        analysed = {
            "id": "CVE-2025-0001",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
            "descriptions": [{"lang": "en", "value": "NVD's text."}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:acme:lib:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "9.9",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
        monkeypatch.setattr(NvdImport, "cves", staticmethod(lambda year: iter([analysed])))
        monkeypatch.setattr(
            NvdImport, "index", staticmethod(lambda named=None, repositories=None: {})
        )
        listed = [
            Record.make(
                "CVE-2025-0001",
                [
                    {
                        "cpes": ["cpe:2.3:a:acme:lib:*:*:*:*:*:*:*:*"],
                        "versions": [{"version": "0", "lessThan": "1.0", "status": "affected"}],
                    }
                ],
            ),
            Record.make(
                "CVE-2025-0005",
                [
                    {
                        "cpes": ["cpe:2.3:a:acme:lib:*:*:*:*:*:*:*:*"],
                        "versions": [{"version": "0", "lessThan": "2.0", "status": "affected"}],
                    }
                ],
            ),
        ]
        built = NvdImport.build(
            range(2025, 2026), lambda _, rating: True, lambda _: None, cve_list=listed
        )
        assert built.products["acme:lib"] == [
            ["CVE-2025-0001", "high", {"versionEndExcluding": "9.9"}],
            ["CVE-2025-0005", "high", {"versionEndExcluding": "2.0"}],
        ]
        assert (
            built.text["CVE-2025-0001"] == "NVD's text."
            and built.text["CVE-2025-0005"] == "A flaw."
        )
