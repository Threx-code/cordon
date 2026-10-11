"""NVD as an advisory source (`intel/nvd`, `intel/nvd_import`): a package tied to a CPE product --
by a curated mapping, or by the guarded rule from its name and its site together -- and NVD's own
configuration ranges applied to its version."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from cordon_scanner.core.models import Dependency
from cordon_scanner.intel.nvd import CpeRule, NvdAdvisories, NvdData, NvdRange
from cordon_scanner.intel.nvd_import import NvdImport


class Make:
    @staticmethod
    def dep(ecosystem: str, name: str, version: str, **fields: Any) -> Dependency:
        return Dependency(
            purl=f"pkg:{ecosystem}/{name}@{version}",
            ecosystem=ecosystem,
            name=name,
            version=version,
            direct=True,
            **fields,
        )


INDEX = {
    "sqlite": [["sqlite:sqlite", ["sqlite.org"]]],
    "lua": [["lua:lua", ["lua.org"]]],
    "kitty": [
        ["kovidgoyal:kitty", ["github.com/kovidgoyal/kitty"]],
        ["other:kitty", ["kitty.example"]],
    ],
    "tool": [["a:tool", ["shared.example"]], ["b:tool", ["shared.example"]]],
}


class TestTheSite:
    @pytest.mark.parametrize(
        ("url", "site"),
        [
            ("https://www.sqlite.org/index.html", "sqlite.org"),
            ("https://github.com/kovidgoyal/kitty/releases", "github.com/kovidgoyal/kitty"),
            ("https://github.com/kovidgoyal", None),
            ("https://sourceforge.net/projects/lame/files/", "sourceforge.net/lame"),
            ("https://lame.sourceforge.net/", "sourceforge.net/lame"),
            ("https://downloads.example.co.uk/x", "example.co.uk"),
            ("https://user.github.io/thing", "user.github.io"),
            ("not a url", None),
        ],
    )
    def test_site(self, url: str, site: str | None) -> None:
        assert CpeRule.site(url) == site


class TestTheGuardedRule:
    def test_name_and_site_together(self) -> None:
        product, why = CpeRule.match(INDEX, ["sqlite"], ["https://www.sqlite.org/"])
        assert product == "sqlite:sqlite" and "sqlite.org" in why

    def test_a_name_alone_is_not_enough(self) -> None:
        product, why = CpeRule.match(INDEX, ["sqlite"], ["https://example.com/sqlite"])
        assert product is None and "has its name and its site" in why

    def test_a_site_picks_one_of_two_products_with_the_name(self) -> None:
        product, _ = CpeRule.match(INDEX, ["kitty"], ["https://github.com/kovidgoyal/kitty"])
        assert product == "kovidgoyal:kitty"

    def test_two_products_passing_is_ambiguity(self) -> None:
        product, why = CpeRule.match(INDEX, ["tool"], ["https://shared.example/"])
        assert product is None and "more than one" in why

    def test_no_url_no_match(self) -> None:
        assert CpeRule.match(INDEX, ["sqlite"], [])[0] is None


class TestRanges:
    @pytest.mark.parametrize(
        ("bounds", "version", "affected"),
        [
            ({"versionEndExcluding": "3.46.1"}, "3.46.0", True),
            ({"versionEndExcluding": "3.46.1"}, "3.46.1", False),
            ({"versionEndIncluding": "3.46.0"}, "3.46.0_2", True),
            ({"versionStartExcluding": "3.0", "versionEndExcluding": "3.5"}, "3.0", False),
            ({"versionStartIncluding": "3.0", "versionEndExcluding": "3.5"}, "3.0", True),
            ({"v": "5.4.6"}, "5.4.6#1", True),
            ({"v": "1.0", "u": "rc1"}, "1.0rc1", True),
            ({"v": "1.0", "u": "rc1"}, "1.0", False),
            ({}, "anything", True),
            ({"versionEndExcluding": "10.0"}, "9.2", True),
            ({"versionEndExcluding": "6.8.9"}, "6.8.9,abc123", False),
        ],
    )
    def test_affects(self, bounds: dict[str, str], version: str, affected: bool) -> None:
        assert NvdRange.affects(bounds, version) is affected


class TestCheck:
    @staticmethod
    def data(monkeypatch, curated: dict[str, dict[str, list[str]]] | None = None) -> None:
        files = {
            "nvd-cves.json.gz": {
                "products": {
                    "sqlite:sqlite": [
                        ["CVE-2025-0001", "high", {"versionEndExcluding": "3.47.0"}],
                        ["CVE-2020-0002", "critical", {"versionEndExcluding": "3.30.0"}],
                    ],
                    "docker:desktop": [["CVE-2025-0003", "high", {"versionEndExcluding": "4.30"}]],
                },
                "text": {
                    "CVE-2025-0001": "A flaw.",
                    "CVE-2020-0002": "Old.",
                    "CVE-2025-0003": "D.",
                },
            },
            "nvd-cpe.json.gz": {"curated": curated or {}, "index": INDEX},
        }
        monkeypatch.setattr(NvdData, "load", staticmethod(lambda name: files[name]))

    def test_the_rule_ties_and_the_range_decides(self, monkeypatch) -> None:
        self.data(monkeypatch)
        sqlite = Make.dep("vcpkg", "sqlite3", "3.46.0")
        result = NvdAdvisories.check(
            [sqlite], {sqlite.purl: ("https://sqlite.org/2024/sqlite-autoconf.tar.gz",)}
        )
        # sqlite3 is sqlite with a packager's major version: tied, through the site.
        assert sqlite.purl in result.checked
        stranger = Make.dep("vcpkg", "sqlite3", "3.46.0")
        assert (
            stranger.purl
            not in NvdAdvisories.check(
                [stranger], {stranger.purl: ("https://example.com/",)}
            ).checked
        )
        sqlite = Make.dep("conan", "sqlite", "3.46.0")
        result = NvdAdvisories.check([sqlite], {sqlite.purl: ("https://www.sqlite.org/",)})
        assert sqlite.purl in result.checked
        (found,) = result.advisories[sqlite.purl]
        assert found.identifier == "CVE-2025-0001" and found.matched_through == "nvd-inferred"
        assert "matched through NVD" in found.summary and found.fixed == "3.47.0"

    def test_a_curated_cpe_is_used_by_name_offline(self, monkeypatch) -> None:
        self.data(monkeypatch, {"homebrew-cask": {"docker": ["docker:desktop"]}})
        cask = Make.dep("homebrew", "docker", "4.20.0", platform=("cask",))
        formula = Make.dep("homebrew", "docker", "24.0.0")
        result = NvdAdvisories.check([cask, formula], {})
        assert (
            cask.purl in result.checked and result.advisories[cask.purl][0].matched_through == "nvd"
        )
        # The formula of the same name is the CLI, not the curated cask.
        assert formula.purl not in result.checked

    def test_no_data_is_said_so(self, monkeypatch) -> None:
        monkeypatch.setattr(NvdData, "load", staticmethod(lambda name: {}))
        package = Make.dep("conda", "lua", "5.4.6")
        assert "not installed" in NvdAdvisories.check([package]).unchecked[package.purl]


class TestTheImport:
    CVE: ClassVar[dict[str, Any]] = {
        "id": "CVE-2025-0001",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "3.47.0",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:sqlite:sqlite:3.46.0:rc1:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*",
                            },
                            {"vulnerable": True, "criteria": "cpe:2.3:a:x:y:-:*:*:*:*:*:*:*"},
                        ]
                    }
                ]
            }
        ],
    }

    def test_ranges_and_severity(self) -> None:
        assert NvdImport.severity(self.CVE) == "high"
        assert list(NvdImport.ranges(self.CVE)) == [
            ("sqlite:sqlite", {"versionEndExcluding": "3.47.0"}),
            ("sqlite:sqlite", {"v": "3.46.0", "u": "rc1"}),
        ]
