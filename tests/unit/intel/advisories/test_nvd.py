"""NVD as an advisory source (`intel/nvd`, `intel/nvd_import`): a package tied to a CPE product --
by a curated mapping, or by the guarded rule from its name and its site together -- and NVD's own
configuration ranges applied to its version."""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.advisories.nvd import CpeRule, NvdAdvisories, NvdData, NvdRange
from cordon_scanner.intel.advisories.nvd_import import NvdImport


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
    "tool": [["a:tool", ["shared.example", "a.example"]], ["b:tool", ["b.example"]]],
    "poco": [
        ["macchina:poco", ["github.com/pocoproject/poco"]],
        ["pocoproject:poco", ["github.com/pocoproject/poco"]],
    ],
    "libexpat": [["libexpat_project:libexpat", ["github.com/libexpat/libexpat"]]],
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
            (
                "https://downloads.sourceforge.net/project/lame/lame/3.100/x.tar.gz",
                "sourceforge.net/lame",
            ),
            ("https://downloads.sourceforge.net/lame/x.tar.gz", "sourceforge.net/lame"),
            ("https://prdownloads.sourceforge.net/lame/x.tar.gz", "sourceforge.net/lame"),
            ("https://master.dl.sourceforge.net/project/lame/x.tar.gz", "sourceforge.net/lame"),
            ("https://lame.sourceforge.io/", "sourceforge.net/lame"),
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

    def test_two_products_on_different_sites_is_ambiguity(self) -> None:
        product, why = CpeRule.match(INDEX, ["tool"], ["https://a.example/", "https://b.example/"])
        assert product is None and "more than one" in why

    def test_two_cpe_names_on_one_site_are_one_product(self) -> None:
        product, _ = CpeRule.match(INDEX, ["poco"], ["https://github.com/pocoproject/poco"])
        assert product == "macchina:poco pocoproject:poco"

    def test_a_lib_prefix_is_the_same_name(self) -> None:
        product, _ = CpeRule.match(INDEX, ["expat"], ["https://github.com/libexpat/libexpat"])
        assert product == "libexpat_project:libexpat"

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


class TestNameVariants:
    def test_a_packagers_utils_suffix(self) -> None:
        index = {"xz": [["tukaani:xz", ["tukaani.org"]]]}
        product, _ = CpeRule.match(index, ["xz_utils"], ["https://tukaani.org/xz/xz-5.4.5.tar.xz"])
        assert product == "tukaani:xz"


class TestAResolvedVersion:
    def test_the_routes_resolved_version_stands_in_for_a_missing_one(self, monkeypatch) -> None:
        TestCheck.data(monkeypatch)
        port = Dependency(
            purl="pkg:vcpkg/sqlite3", ecosystem="vcpkg", name="sqlite3", version=None, direct=True
        )
        homes = {port.purl: ("https://sqlite.org/2025/sqlite-autoconf-3490100.tar.gz",)}
        assert port.purl in NvdAdvisories.check([port], homes).unchecked
        result = NvdAdvisories.check([port], homes, {port.purl: "3.46.0"})
        assert (
            port.purl in result.checked
            and result.advisories[port.purl][0].identifier == "CVE-2025-0001"
        )


class TestTheProjectSite:
    INDEX: ClassVar[dict[str, list[list[Any]]]] = {
        "lame": [["lame_project:lame", ["sf.net", "sourceforge.net/lame"]]],
        "curl": [["haxx:curl", ["github.com/curl/curl", "haxx.se"]]],
        "libcurl": [["haxx:libcurl", ["github.com/curl/curl", "haxx.se"]]],
        "fork": [["other:fork", ["github.com/curl/curl"]]],
        "aom": [["aomedia:libaom", ["aomedia.org"]]],
    }

    def test_a_project_site_one_product_lists_ties_whatever_the_name(self) -> None:
        product, why = CpeRule.match(
            self.INDEX,
            ["libmp3lame"],
            ["https://downloads.sourceforge.net/project/lame/lame/3.100/lame-3.100.tar.gz"],
        )
        assert product == "lame_project:lame" and "alone lists" in why

    def test_a_repository_two_products_list_is_no_tie(self) -> None:
        product, why = CpeRule.match(
            self.INDEX, ["curl-impersonate"], ["https://github.com/curl/curl"]
        )
        assert product is None and "more than one" in why

    def test_a_domain_is_never_enough_alone(self) -> None:
        product, _ = CpeRule.match(self.INDEX, ["libaom-av1"], ["https://aomedia.org/"])
        assert product is None


class TestEveryNamedProduct:
    def test_a_product_whose_cves_are_all_below_the_cut_is_still_indexed(self, monkeypatch) -> None:
        medium = {
            **TestTheImport.CVE,
            "id": "CVE-2022-0002",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "MEDIUM"}}]},
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:open-mpi:hwloc:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "2.1.0",
                                }
                            ]
                        }
                    ]
                }
            ],
        }
        monkeypatch.setattr(
            NvdImport, "cves", staticmethod(lambda year: iter([TestTheImport.CVE, medium]))
        )
        seen: list[set[str]] = []
        monkeypatch.setattr(
            NvdImport,
            "index",
            staticmethod(lambda named=None, repositories=None: seen.append(set(named or ())) or {}),
        )
        built = NvdImport.build(
            range(2022, 2023), lambda _, rating: rating == "high", lambda _: None
        )
        assert set(built.products) == {"sqlite:sqlite"}
        assert seen == [{"sqlite:sqlite", "open-mpi:hwloc"}]


class TestReleaseNames:
    @pytest.mark.parametrize(
        ("url", "version", "names"),
        [
            (
                "https://downloads.sourceforge.net/project/lame/lame/3.100/lame-3.100.tar.gz",
                "3.100",
                ("lame",),
            ),
            ("https://curl.haxx.se/download/curl-7.68.0.tar.bz2", "7.68.0", ("curl",)),
            (
                "https://www.libsdl.org/projects/SDL_mixer/release/SDL2_mixer-2.6.3.tar.gz",
                "2.6.3#1",
                ("SDL2_mixer",),
            ),
            (
                "https://download.open-mpi.org/release/hwloc/v2.9/hwloc-2.9.3.tar.bz2",
                "2.9.3_1",
                ("hwloc",),
            ),
            ("https://curl.haxx.se/download/curl-7.67.0.tar.bz2", "7.68.0", ()),
            ("https://github.com/ogham/exa/archive/v0.9.0.tar.gz", "0.9.0", ()),
            ("https://example.org/", "1.0", ()),
        ],
    )
    def test_release_names(self, url: str, version: str, names: tuple[str, ...]) -> None:
        assert CpeRule.release_names([url], version) == names

    def test_the_release_file_names_the_product_under_the_site_guard(self, monkeypatch) -> None:
        TestCheck.data(monkeypatch)
        package = Make.dep("conan", "libsqlite-amalgamation", "3.46.0")
        result = NvdAdvisories.check(
            [package], {package.purl: ("https://www.sqlite.org/2024/sqlite-3.46.0.tar.gz",)}
        )
        assert package.purl in result.checked
        stranger = Make.dep("conan", "libsqlite-amalgamation", "3.46.0")
        assert (
            stranger.purl
            not in NvdAdvisories.check(
                [stranger], {stranger.purl: ("https://example.com/sqlite-3.46.0.tar.gz",)}
            ).checked
        )


class TestRepositoriesFromReferences:
    def test_patch_issue_and_release_references_on_forges(self) -> None:
        cve = {
            "references": [
                {"url": "https://github.com/open-mpi/hwloc/issues/544", "tags": ["Issue Tracking"]},
                {"url": "https://github.com/open-mpi/hwloc/commit/abc", "tags": ["Patch"]},
                {"url": "https://www.open-mpi.org/projects/hwloc/", "tags": ["Product"]},
                {"url": "https://c-ares.haxx.se/adv_20210810.html", "tags": ["Vendor Advisory"]},
                {"url": "https://github.com/advisories/GHSA-x", "tags": ["Third Party Advisory"]},
                {"url": "https://lists.debian.org/x", "tags": ["Patch"]},
            ]
        }
        assert NvdImport.project_sites(cve) == {
            "github.com/open-mpi/hwloc",
            "open-mpi.org",
            "haxx.se",
        }

    def test_a_cve_naming_two_products_gives_neither_a_repository(self, monkeypatch) -> None:
        two = {
            "id": "CVE-2024-0003",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
            "references": [{"url": "https://github.com/a/a/commit/1", "tags": ["Patch"]}],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:a:a:*:*:*:*:*:*:*:*"},
                                {"vulnerable": True, "criteria": "cpe:2.3:a:b:b:*:*:*:*:*:*:*:*"},
                            ]
                        }
                    ]
                }
            ],
        }
        one = {
            **two,
            "id": "CVE-2024-0004",
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {"vulnerable": True, "criteria": "cpe:2.3:a:c:c:*:*:*:*:*:*:*:*"}
                            ]
                        }
                    ]
                }
            ],
            "references": [{"url": "https://github.com/c/c/issues/2", "tags": ["Issue Tracking"]}],
        }
        monkeypatch.setattr(NvdImport, "cves", staticmethod(lambda year: iter([two, one])))
        given: list[dict[str, set[str]]] = []
        monkeypatch.setattr(
            NvdImport,
            "index",
            staticmethod(
                lambda named=None, repositories=None: given.append(dict(repositories or {})) or {}
            ),
        )
        NvdImport.build(range(2024, 2025), lambda _, rating: True, lambda _: None)
        assert given == [{"c:c": {"github.com/c/c"}}]


class TestOneVendorsProducts:
    def test_one_vendors_names_for_one_project_together(self) -> None:
        index = {
            "json": [["nlohmann:json", ["github.com/nlohmann/json"]]],
            "jsonformoderncpp": [["nlohmann:json-for-modern-cpp", ["github.com/nlohmann/json"]]],
        }
        product, why = CpeRule.match(
            index, ["modern-json-lib"], ["https://github.com/nlohmann/json"]
        )
        assert product == "nlohmann:json nlohmann:json-for-modern-cpp" and "one vendor's" in why


class TestVendorPrefixedNames:
    INDEX: ClassVar[dict[str, list[list[Any]]]] = {
        "json": [
            ["nlohmann:json", ["github.com/nlohmann/json"]],
            ["other:json", ["github.com/nlohmann/json"]],
        ]
    }

    def test_vendor_underscore_product(self) -> None:
        product, _ = CpeRule.match(
            self.INDEX, ["nlohmann_json"], ["https://github.com/nlohmann/json"]
        )
        assert product == "nlohmann:json"

    def test_the_prefix_must_be_the_products_vendor(self) -> None:
        product, _ = CpeRule.match(self.INDEX, ["boost_json"], ["https://github.com/boostorg/json"])
        assert product is None


class TestOneVendorsTwoProjects:
    def test_two_projects_on_one_site_are_no_tie(self) -> None:
        index = {
            "tcl": [["tcl:tcl", ["sourceforge.net/tcl"]]],
            "tk": [["tcl:tk", ["tcl.tk"]]],
            "tclx": [["tcl:tk_toolkit", ["sourceforge.net/tcl"]]],
        }
        product, why = CpeRule.match(index, ["tk-other"], ["https://sourceforge.net/projects/tcl/"])
        assert product is None and "more than one" in why


class TestDotJs:
    def test_node_is_node_js_on_its_site(self) -> None:
        index = {"nodejs": [["nodejs:node.js", ["nodejs.org", "github.com/nodejs/node"]]]}
        product, _ = CpeRule.match(
            index, ["node"], ["https://nodejs.org/dist/v20.17.0/node-v20.17.0.tar.xz"]
        )
        assert product == "nodejs:node.js"
        assert CpeRule.match(index, ["node"], ["https://example.org/"])[0] is None


class TestOneVendorsNamesOnASite:
    def test_node_js_and_nodejs(self) -> None:
        index = {
            "nodejs": [
                ["nodejs:node.js", ["github.com/nodejs/node", "nodejs.org"]],
                ["nodejs:nodejs", ["nodejs.org"]],
            ]
        }
        product, why = CpeRule.match(
            index,
            ["node"],
            [
                "https://nodejs.org/dist/v23.2.0/node-v23.2.0.tar.xz",
                "https://github.com/nodejs/node",
            ],
        )
        assert product == "nodejs:node.js nodejs:nodejs" and "nodejs.org" in why

    def test_names_on_a_common_site_are_one_product_whatever_the_vendor(self) -> None:
        index = {
            "curl": [
                ["curl:curl", ["haxx.se", "github.com/curl/curl"]],
                ["haxx:curl", ["haxx.se"]],
                ["daniel_stenberg:curl", ["haxx.se", "secunia.com"]],
            ]
        }
        product, _ = CpeRule.match(
            index,
            ["curl"],
            ["https://curl.haxx.se/download/curl-8.4.0.tar.bz2", "https://github.com/curl/curl"],
        )
        assert product == "curl:curl daniel_stenberg:curl haxx:curl"

    def test_products_with_no_common_site_stay_ambiguous(self) -> None:
        index = {"tool": [["a:tool", ["a.example"]], ["b:tool", ["b.example"]]]}
        product, _ = CpeRule.match(index, ["tool"], ["https://a.example/", "https://b.example/"])
        assert product is None
