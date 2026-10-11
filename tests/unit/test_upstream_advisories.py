"""Advisories matched through a package's upstream (`intel/upstream_advisories`).

Offline: each ecosystem's source is stood in with the response it really served when this was
written (BCR's zlib 1.3.1 source.json, the jq formula, the hashicorp/random provider record, a
Conan Center recipe export), and OSV with a fixed answer. What is tested is what the module
decides: which upstream a package names, and that anything it cannot name exactly is unchecked,
with a reason -- never guessed.
"""

from __future__ import annotations

import io
import json
import tarfile
from typing import ClassVar

import pytest

from cordon_scanner.core.models import Dependency
from cordon_scanner.intel.upstream_advisories import (
    RepositoryArchive,
    Unnamed,
    Upstream,
    UpstreamAdvisories,
    Upstreams,
)


class Stand:
    """The network: what each URL serves."""

    @staticmethod
    def dep(ecosystem: str, name: str, version: str | None, **fields: object) -> Dependency:
        return Dependency(
            purl=f"pkg:{ecosystem}/{name}@{version}",
            ecosystem=ecosystem,
            name=name,
            version=version,
            direct=True,
            **fields,  # type: ignore[arg-type]
        )

    @staticmethod
    def serve(monkeypatch, pages: dict[str, bytes]) -> list[str]:
        asked: list[str] = []

        def get(url: str, limit: int = 0) -> bytes:
            asked.append(url)
            if url not in pages:
                raise OSError(f"not served: {url}")
            return pages[url]

        monkeypatch.setattr(Upstreams, "_get", staticmethod(get))
        monkeypatch.setattr(UpstreamAdvisories, "_cache", {})
        monkeypatch.setattr(UpstreamAdvisories, "_records", {})
        return asked


class TestRepositoryArchive:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            (
                "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz",
                ("https://github.com/madler/zlib", "v1.3.1"),
            ),
            (
                "https://github.com/fmtlib/fmt/archive/refs/tags/10.2.1.tar.gz",
                ("https://github.com/fmtlib/fmt", "10.2.1"),
            ),
            (
                "https://github.com/a/b/archive/0123456789abcdef0123456789abcdef01234567.zip",
                ("https://github.com/a/b", "0123456789abcdef0123456789abcdef01234567"),
            ),
            (
                "https://codeload.github.com/a/b/tar.gz/refs/tags/v2.0",
                ("https://github.com/a/b", "v2.0"),
            ),
            (
                "https://gitlab.com/group/sub/proj/-/archive/v1.0/proj-v1.0.tar.gz",
                ("https://gitlab.com/group/sub/proj", "v1.0"),
            ),
            (
                "https://gitlab.freedesktop.org/libopenraw/exempi/-/archive/2.6.6/exempi-2.6.6.tar.gz",
                ("https://gitlab.freedesktop.org/libopenraw/exempi", "2.6.6"),
            ),
            (
                "https://gitlab.arm.com/bazel/download_utils/-/releases/v1.0.1/downloads/src.tar.gz",
                ("https://gitlab.arm.com/bazel/download_utils", "v1.0.1"),
            ),
        ],
    )
    def test_the_forges_fixed_forms(self, url: str, expected: tuple[str, str]) -> None:
        assert RepositoryArchive.parse(url) == expected

    @pytest.mark.parametrize(
        "url",
        [
            "https://zlib.net/fossils/zlib-1.2.11.tar.gz",  # a project's own site
            "https://github.com/a/b/archive/refs/heads/main.tar.gz",  # a branch moves
            "https://example.com/github.com/a/b/archive/v1.tar.gz",
        ],
    )
    def test_anything_else_names_nothing(self, url: str) -> None:
        assert RepositoryArchive.parse(url) is None

    def test_a_commit_is_asked_by_itself_and_a_tag_with_its_repository(self) -> None:
        commit = RepositoryArchive.upstream("https://github.com/a/b", "a" * 40, "x")
        tag = RepositoryArchive.upstream("https://github.com/a/b", "v1.0", "x")
        assert commit.query == {"commit": "a" * 40}
        assert tag.query == {
            "package": {"name": "https://github.com/a/b", "ecosystem": "GIT"},
            "version": "v1.0",
        }


class TestEachEcosystemsSource:
    def test_bazel_reads_bcrs_source_json(self, monkeypatch) -> None:
        Stand.serve(
            monkeypatch,
            {
                "https://bcr.bazel.build/modules/zlib/1.3.1/source.json": json.dumps(
                    {
                        "url": "https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz",
                        "strip_prefix": "zlib-1.3.1",
                    }
                ).encode()
            },
        )
        found = UpstreamAdvisories.name(Stand.dep("bazel", "zlib", "1.3.1"))
        assert isinstance(found, Upstream)
        assert found.query["version"] == "v1.3.1"

    def test_conan_reads_the_locked_recipe_revisions_export(self, monkeypatch) -> None:
        data = (
            b"sources:\n  1.3.1:\n    url:\n    - https://zlib.net/fossils/zlib-1.3.1.tar.gz\n"
            b"    - https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz\n"
        )
        export = io.BytesIO()
        with tarfile.open(fileobj=export, mode="w:gz") as archive:
            member = tarfile.TarInfo("conandata.yml")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        rrev = "cac0f6daea041b0ccf42934163defb20"
        asked = Stand.serve(
            monkeypatch,
            {
                f"https://center2.conan.io/v2/conans/zlib/1.3.1/_/_/revisions/{rrev}/files/conan_export.tgz": export.getvalue()
            },
        )
        found = UpstreamAdvisories.name(
            Stand.dep("conan", "zlib", "1.3.1", integrity=f"md5:{rrev}")
        )
        assert isinstance(found, Upstream)
        assert found.query["package"]["name"] == "https://github.com/madler/zlib"
        assert all("revisions/" + rrev in url for url in asked)

    def test_homebrew_reads_the_formula_the_api_names_checked_by_its_digest(
        self, monkeypatch
    ) -> None:
        import hashlib

        head = "b985925c2dedad9f2feaeda825d9a57875182813"
        # curl's formula: the stable URL is the project's own site; a mirror is GitHub's asset.
        text = (
            b"class Curl < Formula\n"
            b'  url "https://curl.se/download/curl-8.0.0.tar.bz2"\n'
            b'  mirror "https://github.com/curl/curl/releases/download/curl-8_0_0/curl-8.0.0.tar.bz2"\n'
            b'  sha256 "dd6e792593dbd2253cc2da57265808427e3614e84ca86d424fbc75cf9baba08c"\n'
            b"  def install\n"
            b"    args << if OS.mac?\n"
            b'      "--with-gssapi"\n'
            b"    else\n"
            b'      "--without-gssapi"\n'
            b"    end\n"
            b"  end\n"
            b"end\n"
        )

        def api(digest: str) -> bytes:
            return json.dumps(
                {
                    "versions": {"stable": "8.0.0"},
                    "tap_git_head": head,
                    "ruby_source_path": "Formula/c/curl.rb",
                    "ruby_source_checksum": {"sha256": digest},
                }
            ).encode()

        raw = f"https://raw.githubusercontent.com/Homebrew/homebrew-core/{head}/Formula/c/curl.rb"
        Stand.serve(
            monkeypatch,
            {
                "https://formulae.brew.sh/api/formula/curl.json": api(
                    hashlib.sha256(text).hexdigest()
                ),
                raw: text,
            },
        )
        found = UpstreamAdvisories.name(Stand.dep("homebrew", "curl", "8.0.0_1"))
        assert isinstance(found, Upstream)
        assert found.query["package"]["name"] == "https://github.com/curl/curl"
        assert found.query["version"] == "curl-8_0_0"

        Stand.serve(
            monkeypatch,
            {"https://formulae.brew.sh/api/formula/curl.json": api("0" * 64), raw: text},
        )
        tampered = UpstreamAdvisories.name(Stand.dep("homebrew", "curl", "8.0.0"))
        assert isinstance(tampered, Unnamed) and "SHA-256" in tampered.reason

    def test_a_cask_is_not_a_formula(self, monkeypatch) -> None:
        Stand.serve(monkeypatch, {})
        found = UpstreamAdvisories.name(
            Stand.dep("homebrew", "docker", "4.30.0", platform=("cask",))
        )
        assert isinstance(found, Unnamed) and "a cask" in found.reason

    def test_terraform_providers_are_go_modules(self, monkeypatch) -> None:
        Stand.serve(
            monkeypatch,
            {
                "https://registry.terraform.io/v1/providers/hashicorp/random": json.dumps(
                    {"source": "https://github.com/hashicorp/terraform-provider-random"}
                ).encode()
            },
        )
        found = UpstreamAdvisories.name(Stand.dep("terraform", "hashicorp/random", "3.6.0"))
        assert isinstance(found, Upstream)
        assert found.query == {
            "package": {
                "name": "github.com/hashicorp/terraform-provider-random",
                "ecosystem": "Go",
            },
            "version": "3.6.0",
        }

    def test_a_terraform_module_is_not_a_provider(self, monkeypatch) -> None:
        Stand.serve(monkeypatch, {})
        found = UpstreamAdvisories.name(
            Stand.dep("terraform", "terraform-aws-modules/vpc/aws", "5.0.0")
        )
        assert isinstance(found, Unnamed)

    def test_nix_asks_by_the_locked_commit(self, monkeypatch) -> None:
        Stand.serve(monkeypatch, {})
        found = UpstreamAdvisories.name(Stand.dep("nix", "madler/zlib", "c" * 40))
        assert isinstance(found, Upstream) and found.query == {"commit": "c" * 40}

    def test_a_source_that_cannot_be_read_leaves_it_unchecked(self, monkeypatch) -> None:
        Stand.serve(monkeypatch, {})
        found = UpstreamAdvisories.name(Stand.dep("bazel", "zlib", "1.3.1"))
        assert isinstance(found, Unnamed) and "could not be read" in found.reason


class TestTheCheck:
    def test_what_osv_names_becomes_an_advisory_saying_how_it_was_matched(
        self, monkeypatch
    ) -> None:
        Stand.serve(
            monkeypatch,
            {
                "https://api.osv.dev/v1/vulns/CVE-2018-25032": json.dumps(
                    {
                        "id": "CVE-2018-25032",
                        "summary": "zlib before 1.2.12 allows memory corruption",
                    }
                ).encode()
            },
        )
        monkeypatch.setattr(
            UpstreamAdvisories,
            "_post",
            staticmethod(lambda url, body: {"results": [{"vulns": [{"id": "CVE-2018-25032"}]}]}),
        )
        dependency = Stand.dep("nix", "madler/zlib", "c" * 40)
        result = UpstreamAdvisories.check([dependency])
        assert dependency.purl in result.checked
        (advisory,) = result.advisories[dependency.purl]
        assert advisory.identifier == "CVE-2018-25032"
        assert advisory.affects("c" * 40)
        assert "Matched through its locked commit" in advisory.summary

    def test_when_osv_cannot_be_asked_nothing_counts_as_checked(self, monkeypatch) -> None:
        Stand.serve(monkeypatch, {})

        def fail(url, body):
            raise OSError("unreachable")

        monkeypatch.setattr(UpstreamAdvisories, "_post", staticmethod(fail))
        dependency = Stand.dep("nix", "madler/zlib", "c" * 40)
        result = UpstreamAdvisories.check([dependency])
        assert result.checked == set()
        assert "OSV could not be asked" in result.unchecked[dependency.purl]


class TestTheDetector:
    """The advisory detector: what is matched through an upstream is checked and reported; what
    is not is named in the no-feed notice, with why."""

    @staticmethod
    def run(dependencies: tuple[Dependency, ...], *, offline: bool) -> list[tuple[str, str]]:
        from cordon_scanner.core.config import Config
        from cordon_scanner.detect.advisory import AdvisoryDetector
        from cordon_scanner.detect.base import GraphUnit, ScanContext
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        ctx = ScanContext(
            config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()), offline=offline
        )
        return [
            (f.rule_id, f.message)
            for f in AdvisoryDetector().inspect(GraphUnit(dependencies=dependencies), ctx)
        ]

    def test_offline_the_notice_says_online_would_check_them(self) -> None:
        found = self.run((Stand.dep("nix", "madler/zlib", "c" * 40),), offline=True)
        (message,) = [m for rule, m in found if rule == "OPERATIONAL.ADVISORY.NO_FEED.001"]
        assert "With --online, nix packages are matched through the upstream" in message

    def test_online_a_matched_package_is_reported_and_not_named_unchecked(
        self, monkeypatch
    ) -> None:
        Stand.serve(
            monkeypatch,
            {
                "https://api.osv.dev/v1/vulns/CVE-2018-25032": json.dumps(
                    {"id": "CVE-2018-25032", "summary": "zlib memory corruption"}
                ).encode()
            },
        )
        monkeypatch.setattr(
            UpstreamAdvisories,
            "_post",
            staticmethod(lambda url, body: {"results": [{"vulns": [{"id": "CVE-2018-25032"}]}]}),
        )
        found = self.run((Stand.dep("nix", "madler/zlib", "c" * 40),), offline=False)
        rules = [rule for rule, _ in found]
        assert "OPERATIONAL.ADVISORY.NO_FEED.001" not in rules
        assert any("CVE-2018-25032" in message for _, message in found)

    def test_online_an_unnamed_package_is_named_with_why(self, monkeypatch) -> None:
        Stand.serve(monkeypatch, {})
        found = self.run((Stand.dep("nix", "x/y", "not-a-commit"),), offline=False)
        (message,) = [m for rule, m in found if rule == "OPERATIONAL.ADVISORY.NO_FEED.001"]
        assert "it is locked to no git commit" in message


class TestTagInference:
    """The inference used where nothing names a version's tag: only in the repository the
    ecosystem names, only a tag spelled as the version, and only when those tags agree."""

    @pytest.mark.parametrize(
        ("given", "expected"),
        [
            ("github:madler/zlib", "https://github.com/madler/zlib"),
            ("https://github.com/git/git.git", "https://github.com/git/git"),
            (
                "https://gitlab.gnome.org/GNOME/libxml2/-/wikis/home",
                "https://gitlab.gnome.org/GNOME/libxml2",
            ),
            (
                "https://git.savannah.gnu.org/git/wget.git",
                "https://git.savannah.gnu.org/git/wget.git",
            ),
            ("https://zlib.net", None),  # a project's site is not a repository
            ("https://ftp.gnu.org/gnu/gawk/", None),
        ],
    )
    def test_only_a_repository_is_a_repository(self, given: str, expected: str | None) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        assert TagInference.repository(given) == expected

    @staticmethod
    def tags(monkeypatch, tags: dict[str, str]) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        monkeypatch.setattr(TagInference, "refs", staticmethod(lambda repository: tags))

    def test_the_one_tag_spelled_as_the_version_is_asked_by_its_commit(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        self.tags(monkeypatch, {"v1.25.0": "a" * 40, "v1.25.1": "b" * 40, "latest": "c" * 40})
        found = TagInference.infer("https://example.invalid/wget.git", "1.25.0", ("wget",), "x")
        assert isinstance(found, Upstream)
        assert found.query == {"commit": "a" * 40}
        assert "inferred: the tag v1.25.0" in found.how

    def test_tags_that_disagree_are_not_chosen_between(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        self.tags(monkeypatch, {"1.0": "a" * 40, "v1.0": "b" * 40})
        found = TagInference.infer("https://example.invalid/r.git", "1.0", (), "x")
        assert isinstance(found, Unnamed) and "different commits" in found.reason

    def test_two_spellings_of_one_commit_agree(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        self.tags(monkeypatch, {"1.0": "a" * 40, "v1.0": "a" * 40})
        found = TagInference.infer("https://example.invalid/r.git", "1.0", (), "x")
        assert isinstance(found, Upstream) and found.query == {"commit": "a" * 40}

    def test_no_tag_spelled_as_the_version_is_no_guess(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        self.tags(monkeypatch, {"curl-8_0_1": "a" * 40, "8.0.1": "b" * 40, "8.0.0-rc1": "c" * 40})
        found = TagInference.infer("https://example.invalid/curl.git", "8.0.0", ("curl",), "x")
        assert isinstance(found, Unnamed) and "no tag spelled as version 8.0.0" in found.reason

    def test_dots_written_as_underscores_are_the_same_version(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        # curl tags `curl-8_0_0`; a tag spelled otherwise naming another commit would refuse it.
        self.tags(monkeypatch, {"curl-8_0_0": "a" * 40})
        found = TagInference.infer("https://example.invalid/curl.git", "8.0.0", ("curl",), "x")
        assert isinstance(found, Upstream) and found.query == {"commit": "a" * 40}
        self.tags(monkeypatch, {"curl-8_0_0": "a" * 40, "v8.0.0": "b" * 40})
        assert isinstance(
            TagInference.infer("https://example.invalid/curl.git", "8.0.0", ("curl",), "x"), Unnamed
        )

    def test_an_exact_upstream_is_never_replaced_by_an_inferred_one(self, monkeypatch) -> None:
        exact = Upstream({"commit": "a" * 40}, "exact")
        self.tags(monkeypatch, {"1.0": "b" * 40})
        assert Upstreams.inferred(exact, ["https://github.com/a/b"], "1.0", (), "x") is exact


class TestConfidence:
    """A record about the package itself is confirmed; one matched through its upstream is high;
    one matched through an inferred tag is medium -- still at the default gate, set apart."""

    @pytest.mark.parametrize(
        ("matched_through", "expected"),
        [("", "CONFIRMED"), ("upstream", "HIGH"), ("inferred", "MEDIUM")],
    )
    def test_how_it_was_matched_sets_the_confidence(self, matched_through, expected) -> None:
        from cordon_scanner.core.config import Config
        from cordon_scanner.detect.advisory import AdvisoryDetector
        from cordon_scanner.detect.base import ScanContext
        from cordon_scanner.intel.advisories import Advisory
        from cordon_scanner.rules.loader import RuleLoader, RuleSet

        dependency = Stand.dep("bazel", "zlib", "1.2.11")
        advisory = Advisory(
            ecosystem="bazel",
            name="zlib",
            versions=("1.2.11",),
            summary="zlib memory corruption",
            identifier="CVE-2018-25032",
            severity="high",
            matched_through=matched_through,
        )
        ctx = ScanContext(config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()))
        finding = AdvisoryDetector()._finding(dependency, advisory, ctx)
        assert finding.confidence.name == expected


class TestVcpkgPortfiles:
    """A portfile read as CMake reads it: what real ports in vcpkg's registry write."""

    @staticmethod
    def read(portfile: str, version: str, port: str) -> Upstream | Unnamed:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        return VcpkgPorts.source(portfile, version, port, "x")

    def test_7zips_regex_replace_and_escaped_dollar(self) -> None:
        found = self.read(
            'string(REGEX REPLACE "[.]([0-9])\\$" ".0\\\\1" upstream_version "${VERSION}")\n'
            'vcpkg_from_github(OUT_SOURCE_PATH S REPO ip7z/7zip REF "${upstream_version}" '
            "SHA512 0 HEAD_REF main)\n",
            "25.1",
            "7zip",
        )
        assert isinstance(found, Upstream) and found.query["version"] == "25.01"

    def test_a_bracket_argument_is_taken_as_written(self) -> None:
        found = self.read(
            "string(REGEX MATCH [[^[0-9][0-9]*\\.[1-9][0-9]*]] MM ${VERSION})\n"
            'vcpkg_download_distfile(A URLS "https://github.com/o/r/archive/refs/tags/v${MM}.tar.gz" '
            "FILENAME f SHA512 0)\n",
            "2.38.0",
            "p",
        )
        assert isinstance(found, Upstream) and found.query["version"] == "v2.38"

    def test_a_gitlab_url_with_a_group(self) -> None:
        found = self.read(
            "vcpkg_from_gitlab(GITLAB_URL https://gitlab.com/inivation OUT_SOURCE_PATH S "
            'REPO dv/dv-processing REF "${VERSION}" HEAD_REF master)\n',
            "1.7.9",
            "dv-processing",
        )
        assert isinstance(found, Upstream)
        assert found.query["package"]["name"] == "https://gitlab.com/inivation/dv/dv-processing"

    def test_the_first_unconditional_fetch_is_the_source(self) -> None:
        # amd-amf downloads its licence after its headers.
        found = self.read(
            'vcpkg_download_distfile(A URLS "https://github.com/o/amf/releases/download/v${VERSION}/h.tar.gz" '
            "FILENAME h SHA512 0)\n"
            'vcpkg_download_distfile(L URLS "https://example.invalid/LICENSE.txt" FILENAME l SHA512 0)\n',
            "1.4",
            "amd-amf",
        )
        assert isinstance(found, Upstream) and found.query["version"] == "v1.4"

    def test_conditional_fetches_count_only_when_they_agree(self) -> None:
        same = (
            'if("tao" IN_LIST FEATURES)\n'
            '  vcpkg_from_github(OUT_SOURCE_PATH S REPO o/r REF "v${VERSION}" SHA512 0)\n'
            "else()\n"
            '  vcpkg_from_github(OUT_SOURCE_PATH S REPO o/r REF "v${VERSION}" SHA512 0)\n'
            "endif()\n"
        )
        assert isinstance(self.read(same, "1.0", "ace"), Upstream)
        differ = same.replace("REPO o/r REF", "REPO o/other REF", 1)
        found = self.read(differ, "1.0", "ace")
        assert isinstance(found, Unnamed) and "by platform or feature" in found.reason

    def test_an_empty_port_has_nothing_to_check(self) -> None:
        found = self.read("SET(VCPKG_POLICY_EMPTY_PACKAGE enabled)\n", "1.0", "atl")
        assert isinstance(found, Unnamed) and found.nothing

    def test_a_qt_module_is_proved_or_inferred_from_its_port_data(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference, VcpkgPorts

        data = (
            'set(qtsvg_HASH "' + "a" * 128 + '")\n'
            'set(qtsvg_URL "https://download.qt.io/qtsvg-everywhere-src-6.11.2.tar.xz")\n'
        )
        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"v6.11.2": "c" * 40})
        )
        monkeypatch.setattr(
            "cordon_scanner.intel.upstream_advisories.ContentProof.check",
            staticmethod(lambda archive, repository, commit, tag="": ("unprovable", "stood in")),
        )
        found = VcpkgPorts.qt("qtsvg", "6.11.2", lambda filename: data, "x")
        assert isinstance(found, Upstream) and found.inferred
        assert found.query == {"commit": "c" * 40}


class TestHomebrewTaps:
    def test_a_tap_locked_to_a_commit_is_that_commit(self, monkeypatch) -> None:
        Stand.serve(monkeypatch, {})
        found = UpstreamAdvisories.name(Stand.dep("homebrew", "buo/cask-upgrade", "e" * 40))
        assert isinstance(found, Upstream) and found.query == {"commit": "e" * 40}

    def test_an_old_version_without_a_bottle_is_inferred_from_the_formulas_repository(
        self, monkeypatch
    ) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewBottles, TagInference

        head = "b" * 40
        formula = b'class Bat < Formula\n  url "https://github.com/sharkdp/bat/archive/refs/tags/v0.26.0.tar.gz"\n  head "https://github.com/sharkdp/bat.git", branch: "master"\nend\n'
        api = json.dumps(
            {
                "versions": {"stable": "0.26.0"},
                "tap_git_head": head,
                "ruby_source_path": "Formula/b/bat.rb",
            }
        ).encode()
        Stand.serve(
            monkeypatch,
            {
                "https://formulae.brew.sh/api/formula/bat.json": api,
                f"https://raw.githubusercontent.com/Homebrew/homebrew-core/{head}/Formula/b/bat.rb": formula,
            },
        )

        def no_bottle(name, version):
            raise OSError("no such bottle")

        monkeypatch.setattr(HomebrewBottles, "formula", staticmethod(no_bottle))
        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"v0.12.1": "d" * 40})
        )
        found = UpstreamAdvisories.name(Stand.dep("homebrew", "bat", "0.12.1"))
        assert isinstance(found, Upstream) and found.inferred
        assert found.query == {"commit": "d" * 40}


class TestConanCenterSources:
    def test_a_binary_tools_sources_keyed_by_platform(self) -> None:
        from cordon_scanner.intel.upstream_advisories import ConanCenter

        source = {
            "Linux": {
                "armv8": {
                    "sha256": "a" * 64,
                    "url": [
                        "https://cmake.org/files/v3.31/cmake-3.31.12-linux-aarch64.tar.gz",
                        "https://github.com/Kitware/CMake/releases/download/v3.31.12/cmake-3.31.12-linux-aarch64.tar.gz",
                    ],
                },
                "x86_64": {
                    "sha256": "b" * 64,
                    "url": "https://github.com/Kitware/CMake/releases/download/v3.31.12/cmake-3.31.12-linux-x86_64.tar.gz",
                },
            }
        }
        urls, archive = ConanCenter.leaves(source)
        assert len(urls) == 3 and archive is not None and archive.digest == "sha256:" + "a" * 64
        found = ConanCenter.exact(urls, "x")
        assert isinstance(found, Upstream) and found.query["version"] == "v3.31.12"

    def test_sources_naming_different_tags_are_not_one_upstream(self) -> None:
        from cordon_scanner.intel.upstream_advisories import ConanCenter

        found = ConanCenter.exact(
            [
                "https://github.com/o/r/archive/refs/tags/v1.0.tar.gz",
                "https://github.com/o/r/archive/refs/tags/v1.1.tar.gz",
            ],
            "x",
        )
        assert isinstance(found, Unnamed)

    def test_a_tag_with_underscores_for_dots_is_the_version(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"v3_2_2": "f" * 40})
        )
        found = Upstreams.inferred(
            Unnamed("x"), ["https://github.com/ruby/ruby"], "3.2.2", ("ruby",), "x"
        )
        assert isinstance(found, Upstream) and found.query == {"commit": "f" * 40}


class TestCocoaPodsCheckouts:
    @staticmethod
    def pod(resolved_from: str) -> Dependency:
        return Dependency(
            # name() keeps one answer per package: each case is its own.
            purl=f"pkg:cocoapods/X{len(resolved_from)}@1.0",
            ecosystem="cocoapods",
            name=f"X{len(resolved_from)}",
            version="1.0",
            direct=True,
            resolved_from=resolved_from,
        )

    def test_a_commit_checkout_is_exact(self) -> None:
        found = UpstreamAdvisories.name(self.pod("git+https://github.com/o/r.git#" + "c" * 40))
        assert isinstance(found, Upstream) and found.query == {"commit": "c" * 40}

    def test_a_tag_checkout_is_exact_once_the_repository_shows_the_tag(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"1.0": "d" * 40})
        )
        found = UpstreamAdvisories.name(self.pod("git+https://github.com/o/r.git#1.0"))
        assert isinstance(found, Upstream) and found.query["version"] == "1.0"
        branch = UpstreamAdvisories.name(self.pod("git+https://github.com/o/r.git#main"))
        assert isinstance(branch, Unnamed) and "not a tag" in branch.reason


class TestCMakeArguments:
    def test_nested_parentheses_separate_arguments_and_end(self) -> None:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        assert VcpkgPorts._arguments('A AND (B OR "C") ( )', {}) == ["A", "AND", "B", "OR", "C"]


class TestMoreSourceHosts:
    def test_one_file_at_a_commit_is_that_commit(self) -> None:
        from cordon_scanner.intel.upstream_advisories import RepositoryArchive

        sha = "8e729daa702d45597ccffa0c964bba1eca10a9e6"
        for url in (
            f"https://github.com/KhronosGroup/OpenGL-Registry/raw/{sha}/api/GL/glext.h",
            f"https://raw.githubusercontent.com/KhronosGroup/OpenGL-Registry/{sha}/api/GL/glext.h",
        ):
            assert RepositoryArchive.parse(url) == (
                "https://github.com/KhronosGroup/OpenGL-Registry",
                sha,
            )
        # A branch is no fixed point.
        assert RepositoryArchive.parse("https://github.com/o/r/raw/main/x.h") is None

    def test_download_hosts_imply_repositories_to_prove_against(self) -> None:
        from cordon_scanner.intel.upstream_advisories import Conventions

        assert Conventions.repositories(
            ["https://archive.apache.org/dist/apr/apr-1.7.6.tar.bz2"]
        ) == ["https://github.com/apache/apr"]
        assert Conventions.repositories(
            ["https://www.netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2"]
        ) == ["https://git.netfilter.org/libmnl"]
        assert Conventions.repositories(
            ["http://ftp.gnome.org/pub/gnome/sources/at-spi2-atk/2.38/at-spi2-atk-2.38.0.tar.xz"]
        ) == ["https://gitlab.gnome.org/GNOME/at-spi2-atk"]
        assert Conventions.repositories(
            ["https://prdownloads.sourceforge.net/argtable/argtable2-13.tar.gz"]
        ) == [
            "https://git.code.sf.net/p/argtable/code",
            "https://git.code.sf.net/p/argtable/git",
        ]


class TestConanRemovedVersions:
    def test_a_version_the_index_still_lists_is_read_from_its_data(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import ConanCenter

        monkeypatch.setattr(
            ConanCenter,
            "index",
            staticmethod(
                lambda name: {
                    "1.0": {
                        "url": "https://github.com/o/r/archive/refs/tags/v1.0.tar.gz",
                        "sha256": "a" * 64,
                    },
                    "2.0": {
                        "url": "https://github.com/o/r/archive/refs/tags/v2.0.tar.gz",
                        "sha256": "b" * 64,
                    },
                }
            ),
        )
        found = ConanCenter.removed("r", "1.0")
        assert isinstance(found, Upstream) and found.query["version"] == "v1.0"


class TestGoRelease:
    def test_gos_source_release_is_the_standard_library(self) -> None:
        from cordon_scanner.intel.upstream_advisories import RegistryArchive

        assert RegistryArchive.parse("https://go.dev/dl/go1.23.3.src.tar.gz") == (
            "Go",
            "stdlib",
            "1.23.3",
        )
        assert RegistryArchive.parse("https://dl.google.com/go/go1.20.src.tar.gz") == (
            "Go",
            "stdlib",
            "1.20.0",
        )
        assert RegistryArchive.parse("https://go.dev/dl/go1.22rc1.src.tar.gz") is None


class TestCocoaPodsItself:
    def test_the_cocoapods_line_is_the_rubygem(self) -> None:
        from cordon_scanner.core.models import Scope

        found = UpstreamAdvisories.name(
            Dependency(
                purl="pkg:cocoapods/cocoapods@1.7.5",
                ecosystem="cocoapods",
                name="cocoapods",
                version="1.7.5",
                direct=True,
                scope=Scope.TOOL,
            )
        )
        assert isinstance(found, Upstream)
        assert found.query == {
            "package": {"name": "cocoapods", "ecosystem": "RubyGems"},
            "version": "1.7.5",
        }


class TestQtBeforePortData:
    DETAILS = "set(QT_VERSION 6.8.2)\nset(QT_FROM_GITHUB qtcoap qtopcua qtmqtt)\n"
    DATA = 'set(qtsvg_HASH "' + "a" * 128 + '")\n'

    def qtbase(self, filename: str) -> str:
        return self.DETAILS if filename.endswith("details.cmake") else self.DATA

    @staticmethod
    def missing(filename: str) -> str:
        raise OSError("404")

    def test_a_module_mirrored_on_github_is_its_tag(self) -> None:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        found = VcpkgPorts.qt("qtmqtt", "6.8.2", self.missing, "x", self.qtbase)
        assert isinstance(found, Upstream)
        assert found.query == {
            "package": {"name": "https://github.com/qt/qtmqtt", "ecosystem": "GIT"},
            "version": "v6.8.2",
        }

    def test_a_release_module_is_proved_by_its_digest(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import Archive, Upstreams, VcpkgPorts

        seen: list[Archive | None] = []

        def inferred(first, homes, version, names, how, archive=None):
            seen.append(archive)
            return first

        monkeypatch.setattr(Upstreams, "inferred", staticmethod(inferred))
        VcpkgPorts.qt("qtsvg", "6.8.2", self.missing, "x", self.qtbase)
        assert seen[0] is not None and seen[0].digest == "sha512:" + "a" * 128
        assert (
            "https://download.qt.io/archive/qt/6.8/6.8.2/submodules/qtsvg-everywhere-src-6.8.2.tar.xz"
            in seen[0].urls
        )

    def test_another_qt_version_than_the_baselines_is_not_read(self) -> None:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        found = VcpkgPorts.qt("qtsvg", "6.7.0", self.missing, "x", self.qtbase)
        assert isinstance(found, Unnamed) and "no Qt 6.7.0" in found.reason


class TestHomebrewAliases:
    API = "https://formulae.brew.sh/api/formula"
    CORE = "https://raw.githubusercontent.com/Homebrew/homebrew-core/HEAD"

    @staticmethod
    def registry(monkeypatch, pages: dict[str, bytes]) -> None:
        """What a registry serves; anything else is its 404, PackageNotFound."""
        from cordon_scanner.intel.registry_client import PackageNotFound

        def get(url: str, limit: int = 0) -> bytes:
            if url not in pages:
                raise PackageNotFound(f"no such page: {url}")
            return pages[url]

        monkeypatch.setattr(Upstreams, "_get", staticmethod(get))

    def test_an_alias_is_followed_to_the_installed_versions_series(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewBottles

        record = json.dumps({"versions": {"stable": "3.13.9"}}).encode()
        self.registry(
            monkeypatch,
            {
                f"{self.CORE}/Aliases/python3": b"../Formula/p/python@3.15.rb",
                f"{self.API}/python@3.13.json": record,
                f"{self.API}/python@3.15.json": record,
            },
        )
        found = HomebrewBottles.formula_data("python3", "3.13.0_1")
        assert not isinstance(found, Unnamed) and found[0] == "python@3.13"

    def test_a_formula_homebrew_no_longer_has_is_said_so(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewBottles

        HomebrewBottles._renames = None
        self.registry(monkeypatch, {f"{self.CORE}/formula_renames.json": b'{"annie": "lux"}'})
        found = HomebrewBottles.formula_data("exa", "0.9.0")
        assert isinstance(found, Unnamed) and "no longer has this formula" in found.reason


class TestHomebrewHistory:
    COMMITS = "https://api.github.com/repos/Homebrew/homebrew-core/commits"
    RAW = "https://raw.githubusercontent.com/Homebrew/homebrew-core"
    DIGEST = "c4dd2e8a36d2e4487d9d8c483d42be8b2aa3c5a0a326c10b35aeca82fccd8c0f"
    FORMULA = (
        "class Exa < Formula\n"
        '  homepage "https://the.exa.website"\n'
        '  url "https://github.com/ogham/exa/archive/v0.9.0.tar.gz"\n'
        f'  sha256 "{"1" * 64}"\n'
        "  bottle do\n"
        f'    sha256 "{DIGEST}" => :catalina\n'
        "  end\n"
        "end\n"
    )

    def serve(
        self, monkeypatch, commits: dict[str, list[dict]], files: dict[str, bytes]
    ) -> list[str]:
        from cordon_scanner.intel.homebrew_provenance import HomebrewProvenance
        from cordon_scanner.intel.registry_client import PackageNotFound

        asked: list[str] = []

        def api(url: str) -> object:
            asked.append(url)
            return commits.get(url, [])

        def get(url: str, limit: int = 0) -> bytes:
            asked.append(url)
            if url not in files:
                raise PackageNotFound(url)
            return files[url]

        monkeypatch.setattr(HomebrewProvenance, "_get", staticmethod(api))
        monkeypatch.setattr(Upstreams, "_get", staticmethod(get))
        return asked

    @staticmethod
    def commit(sha: str, message: str) -> dict:
        return {"sha": sha * 40, "commit": {"message": message}}

    def test_the_revision_holding_the_bottle_digest_is_the_formula(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewHistory

        path = f"{self.COMMITS}?path=Formula/exa.rb&per_page=100&page=1"
        asked = self.serve(
            monkeypatch,
            {
                path: [
                    self.commit("a", "exa: delete"),
                    self.commit("b", "exa: update 0.9.0 bottle."),
                    self.commit("c", "exa 0.9.0"),
                    self.commit("d", "exa: update 0.9.0_1 bottle."),
                ]
            },
            {
                f"{self.RAW}/{'b' * 40}/Formula/exa.rb": self.FORMULA.encode(),
                f"{self.RAW}/{'c' * 40}/Formula/exa.rb": self.FORMULA.replace(
                    self.DIGEST, "0" * 64
                ).encode(),
            },
        )
        found = HomebrewHistory.formula("exa", "0.9.0", self.DIGEST)
        assert found is not None and found[1] == "b" * 40 and found[2] == "Formula/exa.rb"
        # The deleting commit names no version, and another revision's bottle is not read.
        assert not any("a" * 40 in url or "d" * 40 in url for url in asked)

    def test_a_deleted_formula_is_read_from_the_history(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewBottles

        self.serve(
            monkeypatch,
            {
                f"{self.COMMITS}?path=Formula/exa.rb&per_page=100&page=1": [
                    self.commit("b", "exa: update 0.9.0 bottle.")
                ]
            },
            {f"{self.RAW}/{'b' * 40}/Formula/exa.rb": self.FORMULA.encode()},
        )
        monkeypatch.setattr(
            HomebrewBottles,
            "formula_data",
            staticmethod(
                lambda name, installed: Unnamed(
                    "Homebrew no longer has this formula, under this name or another"
                )
            ),
        )
        exa = Dependency(
            purl="pkg:brew/exa@0.9.0",
            ecosystem="homebrew",
            name="exa",
            version="0.9.0",
            direct=True,
            integrity=f"sha256:{self.DIGEST}",
        )
        answer = Upstreams.homebrew(exa)
        assert isinstance(answer, Upstream), answer
        assert "homebrew-core bbbbbbbbbbbb, which holds its bottle's digest" in answer.how

    def test_no_revision_with_the_digest_is_said_so(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewHistory

        self.serve(monkeypatch, {}, {})
        exa = Dependency(
            purl="pkg:brew/exa@0.9.0",
            ecosystem="homebrew",
            name="exa",
            version="0.9.0",
            direct=True,
            integrity=f"sha256:{self.DIGEST}",
        )
        answer = HomebrewHistory.upstream(exa, Unnamed("Homebrew no longer has this formula"))
        assert isinstance(answer, Unnamed) and "no revision of its formula" in answer.reason

    def test_without_a_digest_the_newest_revision_building_the_version(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewHistory

        path = f"{self.COMMITS}?path=Formula/exa.rb&per_page=100&page=1"
        revised = self.FORMULA.replace("  bottle do", "  revision 1\n  bottle do")
        self.serve(
            monkeypatch,
            {
                path: [
                    self.commit("a", "exa: revision bump (0.9.0_1)"),
                    self.commit("b", "exa: update 0.9.0 bottle."),
                ]
            },
            {
                f"{self.RAW}/{'a' * 40}/Formula/exa.rb": revised.encode(),
                f"{self.RAW}/{'b' * 40}/Formula/exa.rb": self.FORMULA.encode(),
            },
        )
        found = HomebrewHistory.formula("exa", "0.9.0", "")
        assert found is not None and found[1] == "b" * 40
        assert HomebrewHistory.builds(revised, "0.9.0_1")
        assert not HomebrewHistory.builds(revised, "0.9.0")
        assert not HomebrewHistory.builds(self.FORMULA, "0.9.1")

    def test_a_head_build_is_its_commit(self, monkeypatch) -> None:
        from cordon_scanner.intel.homebrew_provenance import HomebrewProvenance
        from cordon_scanner.intel.upstream_advisories import HomebrewBottles

        full = "6598940" + "c" * 33
        monkeypatch.setattr(
            HomebrewProvenance,
            "_get",
            staticmethod(lambda url: {"sha": full} if url.endswith("/commits/6598940") else {}),
        )
        data = {"urls": {"head": {"url": "https://github.com/nodenv/node-build.git"}}}
        found = HomebrewBottles.head(data, "HEAD-6598940", "node-build")
        assert isinstance(found, Upstream) and found.query == {"commit": full}
        assert isinstance(HomebrewBottles.head({}, "HEAD-6598940", "node-build"), Unnamed)

    def test_the_sharded_path(self) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewHistory

        assert HomebrewHistory.paths("cmake") == ("Formula/cmake.rb", "Formula/c/cmake.rb")
        assert HomebrewHistory.paths("libpng") == ("Formula/libpng.rb", "Formula/lib/libpng.rb")


class TestProtocolTwoRefs:
    def test_ls_refs_lists_tags_peeled(self, monkeypatch) -> None:
        import io as _io
        import urllib.request

        from cordon_scanner.intel.gitfetch import GitFetch
        from cordon_scanner.intel.upstream_advisories import TagInference

        answer = b"".join(
            [
                GitFetch._pkt(f"{'a' * 40} refs/tags/REL_14_5 peeled:{'b' * 40}\n"),
                GitFetch._pkt(f"{'c' * 40} refs/tags/REL_14_6\n"),
                b"0000",
            ]
        )
        asked: list[bytes] = []

        class Response(_io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc: object) -> None:
                return None

        def urlopen(request, timeout=0):
            asked.append(request.data)
            return Response(answer)

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)
        found = TagInference.ls_refs("https://git.postgresql.org/git/postgresql.git")
        assert found == {"REL_14_5": "b" * 40, "REL_14_6": "c" * 40}
        assert b"command=ls-refs" in asked[0] and b"ref-prefix refs/tags/" in asked[0]

    def test_postgresqls_tag_spelling(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"REL_14_5": "e" * 40})
        )
        found = TagInference.infer(
            "https://git.postgresql.org/git/postgresql.git", "14.5", ("postgresql",), "x"
        )
        assert isinstance(found, Upstream) and found.query == {"commit": "e" * 40}


class TestCondaInfoStream:
    def test_the_recipe_is_read_past_a_large_info_member(self) -> None:
        zstandard = pytest.importorskip("zstandard")
        from cordon_scanner.intel.upstream_advisories import CondaPackage

        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for name, data in (
                ("info/test/big.bin", b"\0" * (20 << 20)),
                ("info/recipe/meta.yaml", b"package:\n  name: x\n"),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        blob = zstandard.ZstdCompressor().compress(raw.getvalue())
        with tarfile.open(fileobj=CondaPackage._zstd_stream(blob), mode="r|") as archive:
            assert CondaPackage._from_tar(archive) == "package:\n  name: x\n"


class TestGnuProjectsElsewhere:
    def test_gnu_projects_not_on_savannah(self) -> None:
        from cordon_scanner.intel.upstream_advisories import Conventions

        assert Conventions.repositories(
            ["https://ftp.gnu.org/gnu/gcc/gcc-13.2.0/gcc-13.2.0.tar.gz"]
        )[0] == ("https://gcc.gnu.org/git/gcc.git")
        assert Conventions.repositories(["https://ftp.gnu.org/gnu/binutils/binutils-2.40.tar.bz2"])[
            0
        ] == ("https://sourceware.org/git/binutils-gdb.git")
        assert Conventions.repositories(["https://ftp.gnu.org/gnu/mpc/mpc-1.3.1.tar.gz"])[0] == (
            "https://gitlab.inria.fr/mpc/mpc.git"
        )

    def test_the_release_files_name_is_a_tag_prefix(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import Archive, ContentProof, TagInference

        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"releases/gcc-13.2.0": "f" * 40})
        )
        monkeypatch.setattr(
            ContentProof,
            "check",
            staticmethod(lambda archive, repository, commit, tag="": ("proven", "all files")),
        )
        url = "https://ftp.gnu.org/gnu/gcc/gcc-13.2.0/gcc-13.2.0.tar.gz"
        found = Upstreams.inferred(
            Unnamed("x"), [], "13.2.0", ("libgcc-ng",), "x", Archive((url,), "sha256:" + "0" * 64)
        )
        assert (
            isinstance(found, Upstream)
            and not found.inferred
            and found.query == {"commit": "f" * 40}
        )


class TestExactCommitsAndHosts:
    def test_a_conan_source_cloned_at_a_commit(self) -> None:
        from cordon_scanner.intel.upstream_advisories import ConanCenter

        sha = "191bcb948f7191c36eefe634336f5fc5c0c4c2be"
        found = ConanCenter.committed(
            {"url": "https://https.git.savannah.gnu.org/git/config.git", "commit": sha}, "x"
        )
        assert found is not None and found.query == {"commit": sha}
        assert ConanCenter.committed({"url": "https://x/y.git", "commit": "main"}, "x") is None

    def test_a_cgit_snapshot_of_a_commit(self) -> None:
        from cordon_scanner.intel.upstream_advisories import RepositoryArchive

        sha = "191bcb948f7191c36eefe634336f5fc5c0c4c2be"
        assert RepositoryArchive.parse(
            f"http://git.savannah.gnu.org/cgit/config.git/snapshot/config-{sha}.tar.gz"
        ) == (
            "https://git.savannah.gnu.org/cgit/config.git",
            sha,
        )

    def test_hosts_and_spellings(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import Conventions, TagInference

        for url, repository in (
            (
                "https://distfiles.ariadne.space/pkgconf/pkgconf-2.5.1.tar.xz",
                "https://github.com/pkgconf/pkgconf",
            ),
            (
                "https://ffmpeg.org//releases/ffmpeg-7.1.1.tar.bz2",
                "https://git.ffmpeg.org/ffmpeg.git",
            ),
            (
                "https://www.x.org/archive//individual/lib/libpciaccess-0.17.tar.xz",
                "https://gitlab.freedesktop.org/xorg/lib/libpciaccess",
            ),
            (
                "https://download.savannah.gnu.org/releases/freetype/freetype-2.12.1.tar.gz",
                "https://gitlab.freedesktop.org/freetype/freetype",
            ),
        ):
            assert repository in Conventions.repositories([url]), url
        monkeypatch.setattr(
            TagInference,
            "refs",
            staticmethod(lambda repository: {"VER-2-12-1": "a" * 40, "n7.1.1": "b" * 40}),
        )
        first = TagInference.infer("https://r", "2.12.1", (), "x")
        second = TagInference.infer("https://s", "7.1.1", (), "x")
        assert isinstance(first, Upstream) and first.query == {"commit": "a" * 40}
        assert isinstance(second, Upstream) and second.query == {"commit": "b" * 40}


class TestVcpkgRegistryEras:
    BASE = "9f6157af4e5b04ab3cc63150a20b1bad901a7d0b"
    RAW = "https://raw.githubusercontent.com/microsoft/vcpkg"

    @staticmethod
    def registry(monkeypatch, pages: dict[str, bytes]) -> None:
        from cordon_scanner.intel.registry_client import PackageNotFound

        def get(url: str, limit: int = 0) -> bytes:
            if url not in pages:
                raise PackageNotFound(url)
            return pages[url]

        monkeypatch.setattr(Upstreams, "_get", staticmethod(get))

    def test_a_control_file_is_the_ports_manifest(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        control = b"Source: pybind11\nVersion: 2.6.0\nPort-Version: 1\nHomepage: https://github.com/pybind/pybind11\n\nFeature: x\n"
        self.registry(monkeypatch, {f"{self.RAW}/{self.BASE}/ports/pybind11/CONTROL": control})
        assert VcpkgPorts.manifest(self.BASE, "pybind11") == {
            "version-string": "2.6.0",
            "port-version": 1,
            "homepage": "https://github.com/pybind/pybind11",
        }

    def test_a_port_that_downloads_nothing_is_vcpkgs_own_files(self) -> None:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        assert not VcpkgPorts.DOWNLOADS.search(
            'file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/x.cmake" DESTINATION y)'
        )
        for fetching in (
            "vcpkg_from_github(OUT_SOURCE_PATH S REPO a/b)",
            "file(DOWNLOAD https://x/y z)",
            "x_vcpkg_get_python_packages(PACKAGES z)",
            "vcpkg_download_distfile(A URLS u)",
        ):
            assert VcpkgPorts.DOWNLOADS.search(fetching), fetching

    def test_nuget_package_downloads(self) -> None:
        from cordon_scanner.intel.upstream_advisories import RegistryArchive

        assert RegistryArchive.parse(
            "https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/1.0.3800.47"
        ) == (
            "NuGet",
            "Microsoft.Web.WebView2",
            "1.0.3800.47",
        )

    def test_a_tag_spelled_in_another_case(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"OpenSSL_1_1_1n": "c" * 40})
        )
        found = TagInference.infer(
            "https://github.com/openssl/openssl", "1.1.1n", ("openssl",), "x"
        )
        assert isinstance(found, Upstream) and found.query == {"commit": "c" * 40}


class TestACutShortAnswer:
    def test_a_resolver_cut_short_leaves_the_package_unchecked_and_says_why(
        self, monkeypatch
    ) -> None:
        import http.client

        def cut(url: str, limit: int = 0) -> bytes:
            raise http.client.IncompleteRead(b"partial")

        monkeypatch.setattr(Upstreams, "_get", staticmethod(cut))
        monkeypatch.setattr(UpstreamAdvisories, "_cache", {})
        found = UpstreamAdvisories.name(Stand.dep("conan", "zlib", "1.3.1"))
        assert isinstance(found, Unnamed) and "IncompleteRead" in found.reason

    def test_a_git_fetch_refusal_leaves_the_package_unchecked(self, monkeypatch) -> None:
        from cordon_scanner.intel.gitfetch import GitFetchError

        def refuse(dependency):
            raise GitFetchError("not an https repository and object id")

        monkeypatch.setattr(Upstreams, "vcpkg", staticmethod(refuse))
        monkeypatch.setattr(UpstreamAdvisories, "_cache", {})
        found = UpstreamAdvisories.name(Stand.dep("vcpkg", "qtbase", None, resolution_note="x"))
        assert isinstance(found, Unnamed) and "GitFetchError" in found.reason


class TestPodSiblings:
    TRUNK = "https://cdn.cocoapods.org/Specs"
    RAW = "https://raw.githubusercontent.com/firebase/firebase-ios-sdk"
    URL = "https://dl.google.com/firebase/ios/analytics/c549faaa5cd321b5/FirebaseAnalytics-10.6.0.tar.gz"
    PODSPEC = (
        "Pod::Spec.new do |s|\n"
        "    s.name             = 'FirebaseAnalytics'\n"
        "    s.version          = '10.6.0'\n"
        "    s.source           = {\n"
        "        :http => 'https://dl.google.com/firebase/ios/analytics/c549faaa5cd321b5/"
        "FirebaseAnalytics-#{s.version}.tar.gz'\n"
        "    }\n"
        "end\n"
    )

    def pods(self, monkeypatch, podspec: str) -> tuple[list[Dependency], list]:
        from cordon_scanner.intel.more_registries import MoreRegistries
        from cordon_scanner.intel.registry_client import PackageNotFound

        trunk = json.dumps(
            {"name": "FirebaseAnalytics", "version": "10.6.0", "source": {"http": self.URL}}
        )
        monkeypatch.setattr(
            MoreRegistries, "_cocoapods_spec", staticmethod(lambda url: trunk.encode())
        )
        files = {f"{self.RAW}/CocoaPods-10.6.0/FirebaseAnalytics.podspec": podspec.encode()}

        def get(url: str, limit: int = 0) -> bytes:
            if url not in files:
                raise PackageNotFound(url)
            return files[url]

        monkeypatch.setattr(Upstreams, "_get", staticmethod(get))
        core, analytics = (
            Dependency(
                purl=f"pkg:cocoapods/{n}@10.6.0",
                ecosystem="cocoapods",
                name=n,
                version="10.6.0",
                direct=True,
            )
            for n in ("FirebaseCore", "FirebaseAnalytics")
        )
        answers = [
            Upstream(
                {
                    "package": {
                        "name": "https://github.com/firebase/firebase-ios-sdk",
                        "ecosystem": "GIT",
                    },
                    "version": "CocoaPods-10.6.0",
                },
                "the FirebaseCore 10.6.0 podspec",
            ),
            Unnamed(f"a prebuilt binary its vendor ships from {self.URL} (its podspec vends ...)"),
        ]
        return [core, analytics], answers

    def test_a_binary_pod_published_from_a_siblings_repository(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import PodSiblings

        deps, answers = self.pods(monkeypatch, self.PODSPEC)
        resolved = PodSiblings.resolve(deps, answers)
        assert isinstance(resolved[1], Upstream)
        assert resolved[1].query["version"] == "CocoaPods-10.6.0"
        assert "with the same download" in resolved[1].how

    def test_another_download_is_not_the_pod(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import PodSiblings

        deps, answers = self.pods(
            monkeypatch, self.PODSPEC.replace("c549faaa5cd321b5", "0000000000000000")
        )
        assert isinstance(PodSiblings.resolve(deps, answers)[1], Unnamed)

    def test_another_declared_version_is_not_the_pod(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import PodSiblings

        deps, answers = self.pods(monkeypatch, self.PODSPEC.replace("'10.6.0'", "'10.5.0'"))
        assert isinstance(PodSiblings.resolve(deps, answers)[1], Unnamed)


class TestRawFileAtATag:
    def test_a_raw_file_at_a_tag_names_the_release(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"v1.8.2505": "a" * 40})
        )
        url = "https://raw.githubusercontent.com/microsoft/DirectXShaderCompiler/v1.8.2505/LICENSE.TXT"
        found = Upstreams.from_urls([url], "x")
        assert isinstance(found, Upstream) and found.query["version"] == "v1.8.2505"
        # A branch moves: not a release.
        branch = url.replace("v1.8.2505", "main")
        assert isinstance(Upstreams.from_urls([branch], "x"), Unnamed)

    def test_a_file_of_another_repository_is_not_the_package(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import TagInference

        monkeypatch.setattr(
            TagInference, "refs", staticmethod(lambda repository: {"v1.0": "a" * 40})
        )
        urls = [
            "https://example.org/pkg-2.0.tar.gz",
            "https://raw.githubusercontent.com/other/helper/v1.0/cmake/Find.cmake",
            "https://github.com/pkg/pkg/commit/" + "b" * 40 + ".patch",
        ]
        assert isinstance(Upstreams.from_urls(urls, "x"), Unnamed)


class TestVcpkgFromAnyGit:
    def test_a_commit_on_any_https_git_server(self) -> None:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        found = VcpkgPorts._fetched(
            "vcpkg_from_git",
            {"URL": ["https://chromium.googlesource.com/libyuv/libyuv"], "REF": ["c" * 40]},
            "x",
        )
        assert isinstance(found, Upstream) and found.query == {"commit": "c" * 40}
        refused = VcpkgPorts._fetched(
            "vcpkg_from_git", {"URL": ["file:///tmp/x"], "REF": ["c" * 40]}, "x"
        )
        assert isinstance(refused, Unnamed)


class TestPrebuiltPods:
    @pytest.mark.parametrize(
        ("spec", "prebuilt"),
        [
            ({"vendored_frameworks": "Frameworks/FirebaseAnalytics.xcframework"}, True),
            ({"ios": {"vendored_libraries": "libBugly.a"}}, True),
            ({"subspecs": [{"name": "Core", "vendored_frameworks": "A.framework"}]}, True),
            ({"vendored_frameworks": "A.framework", "source_files": "Sources/**/*.m"}, False),
            (
                {"subspecs": [{"vendored_frameworks": "A.framework"}, {"source_files": "x.m"}]},
                False,
            ),
            ({"source_files": "Sources/**/*.swift"}, False),
            ({}, False),
        ],
    )
    def test_a_binary_distribution(self, spec: dict, prebuilt: bool) -> None:
        assert Upstreams.prebuilt(spec) is prebuilt


class TestHeadersAreNotSource:
    @pytest.mark.parametrize(
        ("spec", "prebuilt"),
        [
            (
                {
                    "vendored_frameworks": "Crashlytics.framework",
                    "source_files": "Crashlytics.framework/Headers/*.h",
                },
                True,
            ),
            (
                {
                    "vendored_frameworks": "A.framework",
                    "source_files": ["A/*.{h,hpp}", "A/module.modulemap"],
                },
                True,
            ),
            ({"vendored_frameworks": "A.framework", "source_files": "A/**/*.{h,m}"}, False),
            ({"vendored_frameworks": "A.framework", "source_files": "A/**/*"}, False),
        ],
    )
    def test_header_shims(self, spec: dict, prebuilt: bool) -> None:
        assert Upstreams.prebuilt(spec) is prebuilt


class TestUmbrellaPods:
    def test_a_header_over_its_subspecs(self) -> None:
        firebase = {
            "subspecs": [
                {"name": "CoreOnly", "source_files": ["CoreOnly/Sources/Firebase.h"]},
                {"name": "Analytics"},
            ]
        }
        assert Upstreams.umbrella(firebase) and not Upstreams.prebuilt(firebase)
        assert not Upstreams.umbrella({"source_files": "A/*.{h,m}"})
        assert not Upstreams.umbrella({"vendored_frameworks": "A.framework", "source_files": "A.h"})
        assert not Upstreams.umbrella({})


class TestVcpkgPatchDownloads:
    PORTFILE = (
        "vcpkg_download_distfile(FIX\n"
        "    URLS https://github.com/RainerKuemmerle/g2o/commit/37d17a94594648acf9cce85e8483c0405c510f0d.patch?full_index=1\n"
        f"    SHA512 {'d' * 128}\n"
        "    FILENAME g2o-37d17a9.patch\n"
        ")\n"
        "vcpkg_from_github(\n"
        "    OUT_SOURCE_PATH SOURCE_PATH\n"
        "    REPO RainerKuemmerle/g2o\n"
        "    REF eec325a1da1273e87bc97887d49e70570f28570c\n"
        f"    SHA512 {'e' * 128}\n"
        '    PATCHES "${FIX}"\n'
        ")\n"
    )

    def test_a_patch_download_is_not_the_source(self) -> None:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        found, _ = VcpkgPorts.read(self.PORTFILE, "2023-08-06", "g2o", "x")
        assert isinstance(found, Upstream) and found.query == {
            "commit": "eec325a1da1273e87bc97887d49e70570f28570c"
        }


class TestVcpkgOverrides:
    def test_an_override_is_the_version_not_a_minimum(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import VcpkgPorts

        asked: list[str] = []
        monkeypatch.setattr(
            VcpkgPorts,
            "manifest",
            staticmethod(lambda baseline, port: {"version-string": "chromium_7258"}),
        )

        def at_version(baseline: str, name: str, wanted: str):
            asked.append(wanted)
            return Unnamed("stop here")

        monkeypatch.setattr(VcpkgPorts, "at_version", staticmethod(at_version))
        angle = Dependency(
            purl="pkg:vcpkg/angle",
            ecosystem="vcpkg",
            name="angle",
            version=None,
            direct=True,
            declared_spec="chromium_7258#0",
            resolution_note=f"pinned by an override; vcpkg reads the port at baseline {'a' * 40}",
        )
        answer = Upstreams.vcpkg(angle)
        assert asked == ["chromium_7258#0"]
        assert isinstance(answer, Unnamed) and "not ordered" not in answer.reason


class TestCondaZip64:
    @staticmethod
    def package(member: bytes, name: str = "info-x-1.0-0.tar.zst") -> bytes:
        """A stored zip whose directory and end record use ZIP64 for every size and offset."""
        import struct
        import zlib

        crc = zlib.crc32(member)
        encoded = name.encode()
        local = (
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                45,
                0,
                0,
                0,
                0,
                crc,
                len(member),
                len(member),
                len(encoded),
                0,
            )
            + encoded
            + member
        )
        extra = struct.pack("<HHQQQ", 1, 24, len(member), len(member), 0)
        central = (
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50, 45, 45, 0, 0, 0, 0, crc,
                0xFFFFFFFF, 0xFFFFFFFF, len(encoded), len(extra), 0, 0, 0, 0, 0xFFFFFFFF,
            )
            + encoded
            + extra
        )  # fmt: skip
        record_at = len(local) + len(central)
        record = struct.pack(
            "<IQHHIIQQQQ", 0x06064B50, 44, 45, 45, 0, 0, 1, 1, len(central), len(local)
        )
        locator = struct.pack("<IIQI", 0x07064B50, 0, record_at, 1)
        end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        return local + central + record + locator + end

    def test_a_zip64_package_is_read(self, monkeypatch) -> None:
        from pathlib import Path

        from cordon_scanner.intel.upstream_advisories import CondaPackage

        member = (
            Path(__file__).resolve().parent / "data" / "zstd" / "conda-info.tar.zst"
        ).read_bytes()
        body = self.package(member)

        def ranged(url: str, header: str, limit: int) -> tuple[bytes, int]:
            spec = header.removeprefix("bytes=")
            if spec.startswith("-"):
                return body[-int(spec[1:]) :], len(body)
            start, _, stop = spec.partition("-")
            return body[int(start) : int(stop) + 1], len(body)

        monkeypatch.setattr(CondaPackage, "_range", staticmethod(ranged))
        recipe = CondaPackage.recipe("https://conda.anaconda.org/conda-forge/noarch/x-1.0-0.conda")
        assert recipe is not None and "source" in recipe


class TestHttpGitHubArchives:
    def test_an_http_github_archive_is_the_https_one(self) -> None:
        from cordon_scanner.intel.upstream_advisories import RepositoryArchive

        assert RepositoryArchive.parse(
            "http://github.com/google/re2/archive/2025-11-05.tar.gz"
        ) == (
            "https://github.com/google/re2",
            "2025-11-05",
        )


class TestCondaMetapackages:
    @staticmethod
    def info(paths: list[str]) -> bytes:
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for name, data in (
                ("info/recipe/meta.yaml", b"package:\n  name: python_abi\n"),
                ("info/paths.json", json.dumps({"paths": paths, "paths_version": 1}).encode()),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return raw.getvalue()

    def test_paths_after_the_recipe_are_read_only_when_wanted(self) -> None:
        from cordon_scanner.intel.upstream_advisories import CondaPackage

        seen: dict[str, int] = {}
        with tarfile.open(fileobj=io.BytesIO(self.info([])), mode="r|") as archive:
            assert CondaPackage._from_tar(archive, seen) is not None
        assert "paths" not in seen
        seen["want_paths"] = 1
        with tarfile.open(fileobj=io.BytesIO(self.info([])), mode="r|") as archive:
            CondaPackage._from_tar(archive, seen)
        assert seen["paths"] == 0

    def test_a_package_installing_files_counts_them(self) -> None:
        from cordon_scanner.intel.upstream_advisories import CondaPackage

        seen: dict[str, int] = {"want_paths": 1}
        with tarfile.open(fileobj=io.BytesIO(self.info(["lib/x.so"])), mode="r|") as archive:
            CondaPackage._from_tar(archive, seen)
        assert seen["paths"] == 1


class TestVersionInAnUnderscoredName:
    def test_cf_cli_6_48_0_osx(self) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewHistory

        formula = (
            'class CfCli < Formula\n  url "https://packages.cloudfoundry.org/homebrew/cf-cli_6.48.0_osx.tgz"\n'
            f'  sha256 "{"1" * 64}"\nend\n'
        )
        assert HomebrewHistory.builds(formula, "6.48.0")
        assert not HomebrewHistory.builds(formula, "6.48")


class TestDumbHttpRefs:
    def test_a_plain_info_refs_list(self, monkeypatch) -> None:
        import urllib.request

        from cordon_scanner.intel.upstream_advisories import TagInference

        body = (
            b"e9a53e8922fbebe825f74ffbe309d4e57d6b09d5\trefs/heads/master\n"
            b"1111111111111111111111111111111111111111\trefs/tags/0.69\n"
            b"0675c6ea5368f0843a91c28a472247b8f26015cf\trefs/tags/0.69^{}\n"
            b"ee8e013cd5398c5fb34fb19a24db0f3b6185bac3\trefs/tags/0.67\n"
        )

        class Answer(io.BytesIO):
            headers: ClassVar[dict[str, str]] = {"Content-Type": "text/plain"}

            def __enter__(self):
                return self

            def __exit__(self, *exc) -> None:
                return None

            def geturl(self) -> str:
                return "https://git.example/moreutils.git/info/refs?service=git-upload-pack"

        monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout: Answer(body))
        TagInference._refs.pop("https://git.example/moreutils.git", None)
        refs = TagInference.refs("https://git.example/moreutils.git")
        assert refs == {
            "0.69": "0675c6ea5368f0843a91c28a472247b8f26015cf",
            "0.67": "ee8e013cd5398c5fb34fb19a24db0f3b6185bac3",
        }


class TestGitLabHeadBuilds:
    def test_gitlab_resolves_the_abbreviation(self, monkeypatch) -> None:
        from cordon_scanner.intel.upstream_advisories import HomebrewBottles

        full = "ae2b873" + "d" * 33
        asked: list[str] = []

        def get(url: str, limit: int = 0) -> bytes:
            asked.append(url)
            return json.dumps({"id": full}).encode()

        monkeypatch.setattr(Upstreams, "_get", staticmethod(get))
        data = {"urls": {"head": {"url": "https://gitlab.com/qemu-project/qemu.git"}}}
        found = HomebrewBottles.head(data, "HEAD-ae2b873", "qemu")
        assert isinstance(found, Upstream) and found.query == {"commit": full}
        assert asked == [
            "https://gitlab.com/api/v4/projects/qemu-project%2Fqemu/repository/commits/ae2b873"
        ]


class TestProprietaryConda:
    @pytest.mark.parametrize(
        ("about", "proprietary"),
        [
            ({"license": "LicenseRef-NVIDIA-End-User-License-Agreement"}, True),
            ({"license": "LicenseRef-ProprietaryIntel", "license_family": "Proprietary"}, True),
            ({"license": "LicenseRef-MicrosoftWindowsSDK10"}, True),
            (
                {
                    "license": "LicenseRef-Ubuntu-Font-Licence-Version-1.0",
                    "license_family": "Other",
                },
                False,
            ),
            ({"license": "MIT", "license_family": "MIT"}, False),
            (None, False),
        ],
    )
    def test_a_vendors_own_licence(self, about: object, proprietary: bool) -> None:
        assert bool(Upstreams.proprietary(about)) is proprietary
