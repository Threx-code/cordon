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
