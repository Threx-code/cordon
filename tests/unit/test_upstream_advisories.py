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

        self.tags(monkeypatch, {"curl-8_0_0": "a" * 40, "8.0.1": "b" * 40})
        found = TagInference.infer("https://example.invalid/curl.git", "8.0.0", ("curl",), "x")
        assert isinstance(found, Unnamed) and "no tag spelled as version 8.0.0" in found.reason

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
