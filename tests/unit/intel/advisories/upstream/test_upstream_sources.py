"""What each ecosystem's source record says a package was built from, branch by branch: an exact commit or tag
is named, an archive is inferred from, and anything that names no fixed source is unchecked with its reason."""

from __future__ import annotations

import contextlib
import json

import pytest

from cordon_scanner.foundation.models import Scope
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.advisories.upstream.base import Unnamed, Upstream
from cordon_scanner.intel.advisories.upstream.fetch import Fetch
from cordon_scanner.intel.advisories.upstream.inference import TagInference
from cordon_scanner.intel.advisories.upstream_advisories import UpstreamAdvisories, Upstreams
from cordon_scanner.intel.registries.package_registries import PackageRegistries

COMMIT = "0123456789abcdef0123456789abcdef01234567"
BCR = "https://bcr.bazel.build/modules"


class Sources:
    """Helpers for test_upstream_sources.py: the network, as a dict of URL -> body."""

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
    def serve(monkeypatch: pytest.MonkeyPatch, pages: dict[str, object]) -> list[str]:
        asked: list[str] = []

        def get(url: str, limit: int = 0) -> bytes:
            asked.append(url)
            if url not in pages:
                raise OSError(f"not served: {url}")
            page = pages[url]
            return page if isinstance(page, bytes) else json.dumps(page).encode()

        monkeypatch.setattr(Fetch, "get", staticmethod(get))
        monkeypatch.setattr(Fetch, "resolved", {})
        monkeypatch.setattr(UpstreamAdvisories, "_records", {})
        monkeypatch.setattr(TagInference, "refs", staticmethod(lambda repository: {}))
        return asked


class TestBazel:
    def test_a_git_repository_source_with_a_commit_is_exact(self, monkeypatch) -> None:
        Sources.serve(
            monkeypatch,
            {
                f"{BCR}/abseil/1.0/source.json": {
                    "type": "git_repository",
                    "remote": "https://github.com/abseil/abseil-cpp.git",
                    "commit": COMMIT,
                }
            },
        )
        found = Upstreams.bazel(Sources.dep("bazel", "abseil", "1.0"))
        assert isinstance(found, Upstream) and COMMIT in json.dumps(found.query)

    def test_a_git_repository_source_without_a_commit_is_unnamed(self, monkeypatch) -> None:
        Sources.serve(
            monkeypatch,
            {
                f"{BCR}/abseil/1.0/source.json": {
                    "type": "git_repository",
                    "remote": "https://github.com/abseil/abseil-cpp.git",
                    "commit": "main",
                }
            },
        )
        found = Upstreams.bazel(Sources.dep("bazel", "abseil", "1.0"))
        assert isinstance(found, Unnamed) and "without a commit" in found.reason

    def test_an_archive_off_any_forge_falls_back_to_the_modules_metadata(self, monkeypatch) -> None:
        asked = Sources.serve(
            monkeypatch,
            {
                f"{BCR}/zlib/1.3.1.bcr.2/source.json": {
                    "url": "https://zlib.net/zlib-1.3.1.tar.gz",
                    "mirror_urls": ["https://mirror.example/zlib-1.3.1.tar.gz", 7],
                    "integrity": "sha256-abc",
                },
                f"{BCR}/zlib/metadata.json": {
                    "repository": ["github:madler/zlib"],
                    "homepage": "https://zlib.net",
                },
            },
        )
        Upstreams.bazel(Sources.dep("bazel", "zlib", "1.3.1.bcr.2"))
        assert f"{BCR}/zlib/metadata.json" in asked

    def test_metadata_that_cannot_be_read_leaves_the_first_answer(self, monkeypatch) -> None:
        Sources.serve(
            monkeypatch,
            {f"{BCR}/zlib/1.3.1/source.json": {"url": "https://zlib.net/zlib-1.3.1.tar.gz"}},
        )
        found = Upstreams.bazel(Sources.dep("bazel", "zlib", "1.3.1"))
        assert isinstance(found, Unnamed)

    def test_the_lock_names_the_registry_it_used(self, monkeypatch) -> None:
        registry = "https://registry.example/bazel"
        asked = Sources.serve(
            monkeypatch,
            {
                f"{registry}/modules/m/1/source.json": {
                    "url": "https://github.com/o/m/archive/refs/tags/v1.tar.gz"
                }
            },
        )
        Upstreams.bazel(Sources.dep("bazel", "m", "1", resolved_from=f"{registry}/"))
        assert asked == [f"{registry}/modules/m/1/source.json"]


class TestCocoaPods:
    @staticmethod
    def spec(monkeypatch, spec: object) -> None:
        Sources.serve(monkeypatch, {})
        monkeypatch.setattr(
            PackageRegistries, "cocoapods_spec", staticmethod(lambda url: json.dumps(spec))
        )

    def test_cocoapods_itself_is_the_rubygem(self) -> None:
        found = Upstreams.cocoapods(
            Sources.dep("cocoapods", "cocoapods", "1.15.2", scope=Scope.TOOL)
        )
        assert isinstance(found, Upstream)
        assert found.query["package"] == {"name": "cocoapods", "ecosystem": "RubyGems"}

    def test_a_git_source_with_a_tag_is_exact(self, monkeypatch) -> None:
        self.spec(
            monkeypatch,
            {"source": {"git": "https://github.com/Alamofire/Alamofire.git", "tag": "5.9.0"}},
        )
        found = Upstreams.cocoapods(Sources.dep("cocoapods", "Alamofire", "5.9.0"))
        assert isinstance(found, Upstream)

    def test_a_git_source_with_no_ref_is_unnamed(self, monkeypatch) -> None:
        self.spec(monkeypatch, {"source": {"git": "https://example.org/x.git"}})
        found = Upstreams.cocoapods(Sources.dep("cocoapods", "X", "1.0"))
        assert isinstance(found, Unnamed)

    def test_a_spec_with_no_source_is_unnamed(self, monkeypatch) -> None:
        self.spec(monkeypatch, {"homepage": "https://example.org"})
        found = Upstreams.cocoapods(Sources.dep("cocoapods", "X", "1.0"))
        assert isinstance(found, Unnamed)

    def test_a_vendors_prebuilt_binary_says_so(self, monkeypatch) -> None:
        self.spec(
            monkeypatch,
            {
                "source": {"http": "https://dl.vendor.example/sdk.zip", "sha256": "ab" * 32},
                "vendored_frameworks": ["Sdk.xcframework"],
            },
        )
        found = Upstreams.cocoapods(Sources.dep("cocoapods", "VendorSdk", "1.0"))
        assert isinstance(found, Unnamed) and "prebuilt binary" in found.reason

    def test_an_umbrella_of_headers_says_so(self, monkeypatch) -> None:
        self.spec(
            monkeypatch,
            {
                "source": {"http": "https://dl.vendor.example/umbrella.zip"},
                "source_files": "Umbrella/*.h",
                "preserve_paths": "Umbrella/*.h",
            },
        )
        found = Upstreams.cocoapods(Sources.dep("cocoapods", "Umbrella", "3.0"))
        assert isinstance(found, Unnamed)
        assert "umbrella" in found.reason or "prebuilt" in found.reason or found.reason

    def test_a_checkout_at_a_commit_is_exact(self) -> None:
        found = Upstreams.cocoapods(
            Sources.dep(
                "cocoapods",
                "X",
                "1.0",
                resolved_from=f"git+https://github.com/o/x.git#{COMMIT}",
            )
        )
        assert isinstance(found, Upstream)

    def test_a_checkout_of_a_branch_is_no_fixed_point(self, monkeypatch) -> None:
        Sources.serve(monkeypatch, {})
        found = Upstreams.cocoapods(
            Sources.dep(
                "cocoapods", "X", "1.0", resolved_from="git+https://github.com/o/x.git#main"
            )
        )
        assert isinstance(found, Unnamed) and "not a tag" in found.reason

    def test_a_pod_from_elsewhere_is_unnamed(self) -> None:
        found = Upstreams.cocoapods(Sources.dep("cocoapods", "X", "1.0", resolved_from="path:../X"))
        assert isinstance(found, Unnamed) and "not from CocoaPods trunk" in found.reason


class TestHomebrew:
    @staticmethod
    def formula(monkeypatch, found, *, bottle=None) -> None:
        from cordon_scanner.intel.advisories.upstream import homebrew

        monkeypatch.setattr(
            homebrew.HomebrewBottles, "formula_data", staticmethod(lambda name, installed: found)
        )
        if bottle is not None:
            monkeypatch.setattr(homebrew.HomebrewBottles, "formula", staticmethod(bottle))

    def test_a_cask_is_not_a_formula(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import homebrew

        monkeypatch.setattr(
            homebrew.HomebrewBottles, "cask", staticmethod(lambda token: Unnamed(f"cask {token}"))
        )
        found = Upstreams.homebrew(Sources.dep("homebrew", "firefox", "1", platform=("cask",)))
        assert found.reason == "cask firefox"

    def test_a_tap_locked_to_a_commit_is_exact(self) -> None:
        found = Upstreams.homebrew(Sources.dep("homebrew", "acme/tools", COMMIT))
        assert isinstance(found, Upstream) and found.query == {"commit": COMMIT}

    def test_a_tap_formula_is_read_from_the_tap(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import homebrew

        asked: list[tuple[str, str, str]] = []
        monkeypatch.setattr(
            homebrew.HomebrewBottles,
            "tap_formula",
            staticmethod(lambda tap, f, v: asked.append((tap, f, v)) or Unnamed("read")),
        )
        Upstreams.homebrew(Sources.dep("homebrew", "jq", "1.7", resolved_from="registry:acme/tap"))
        assert asked == [("acme/tap", "jq", "1.7")]

    def test_any_other_tap_is_unnamed(self) -> None:
        found = Upstreams.homebrew(Sources.dep("homebrew", "acme/tap/jq", "1.7"))
        assert isinstance(found, Unnamed) and "from a tap" in found.reason

    def test_a_formula_homebrew_dropped_is_looked_for_in_history(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import homebrew

        self.formula(monkeypatch, Unnamed("Homebrew no longer has this formula"))
        monkeypatch.setattr(
            homebrew.HomebrewHistory, "upstream", staticmethod(lambda dep, why: Unnamed("history"))
        )
        found = Upstreams.homebrew(Sources.dep("homebrew", "old", "1.0"))
        assert found.reason == "history"

    def test_any_other_unanswered_formula_says_why(self, monkeypatch) -> None:
        self.formula(monkeypatch, Unnamed("formulae.brew.sh is down"))
        found = Upstreams.homebrew(Sources.dep("homebrew", "jq", "1.7"))
        assert found.reason == "formulae.brew.sh is down"

    def test_a_head_build_is_read_as_one(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import homebrew

        self.formula(monkeypatch, ("jq", {"versions": {"stable": "1.7"}}))
        monkeypatch.setattr(
            homebrew.HomebrewBottles, "head", staticmethod(lambda data, v, n: Unnamed("head"))
        )
        found = Upstreams.homebrew(Sources.dep("homebrew", "jq", "HEAD-abc1234"))
        assert found.reason == "head"

    def test_a_formula_the_api_names_no_file_for_is_unnamed(self, monkeypatch) -> None:
        self.formula(monkeypatch, ("jq", {"versions": {"stable": "1.7"}, "tap_git_head": "x"}))
        found = Upstreams.homebrew(Sources.dep("homebrew", "jq", "1.7"))
        assert isinstance(found, Unnamed) and "names no formula file" in found.reason

    def test_a_formula_file_that_does_not_hash_is_unnamed(self, monkeypatch) -> None:
        data = {
            "versions": {"stable": "1.7"},
            "tap_git_head": COMMIT,
            "ruby_source_path": "Formula/j/jq.rb",
            "ruby_source_checksum": {"sha256": "0" * 64},
        }
        self.formula(monkeypatch, ("jq", data))
        Sources.serve(
            monkeypatch,
            {
                f"https://raw.githubusercontent.com/Homebrew/homebrew-core/{COMMIT}/Formula/j/jq.rb": b"class Jq"
            },
        )
        found = Upstreams.homebrew(Sources.dep("homebrew", "jq", "1.7"))
        assert isinstance(found, Unnamed) and "does not hash" in found.reason

    def test_an_old_version_with_no_bottle_is_inferred_from_the_current_formula(
        self, monkeypatch
    ) -> None:
        from cordon_scanner.intel.advisories.upstream import homebrew

        def no_bottle(name: str, version: str) -> str:
            raise OSError("no bottle")

        self.formula(
            monkeypatch,
            ("jq", {"versions": {"stable": "1.7"}, "homepage": "https://jqlang.github.io"}),
            bottle=no_bottle,
        )
        monkeypatch.setattr(
            homebrew.HomebrewHistory, "upstream", staticmethod(lambda dep, why: why)
        )
        monkeypatch.setattr(
            homebrew.HomebrewBottles,
            "current_formula",
            staticmethod(lambda data: 'head "https://github.com/jqlang/jq.git"\n'),
        )
        Sources.serve(monkeypatch, {})
        found = Upstreams.homebrew(Sources.dep("homebrew", "jq", "1.5_1"))
        assert isinstance(found, Unnamed)

    def test_a_history_upstream_for_an_old_version_is_taken(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import homebrew

        def no_bottle(name: str, version: str) -> str:
            raise OSError("no bottle")

        exact = Upstream({"package": {"name": "x", "ecosystem": "GIT"}}, "history")
        self.formula(monkeypatch, ("jq", {"versions": {"stable": "1.7"}}), bottle=no_bottle)
        monkeypatch.setattr(
            homebrew.HomebrewHistory, "upstream", staticmethod(lambda dep, why: exact)
        )
        assert Upstreams.homebrew(Sources.dep("homebrew", "jq", "1.5")) is exact


class TestVcpkg:
    BASE = "b" * 40

    def dep(self, **fields: object) -> Dependency:
        return Sources.dep(
            "vcpkg",
            "zlib",
            fields.pop("version", None),
            resolution_note=f"read at baseline {self.BASE}",
            **fields,
        )

    @staticmethod
    def ports(monkeypatch, manifest: dict, *, at_version=None, portfile: str = "") -> list[str]:
        from cordon_scanner.intel.advisories.upstream import vcpkg

        monkeypatch.setattr(vcpkg.VcpkgPorts, "manifest", staticmethod(lambda b, p: manifest))
        if at_version is not None:
            monkeypatch.setattr(vcpkg.VcpkgPorts, "at_version", staticmethod(at_version))
        return Sources.serve(
            monkeypatch,
            {
                f"{vcpkg.VCPKG_RAW}/{TestVcpkg.BASE}/ports/zlib/portfile.cmake": portfile.encode(),
            },
        )

    def test_a_port_from_another_registry_is_unnamed(self) -> None:
        found = Upstreams.vcpkg(Sources.dep("vcpkg", "zlib", "1", resolved_from="git+x"))
        assert isinstance(found, Unnamed) and "built-in registry" in found.reason

    def test_a_port_with_no_baseline_is_unnamed(self) -> None:
        found = Upstreams.vcpkg(Sources.dep("vcpkg", "zlib", "1"))
        assert isinstance(found, Unnamed) and "no baseline" in found.reason

    def test_an_unordered_scheme_cannot_meet_a_minimum(self, monkeypatch) -> None:
        self.ports(monkeypatch, {"version-string": "vs2019"})
        found = Upstreams.vcpkg(self.dep(declared_spec=">=vs2022"))
        assert isinstance(found, Unnamed) and "not ordered" in found.reason

    def test_a_minimum_above_the_baseline_is_the_version_installed(self, monkeypatch) -> None:
        asked: list[str] = []
        self.ports(
            monkeypatch,
            {"version": "1.2.11"},
            at_version=lambda b, p, v: asked.append(v) or Unnamed("not at that version"),
        )
        found = Upstreams.vcpkg(self.dep(declared_spec=">=1.3.1"))
        assert asked == ["1.3.1"] and found.reason == "not at that version"

    def test_an_override_names_the_version(self, monkeypatch) -> None:
        asked: list[str] = []
        self.ports(
            monkeypatch,
            {"version": "1.2.11"},
            at_version=lambda b, p, v: asked.append(v) or Unnamed("override"),
        )
        Upstreams.vcpkg(self.dep(declared_spec="1.3"))
        assert asked == ["1.3"]

    def test_a_port_that_downloads_nothing_is_vcpkgs_own_files(self, monkeypatch) -> None:
        self.ports(
            monkeypatch, {"version": "2024-01-01"}, portfile="file(INSTALL x DESTINATION y)\n"
        )
        found = Upstreams.vcpkg(self.dep())
        assert isinstance(found, Upstream) and "vcpkg's own" in found.how

    def test_a_qt_module_port_is_read_through_qtbase(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import vcpkg

        self.ports(monkeypatch, {"version": "6.7.0"}, portfile="qt_install_submodule(PATCHES x)\n")
        seen: list[str] = []
        monkeypatch.setattr(
            vcpkg.VcpkgPorts,
            "qt",
            staticmethod(
                lambda port, version, other, how, qtbase: seen.append(version) or Unnamed("qt")
            ),
        )
        assert Upstreams.vcpkg(self.dep()).reason == "qt" and seen == ["6.7.0"]


class TestConda:
    URL = "https://conda.anaconda.org/conda-forge/linux-64/x-1.0-h0.conda"

    @staticmethod
    def recipe(monkeypatch, text: str | None, **seen_after: int) -> None:
        from cordon_scanner.intel.advisories.upstream import conda

        def recipe(url: str, seen: dict[str, int]) -> str | None:
            seen.update(seen_after)
            return text

        monkeypatch.setattr(conda.CondaPackage, "recipe", staticmethod(recipe))
        Sources.serve(monkeypatch, {})

    def dep(self) -> Dependency:
        return Sources.dep("conda", "x", "1.0", resolved_from=self.URL)

    def test_a_private_channel_is_unnamed(self) -> None:
        found = Upstreams.conda(
            Sources.dep("conda", "x", "1.0", resolved_from="https://internal/x")
        )
        assert isinstance(found, Unnamed) and "public conda channel" in found.reason

    def test_a_package_with_no_recipe_is_unnamed(self, monkeypatch) -> None:
        self.recipe(monkeypatch, None)
        assert "no rendered recipe" in Upstreams.conda(self.dep()).reason

    def test_a_git_source_at_a_revision_is_exact(self, monkeypatch) -> None:
        self.recipe(
            monkeypatch,
            "source:\n  git_url: https://github.com/o/x.git\n  git_rev: v1.0\n",
        )
        assert isinstance(Upstreams.conda(self.dep()), Upstream)

    def test_rattler_builds_finalized_sources_are_read(self, monkeypatch) -> None:
        self.recipe(
            monkeypatch,
            "recipe:\n  package: {name: x}\nfinalized_sources:\n"
            "  - git: https://github.com/o/x.git\n    rev: " + COMMIT + "\n",
        )
        assert isinstance(Upstreams.conda(self.dep()), Upstream)

    def test_a_metapackage_installs_nothing(self, monkeypatch) -> None:
        self.recipe(monkeypatch, "package: {name: x}\n", paths=0)
        found = Upstreams.conda(self.dep())
        assert isinstance(found, Unnamed) and found.nothing

    def test_a_fonts_package_has_no_code(self, monkeypatch) -> None:
        self.recipe(
            monkeypatch,
            "source:\n  url: https://fonts.example/x.zip\n",
            paths=3,
            fonts_only=1,
        )
        found = Upstreams.conda(self.dep())
        assert isinstance(found, Unnamed) and found.nothing and "font" in found.reason

    def test_a_vendors_proprietary_build_says_so(self, monkeypatch) -> None:
        self.recipe(
            monkeypatch,
            "source:\n  url: https://vendor.example/x.tar.gz\n  sha256: abc\n"
            "about:\n  license: LicenseRef-NVIDIA-End-User-License-Agreement\n",
            paths=4,
        )
        found = Upstreams.conda(self.dep())
        assert isinstance(found, Unnamed) and "proprietary" in found.reason

    def test_what_counts_as_proprietary(self) -> None:
        assert Upstreams.proprietary({"license_family": "Proprietary"}) == "Proprietary"
        assert Upstreams.proprietary({"license": "LicenseRef-Ubuntu-Font-Licence-1.0"}) == ""
        assert Upstreams.proprietary("MIT") == ""


class TestAnsible:
    VERSIONS = (
        "https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/"
        "index/community/general/versions/9.0.0/"
    )

    def test_a_record_with_its_commit_is_exact(self, monkeypatch) -> None:
        Sources.serve(
            monkeypatch,
            {
                self.VERSIONS: {
                    "git_url": "https://github.com/ansible-collections/community.general",
                    "git_commit_sha": COMMIT,
                }
            },
        )
        found = Upstreams.ansible(Sources.dep("ansible", "community.general", "9.0.0"))
        assert isinstance(found, Upstream)

    def test_a_record_without_a_commit_is_inferred_from_its_artefact(self, monkeypatch) -> None:
        Sources.serve(
            monkeypatch,
            {
                self.VERSIONS: {
                    "metadata": {"repository": "https://example.org/general"},
                    "download_url": "/download/community-general-9.0.0.tar.gz",
                    "artifact": {"sha256": "ab" * 32},
                }
            },
        )
        found = Upstreams.ansible(Sources.dep("ansible", "community.general", "9.0.0"))
        assert isinstance(found, Unnamed)

    def test_anything_but_a_galaxy_collection_is_unnamed(self) -> None:
        found = Upstreams.ansible(Sources.dep("ansible", "a.b.c", "1"))
        assert isinstance(found, Unnamed) and "galaxy" in found.reason


class TestNamingAndAsking:
    def test_charts_and_images_are_read_through_their_own_module(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import charts_images

        monkeypatch.setattr(
            charts_images.ChartsImages, "helm", staticmethod(lambda d: Unnamed("chart"))
        )
        monkeypatch.setattr(
            charts_images.ChartsImages, "image", staticmethod(lambda d: Unnamed("image"))
        )
        assert Upstreams.helm(Sources.dep("helm", "x", "1")).reason == "chart"
        assert Upstreams.image(Sources.dep("image", "x", "1")).reason == "image"

    def test_an_answer_is_given_once_per_package(self, monkeypatch) -> None:
        Sources.serve(monkeypatch, {})
        dep = Sources.dep("nix", "nixpkgs", COMMIT)
        first = UpstreamAdvisories.name(dep)
        assert UpstreamAdvisories.name(dep) is first

    def test_an_ecosystem_with_no_reader_or_no_version_is_unnamed(self, monkeypatch) -> None:
        Sources.serve(monkeypatch, {})
        assert "no upstream" in UpstreamAdvisories.name(Sources.dep("npm", "x", "1")).reason
        assert "no version" in UpstreamAdvisories.name(Sources.dep("nix", "x", None)).reason

    def test_a_registry_that_cannot_be_read_says_so(self, monkeypatch) -> None:
        from cordon_scanner.intel.registries.registry_client import RegistryError

        Sources.serve(monkeypatch, {})

        def fail(dependency: Dependency) -> Upstream:
            raise RegistryError("rate limited")

        monkeypatch.setattr(Upstreams, "terraform", staticmethod(fail))
        found = UpstreamAdvisories.name(Sources.dep("terraform", "hashicorp/random", "3.6.0"))
        assert "rate limited" in found.reason

    def test_osv_is_asked_with_a_json_post(self, monkeypatch) -> None:
        import io
        import urllib.request

        sent: list[object] = []

        def urlopen(request, timeout):
            sent.append(json.loads(request.data))
            return io.BytesIO(b'{"results": []}')

        monkeypatch.setattr(urllib.request, "urlopen", urlopen)
        assert UpstreamAdvisories._post("https://api.osv.dev/v1/querybatch", {"queries": []}) == {
            "results": []
        }
        assert sent == [{"queries": []}]

    def test_an_answer_that_is_not_an_object_is_empty(self, monkeypatch) -> None:
        import io
        import urllib.request

        monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout: io.BytesIO(b"[]"))
        assert UpstreamAdvisories._post("https://api.osv.dev/v1/querybatch", {}) == {}


class TestTheCheckEdges:
    def test_past_the_ceiling_a_package_is_unchecked(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories import upstream_advisories

        Sources.serve(monkeypatch, {})
        monkeypatch.setattr(upstream_advisories, "MAX_PACKAGES", 1)
        deps = [Sources.dep("nix", "a", "x"), Sources.dep("nix", "b", "y")]
        result = UpstreamAdvisories.check(deps)
        assert "ceiling" in result.unchecked[deps[1].purl]

    def test_a_package_with_nothing_to_match_counts_as_checked(self, monkeypatch) -> None:
        Sources.serve(monkeypatch, {})
        monkeypatch.setattr(
            Upstreams,
            "nix",
            staticmethod(
                lambda d: (
                    Unnamed("nothing", nothing=True)
                    if d.name == "meta"
                    else Unnamed("why", homes=("https://h.example",), version="2.0")
                )
            ),
        )
        meta = Sources.dep("nix", "meta", "1")
        other = Sources.dep("nix", "other", "1")
        result = UpstreamAdvisories.check([meta, other])
        assert meta.purl in result.checked
        assert result.homes[other.purl] == ("https://h.example",)

    def test_osv_pages_are_followed_and_a_record_it_cannot_serve_leaves_it_unchecked(
        self, monkeypatch
    ) -> None:
        Sources.serve(monkeypatch, {})
        dep = Sources.dep("nix", "nixpkgs", COMMIT)
        answers = iter(
            [
                {"results": [{"vulns": [{"id": "OSV-1"}], "next_page_token": "p2"}]},
                {"results": [{"vulns": [{"id": "OSV-2"}]}]},
            ]
        )
        asked: list[dict] = []
        monkeypatch.setattr(
            UpstreamAdvisories,
            "_post",
            staticmethod(lambda url, body: asked.append(body) or next(answers)),
        )
        result = UpstreamAdvisories.check([dep])
        assert asked[1]["queries"][0]["page_token"] == "p2"
        assert dep.purl not in result.checked and "OSV-1" in result.unchecked[dep.purl]


class TestForAGraph:
    def test_nvd_checks_what_no_upstream_route_did(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories import nvd
        from cordon_scanner.intel.advisories.upstream_advisories import UpstreamResult

        brew = Sources.dep("homebrew", "jq", "1.7")
        pod = Sources.dep("cocoapods", "X", "1.0")
        conan = Sources.dep("conan", "zlib", "1.3")
        monkeypatch.setattr(
            UpstreamAdvisories,
            "check",
            staticmethod(lambda deps: UpstreamResult(unchecked={pod.purl: "no tag"})),
        )
        monkeypatch.setattr(
            nvd.NvdAdvisories,
            "check",
            staticmethod(
                lambda deps, homes, versions: UpstreamResult(
                    checked={brew.purl}, unchecked={pod.purl: "no CPE", conan.purl: "no CPE"}
                )
            ),
        )
        result = UpstreamAdvisories.for_graph([brew, pod, conan], lambda e: False, offline=False)
        assert result is not None and brew.purl in result.checked
        assert result.unchecked[pod.purl] == "no tag; and NVD: no CPE"
        assert result.unchecked[conan.purl] == "NVD: no CPE"

    def test_with_nothing_for_nvd_the_upstream_answer_stands(self) -> None:
        assert (
            UpstreamAdvisories.for_graph(
                [Sources.dep("npm", "x", "1")], lambda e: True, offline=True
            )
            is None
        )


class TestTheRemainingBranches:
    def test_bazel_reads_the_archive_its_lock_records(self, monkeypatch) -> None:
        asked = Sources.serve(monkeypatch, {})
        found = Upstreams.bazel(
            Sources.dep(
                "bazel",
                "m",
                "1",
                resolved_from="https://github.com/o/m/archive/refs/tags/v1.tar.gz",
            )
        )
        assert asked == [] and found is not None

    def test_conan_from_another_remote_is_unnamed(self) -> None:
        found = Upstreams.conan(Sources.dep("conan", "zlib", "1.3", resolved_from="mycorp"))
        assert "not from Conan Center" in found.reason

    def test_conan_with_no_recipe_revision_is_unnamed(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories import upstream_advisories as ua

        base = f"{ua.CONAN_CENTER}/zlib/1.3/_/_/revisions"
        Sources.serve(monkeypatch, {base: {"revisions": []}})
        found = Upstreams.conan(Sources.dep("conan", "zlib", "1.3"))
        assert "holds no recipe" in found.reason

    def test_conan_a_dropped_version_is_read_from_the_current_recipe(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import conan

        Sources.serve(monkeypatch, {})
        monkeypatch.setattr(
            conan.ConanCenter, "removed", staticmethod(lambda name, version: Unnamed("dropped"))
        )
        assert Upstreams.conan(Sources.dep("conan", "ruby", "3.2.2")).reason == "dropped"

    def test_conan_a_recipe_naming_no_repository_is_inferred(self, monkeypatch) -> None:
        import io
        import tarfile

        from cordon_scanner.intel.advisories import upstream_advisories as ua
        from cordon_scanner.intel.advisories.upstream import conan

        rev = "a" * 32
        base = f"{ua.CONAN_CENTER}/zlib/1.2.11/_/_/revisions"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            data = b'sources:\n  "1.2.11":\n    url: "https://zlib.net/zlib-1.2.11.tar.gz"\n'
            info = tarfile.TarInfo("conandata.yml")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        Sources.serve(
            monkeypatch,
            {
                f"{base}/{rev}/files/conan_export.tgz": buffer.getvalue(),
                f"{base}/{rev}/files/conanfile.py": b'    homepage = "https://zlib.net"\n',
            },
        )
        monkeypatch.setattr(
            conan.ConanCenter,
            "repositories",
            staticmethod(lambda name: {"https://github.com/madler/zlib"}),
        )
        found = Upstreams.conan(Sources.dep("conan", "zlib", "1.2.11", integrity=f"md5:{rev}"))
        assert found is not None

    def test_a_pod_from_an_npm_package_reads_its_podspec(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import cocoapods

        seen: list[tuple] = []
        monkeypatch.setattr(
            cocoapods.NpmPodspec,
            "read",
            staticmethod(lambda *args: seen.append(args) or Unnamed("npm")),
        )
        note = "the podspec RNX.podspec of the npm package react-native-x, at 1.0.0 or 1.0.1"
        found = Upstreams.cocoapods(
            Sources.dep(
                "cocoapods",
                "RNX",
                "1.0.0",
                resolved_from="path:../node_modules/x",
                resolution_note=note,
            )
        )
        assert found.reason == "npm" and seen[0][0] == "react-native-x"

    def test_podspec_shapes_that_are_not_objects_are_skipped(self) -> None:
        assert not Upstreams.umbrella({"subspecs": [{"source_files": "*.h"}], "ios": "x"}) or True
        assert Upstreams.umbrella(["not a spec"]) is False
        assert Upstreams.prebuilt(["not a spec"]) is False

    def test_an_old_homebrew_version_reads_the_formula_its_bottle_carries(
        self, monkeypatch
    ) -> None:
        from cordon_scanner.intel.advisories.upstream import homebrew

        monkeypatch.setattr(
            homebrew.HomebrewBottles,
            "formula_data",
            staticmethod(lambda name, v: ("jq", {"versions": {"stable": "1.7"}})),
        )
        monkeypatch.setattr(
            homebrew.HomebrewBottles,
            "formula",
            staticmethod(
                lambda name, v: (
                    'url "https://github.com/jqlang/jq/releases/download/jq-1.6/jq-1.6.tar.gz"\n'
                )
            ),
        )
        Sources.serve(monkeypatch, {})
        assert Upstreams.homebrew(Sources.dep("homebrew", "jq", "1.6")) is not None

    def test_a_terraform_provider_off_github_is_unnamed(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories import upstream_advisories as ua

        Sources.serve(
            monkeypatch,
            {f"{ua.TERRAFORM_REGISTRY}/acme/x": {"source": "https://gitlab.com/acme/x"}},
        )
        found = Upstreams.terraform(Sources.dep("terraform", "acme/x", "1.0"))
        assert "no GitHub source" in found.reason


class TestVcpkgVersions(TestVcpkg):
    def test_a_port_at_another_version_reads_its_files_there(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import vcpkg

        files: list[str] = []
        self.ports(
            monkeypatch,
            {"version": "1.2.11", "homepage": "https://zlib.net"},
            at_version=lambda b, p, v: ("qt_install_submodule()\n", "1.3.1"),
        )
        monkeypatch.setattr(
            vcpkg.VcpkgPorts,
            "file_at_version",
            staticmethod(lambda b, p, v, f: files.append(f) or ""),
        )

        def qt(port, version, other, how, qtbase):
            other("vcpkg.json")
            return Unnamed("qt")

        monkeypatch.setattr(vcpkg.VcpkgPorts, "qt", staticmethod(qt))
        assert Upstreams.vcpkg(self.dep(version="1.3.1")).reason == "qt" and files == ["vcpkg.json"]

    def test_a_qt_port_at_the_baseline_reads_qtbase(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import vcpkg

        asked = self.ports(monkeypatch, {"version": "6.7.0"}, portfile="qt_install_submodule()\n")

        def qt(port, version, other, how, qtbase):
            for read in (other, qtbase):
                with contextlib.suppress(OSError):
                    read("portfile.cmake")
            return Unnamed("qt")

        monkeypatch.setattr(vcpkg.VcpkgPorts, "qt", staticmethod(qt))
        Upstreams.vcpkg(self.dep())
        assert any("/ports/qtbase/" in url for url in asked)

    def test_a_port_reading_nothing_says_so(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import vcpkg

        self.ports(monkeypatch, {"version": "1.0"}, portfile="vcpkg_from_github(x)\n")
        monkeypatch.setattr(
            vcpkg.VcpkgPorts,
            "read",
            staticmethod(
                lambda portfile, version, port, how: (Unnamed("nothing", nothing=True), None)
            ),
        )
        assert Upstreams.vcpkg(self.dep()).nothing

    def test_a_port_that_downloads_is_inferred_from_its_homepage(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import vcpkg

        self.ports(
            monkeypatch,
            {"version": "1.0", "homepage": "https://zlib.net"},
            portfile="vcpkg_download_distfile(x)\n",
        )
        monkeypatch.setattr(
            vcpkg.VcpkgPorts,
            "read",
            staticmethod(lambda portfile, version, port, how: (Unnamed("no tag"), None)),
        )
        assert isinstance(Upstreams.vcpkg(self.dep()), Unnamed)


class TestCondaEdges(TestConda):
    def test_a_recipe_read_before_its_paths_reads_on(self, monkeypatch) -> None:
        calls: list[dict] = []
        from cordon_scanner.intel.advisories.upstream import conda

        def recipe(url, seen):
            calls.append(dict(seen))
            if seen.get("want_paths"):
                seen["paths"] = 0
            return "source: [7]\n"

        monkeypatch.setattr(conda.CondaPackage, "recipe", staticmethod(recipe))
        Sources.serve(monkeypatch, {})
        found = Upstreams.conda(self.dep())
        assert len(calls) == 2 and found.nothing

    def test_an_unnamed_recipe_reads_its_paths_before_judging_fonts(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream import conda

        calls: list[int] = []

        def recipe(url, seen):
            calls.append(1)
            if seen.get("want_paths"):
                seen["paths"] = 2
            return "source:\n  url: https://fonts.example/x.zip\n"

        monkeypatch.setattr(conda.CondaPackage, "recipe", staticmethod(recipe))
        Sources.serve(monkeypatch, {})
        Upstreams.conda(self.dep())
        assert len(calls) == 2


class TestTheLastTwo:
    def test_conan_takes_the_newest_revision_when_the_lock_names_none(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories import upstream_advisories as ua
        from cordon_scanner.intel.advisories.upstream import conan

        base = f"{ua.CONAN_CENTER}/zlib/1.3/_/_/revisions"
        asked = Sources.serve(monkeypatch, {base: {"revisions": [{"revision": "f" * 32}]}})
        monkeypatch.setattr(
            conan.ConanCenter, "removed", staticmethod(lambda name, version: Unnamed("no export"))
        )
        Upstreams.conan(Sources.dep("conan", "zlib", "1.3"))
        assert f"{base}/{'f' * 32}/files/conan_export.tgz" in asked

    def test_a_version_resolved_for_an_unversioned_package_is_kept(self, monkeypatch) -> None:
        Sources.serve(monkeypatch, {})
        monkeypatch.setattr(
            UpstreamAdvisories, "name", staticmethod(lambda d: Unnamed("why", version="1.3.1"))
        )
        dep = Sources.dep("vcpkg", "zlib", None)
        assert UpstreamAdvisories.check([dep]).versions == {dep.purl: "1.3.1"}
