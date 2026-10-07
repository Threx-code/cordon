"""Ecosystem depth (advanced gap P5), with every registry substituted.

* `scan pkg:<type>/... --online` compares a release with the one before it for crates.io,
  RubyGems, NuGet, Go, Hex, pub and Maven Central, not npm and PyPI only.
* Go, Hex, pub and Maven package URLs are fetchable at all.
* A Maven range in a pom with no lockfile resolves, online, to what Maven itself would pick.
"""

from __future__ import annotations

import pytest

from cordon_scanner import Scanner
from cordon_scanner.core.config import Config
from cordon_scanner.intel.more_registries import MoreRegistries
from cordon_scanner.intel.registry_client import PackageArchive
from cordon_scanner.sources.package import PackageTarget
from cordon_scanner.sources.previous import Identity, PreviousRelease

POM = """<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>app</artifactId><version>1</version>
<dependencies><dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>[2.0,2.0.10)</version></dependency></dependencies></project>
"""


class TestPackageUrls:
    @pytest.mark.parametrize(
        ("purl", "ecosystem", "name"),
        [
            ("pkg:golang/github.com/pkg/errors@v0.9.1", "gomod", "github.com/pkg/errors"),
            ("pkg:hex/jason@1.4.4", "hex", "jason"),
            ("pkg:pub/http@1.2.1", "pub", "http"),
            ("pkg:maven/org.slf4j/slf4j-api@2.0.13", "maven", "org.slf4j:slf4j-api"),
        ],
    )
    def test_each_registry_with_an_archive_is_fetchable(self, purl, ecosystem, name) -> None:
        target = PackageTarget.parse(purl)
        assert (target.ecosystem, target.name) == (ecosystem, name)


class TestThePreviousRelease:
    @pytest.mark.parametrize(
        "ecosystem", ["cargo", "rubygems", "nuget", "gomod", "hex", "pub", "maven"]
    )
    def test_by_the_ecosystems_own_version_order(self, monkeypatch, tmp_path, ecosystem) -> None:
        monkeypatch.setattr(
            MoreRegistries,
            "versions",
            staticmethod(lambda eco, name: ["1.9.0", "1.10.0", "1.10.1", "2.0.0", "1.2.0"]),
        )
        fetched: list[str] = []

        def archive(eco, name, version):
            fetched.append(version)
            return PackageArchive(
                eco,
                name,
                version,
                f"{name.replace(':', '-')}-{version}.tgz",
                b"\x1f\x8b" + b"\x00" * 20,
            )

        monkeypatch.setattr(
            "cordon_scanner.intel.registry_client.RegistryClient.package_archive",
            staticmethod(archive),
        )
        found = PreviousRelease.fetch_previous(Identity(ecosystem, "example", "1.10.1"), tmp_path)
        assert found is not None and fetched == ["1.10.0"] and found.label == "example 1.10.0"

    def test_the_first_release_has_none(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(MoreRegistries, "versions", staticmethod(lambda eco, name: ["1.0.0"]))
        assert (
            PreviousRelease.fetch_previous(Identity("cargo", "example", "1.0.0"), tmp_path) is None
        )


class TestTheGoChecksumDatabase:
    def test_a_version_recorded_without_v_is_asked_for_canonically(self, monkeypatch) -> None:
        """Cordon records `0.9.1`; sum.golang.org answers only `v0.9.1`, and refused every lookup
        with HTTP 400 -- so no go.sum hash was ever compared with the log."""
        asked: list[str] = []

        def text(url: str) -> str:
            asked.append(url)
            if "/lookup/" in url:
                return (
                    "github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=\n"
                )
            return "v0.9.0\nv0.9.1\n"

        monkeypatch.setattr(MoreRegistries, "_text", staticmethod(text))
        monkeypatch.setattr(
            MoreRegistries, "_json", staticmethod(lambda url: {"Version": "v0.9.1"})
        )
        facts = MoreRegistries.gomod("github.com/pkg/errors", "0.9.1")
        assert any(url.endswith("/lookup/github.com/pkg/errors@v0.9.1") for url in asked)
        assert (
            facts.digests == ("h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",)
            and facts.version == "0.9.1"
        )


class TestMavenRanges:
    def test_resolved_online_to_the_highest_admitted_release(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(
            MoreRegistries,
            "versions",
            staticmethod(lambda eco, name: ["1.7.36", "2.0.0", "2.0.9", "2.0.10", "2.0.13"]),
        )
        (tmp_path / "pom.xml").write_text(POM)
        [dependency] = (
            Scanner(Config.default().with_overrides(use_cache=False, offline=False), detectors=())
            .scan(tmp_path)
            .dependencies
        )
        assert dependency.version == "2.0.9" and "resolved online" in (
            dependency.resolution_note or ""
        )

    def test_offline_it_stays_unresolved(self, monkeypatch, tmp_path) -> None:
        def refuse(eco, name):
            raise AssertionError("an offline scan asked a registry")

        monkeypatch.setattr(MoreRegistries, "versions", staticmethod(refuse))
        (tmp_path / "pom.xml").write_text(POM)
        [dependency] = (
            Scanner(Config.default().with_overrides(use_cache=False), detectors=())
            .scan(tmp_path)
            .dependencies
        )
        assert dependency.version is None
