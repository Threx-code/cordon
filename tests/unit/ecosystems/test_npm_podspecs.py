"""CocoaPods pods whose podspec ships inside an npm package (React Native's third-party podspecs):
the reader names the package and the versions the pods at its root are at; the resolver reads the
podspec from the registry's verified tarball, and uses it only if it declares the locked version."""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.ecosystems.packages.cocoapods import CocoaPodsEcosystem
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.intel.advisories.upstream.base import Unnamed, Upstream
from cordon_scanner.intel.advisories.upstream.cocoapods import NpmPodspec

LOCK = """PODS:
  - DoubleConversion (1.1.6)
  - React-Core (0.72.6)
  - RCT-Folly (2021.07.22.00)

DEPENDENCIES:
  - DoubleConversion (from `../node_modules/react-native/third-party-podspecs/DoubleConversion.podspec`)
  - React-Core (from `../node_modules/react-native/`)
  - RCT-Folly (from `../node_modules/react-native/third-party-podspecs/RCT-Folly.podspec`)

EXTERNAL SOURCES:
  DoubleConversion:
    :podspec: "../node_modules/react-native/third-party-podspecs/DoubleConversion.podspec"
  React-Core:
    :path: "../node_modules/react-native/"
  RCT-Folly:
    :podspec: "../node_modules/react-native/third-party-podspecs/RCT-Folly.podspec"

COCOAPODS: 1.12.1
"""


class TestTheReader:
    def test_a_podspec_inside_an_npm_package_is_named_with_the_packages_version(self) -> None:
        graph = CocoaPodsEcosystem().parse_lockfile(
            FileContent.from_bytes("ios/Podfile.lock", LOCK.encode())
        )
        notes = {e.name: e.note for e in graph.entries}
        assert notes["DoubleConversion"] == (
            "the podspec third-party-podspecs/DoubleConversion.podspec of the npm package react-native, at 0.72.6"
        )
        assert notes["React-Core"] is None


class TestTheResolver:
    FILES: ClassVar[dict[str, str]] = {
        "third-party-podspecs/DoubleConversion.podspec": (
            "Pod::Spec.new do |spec|\n  spec.version = '1.1.6'\n"
            "  spec.source = { :git => 'https://github.com/google/double-conversion.git',\n"
            '                  :tag => "v#{spec.version}" }\nend\n'
        ),
        "third-party-podspecs/RCT-Folly.podspec": (
            "folly_config = get_folly_config()\nfolly_release_version = folly_config[:version]\n"
            "folly_git_url = folly_config[:git]\nPod::Spec.new do |spec|\n"
            "  spec.version = folly_release_version\n"
            '  spec.source = { :git => folly_git_url,\n                  :tag => "v#{folly_release_version}" }\nend\n'
        ),
        "scripts/cocoapods/helpers.rb": (
            "@@folly_config = {\n    :version => '2021.07.22.00',\n    :git => 'https://github.com/facebook/folly.git',\n}\n"
        ),
        "sdks/hermes-engine/hermes-engine.podspec": "spec.version = version\nspec.source = source\n",
        "sdks/.hermesversion": "hermes-2023-08-07-RNv0.72.4-813b2def12bc9df02654b3e3653ae4a68d0572e0\n",
    }

    def serve(self, monkeypatch) -> None:
        """The registry holds react-native 0.72.6 alone; any other version is its 404."""
        from cordon_scanner.intel.registries.registry_client import PackageNotFound

        def package(package: str, version: str) -> dict[str, str]:
            if version != "0.72.6":
                raise PackageNotFound(f"{package}@{version}")
            return self.FILES

        monkeypatch.setattr(NpmPodspec, "package", staticmethod(package))

    def test_a_literal_version_and_an_interpolated_tag(self, monkeypatch) -> None:
        self.serve(monkeypatch)
        found = NpmPodspec.read(
            "react-native",
            "third-party-podspecs/DoubleConversion.podspec",
            ["0.72.6"],
            "1.1.6",
            "x",
        )
        assert isinstance(found, Upstream)
        assert found.query == {
            "package": {"name": "https://github.com/google/double-conversion", "ecosystem": "GIT"},
            "version": "v1.1.6",
        }

    def test_values_from_the_packages_own_helpers(self, monkeypatch) -> None:
        self.serve(monkeypatch)
        found = NpmPodspec.read(
            "react-native",
            "third-party-podspecs/RCT-Folly.podspec",
            ["0.72.6"],
            "2021.07.22.00",
            "x",
        )
        assert isinstance(found, Upstream) and found.query["version"] == "v2021.07.22.00"

    def test_a_podspec_declaring_another_version_is_not_used(self, monkeypatch) -> None:
        self.serve(monkeypatch)
        found = NpmPodspec.read(
            "react-native",
            "third-party-podspecs/DoubleConversion.podspec",
            ["0.72.6"],
            "1.1.5",
            "x",
        )
        assert isinstance(found, Unnamed) and "holds" in found.reason

    def test_hermes_at_react_natives_version_is_the_pinned_commit(self, monkeypatch) -> None:
        self.serve(monkeypatch)
        found = NpmPodspec.read(
            "react-native", "sdks/hermes-engine/hermes-engine.podspec", ["0.72.6"], "0.72.6", "x"
        )
        assert isinstance(found, Upstream) and found.query == {
            "commit": "813b2def12bc9df02654b3e3653ae4a68d0572e0"
        }
        other = NpmPodspec.read(
            "react-native",
            "sdks/hermes-engine/hermes-engine.podspec",
            ["0.72.6"],
            "250829098.0.1",
            "x",
        )
        assert isinstance(other, Unnamed)


class TestNewerReleases:
    """React Native 0.74 and later: a config returned by a method, a podspec versioned by the
    package, and Hermes named by version.properties."""

    FILES: ClassVar[dict[str, str]] = {
        "scripts/cocoapods/helpers.rb": (
            "module Helpers\n  class Constants\n"
            "    def self.folly_config\n        return {\n"
            "            :version => '2024.01.01.00',\n"
            "            :compiler_flags => '-DFOLLY_NO_CONFIG'\n        }\n    end\n"
            "  end\nend\n"
        ),
        "third-party-podspecs/RCT-Folly.podspec": (
            "folly_config = get_folly_config()\n"
            "folly_release_version = folly_config[:version]\n"
            "Pod::Spec.new do |spec|\n"
            "  spec.version = folly_release_version\n"
            "  spec.source = { :git => 'https://github.com/facebook/folly.git',\n"
            '                  :tag => "v#{folly_release_version}" }\n'
            "end\n"
        ),
        "React-Core-prebuilt.podspec": (
            'package = JSON.parse(File.read(File.join(__dir__, "package.json")))\n'
            "version = package['version']\n"
            "source = ReactNativeCoreUtils.resolve_podspec_source()\n"
            "Pod::Spec.new do |s|\n  s.version = version\n  s.source = source\nend\n"
        ),
        "third-party-podspecs/ReactNativeDependencies.podspec": (
            "version = package['version']\n"
            "source = ReactNativeDependenciesUtils.resolve_podspec_source()\n"
            "Pod::Spec.new do |spec|\n  spec.version = version\n  spec.source = source\nend\n"
        ),
        "sdks/hermes-engine/hermes-engine.podspec": "spec.version = version\n",
        "sdks/hermes-engine/version.properties": (
            "HERMES_VERSION_NAME=0.14.0\nHERMES_V1_VERSION_NAME=250829098.0.9\n"
        ),
    }

    def serve(self, monkeypatch) -> None:
        from cordon_scanner.intel.registries.registry_client import PackageNotFound

        def package(package: str, version: str) -> dict[str, str]:
            if version != "0.84.1":
                raise PackageNotFound(f"{package}@{version}")
            return self.FILES

        monkeypatch.setattr(NpmPodspec, "package", staticmethod(package))

    def test_a_config_a_method_returns(self, monkeypatch) -> None:
        self.serve(monkeypatch)
        found = NpmPodspec.read(
            "react-native",
            "third-party-podspecs/RCT-Folly.podspec",
            ["0.84.1"],
            "2024.01.01.00",
            "x",
        )
        assert isinstance(found, Upstream) and found.query["version"] == "v2024.01.01.00"

    def test_react_natives_own_core_prebuilt(self, monkeypatch) -> None:
        self.serve(monkeypatch)
        found = NpmPodspec.read(
            "react-native", "React-Core-prebuilt.podspec", ["0.84.1"], "0.84.1", "x"
        )
        assert isinstance(found, Upstream)
        assert found.query == {
            "package": {"name": "react-native", "ecosystem": "npm"},
            "version": "0.84.1",
        }

    def test_a_bundle_of_third_parties_is_not_the_package(self, monkeypatch) -> None:
        self.serve(monkeypatch)
        found = NpmPodspec.read(
            "react-native",
            "third-party-podspecs/ReactNativeDependencies.podspec",
            ["0.84.1"],
            "0.84.1",
            "x",
        )
        assert isinstance(found, Unnamed)

    def test_hermes_named_by_version_properties(self, monkeypatch) -> None:
        from cordon_scanner.intel.advisories.upstream.tags import TagInference

        self.serve(monkeypatch)
        asked: list[tuple[str, str]] = []

        def infer(repository: str, version: str, names, how: str) -> Upstream:
            asked.append((repository, version))
            return Upstream({"commit": "a" * 40}, how)

        monkeypatch.setattr(TagInference, "infer", staticmethod(infer))
        found = NpmPodspec.read(
            "react-native",
            "sdks/hermes-engine/hermes-engine.podspec",
            ["0.84.1"],
            "250829098.0.9",
            "x",
        )
        assert isinstance(found, Upstream) and asked == [
            ("https://github.com/facebook/hermes", "250829098.0.9")
        ]
        other = NpmPodspec.read(
            "react-native",
            "sdks/hermes-engine/hermes-engine.podspec",
            ["0.84.1"],
            "250829098.0.8",
            "x",
        )
        assert isinstance(other, Unnamed)
