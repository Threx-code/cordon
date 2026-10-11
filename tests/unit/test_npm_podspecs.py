"""CocoaPods pods whose podspec ships inside an npm package (React Native's third-party podspecs):
the reader names the package and the versions the pods at its root are at; the resolver reads the
podspec from the registry's verified tarball, and uses it only if it declares the locked version."""

from __future__ import annotations

from typing import ClassVar

from cordon_scanner.core.content import FileContent
from cordon_scanner.ecosystems.cocoapods import CocoaPodsEcosystem
from cordon_scanner.intel.upstream_advisories import NpmPodspec, Unnamed, Upstream

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
        monkeypatch.setattr(
            NpmPodspec, "package", staticmethod(lambda package, version: self.FILES)
        )

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
