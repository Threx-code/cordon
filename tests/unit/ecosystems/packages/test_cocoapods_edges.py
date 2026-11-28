"""Podfiles, podspecs and Podfile.lock on the shapes written less often (`ecosystems/packages/cocoapods.py`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.ecosystems.packages.cocoapods import PodfileLock
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["cocoapods"]

    @staticmethod
    def read(path: str, text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc(path, text))


class TestPodfile:
    def test_blocks_nested_in_a_target_and_a_def_inside_it_keep_the_targets_pods(self) -> None:
        text = (
            "target 'App' do\n"
            "  def shared\n    pod 'A', '1.0'\n  end\n"
            "  abstract_target 'Inner' do\n    pod 'B', '2.0'\n  end\n"
            "  post_install do |installer|\n    puts 'x'\n  end\n"
            "end\n"
        )
        manifest = _Kit.read("Podfile", text)
        assert {d.name for d in manifest.dependencies} == {"A", "B"}
        assert [h.name for h in manifest.hooks] == ["post_install"]


class TestPodspec:
    def test_script_phases_and_vendored_frameworks_are_build_hooks(self) -> None:
        text = (
            "Pod::Spec.new do |s|\n  s.name = 'P'\n  s.version = '1.0'\n"
            "  s.script_phases = [{ name: 'x', script: 'echo' }]\n"
            "  s.vendored_frameworks = 'Frameworks/A.xcframework', 'Frameworks/B.xcframework'\nend\n"
        )
        names = [h.name for h in _Kit.read("P.podspec", text).hooks]
        assert "script_phases" in names
        assert "vendored framework Frameworks/A.xcframework" in names
        assert "vendored framework Frameworks/B.xcframework" in names


class TestPodfileLock:
    def test_a_file_whose_pod_lines_are_all_unreadable_is_refused_with_the_count(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("Podfile.lock", "PODS:\n  - !!!\n  - ???\n"))
        assert graph.parse_error == "2 PODS line(s) could not be read"

    def test_a_podspec_in_an_npm_package_names_the_versions_installed_from_it_and_none_when_none_are(
        self,
    ) -> None:
        podspec = "../node_modules/rn-thing/ios/Thing.podspec"
        external = {"Thing": {"path": "../node_modules/rn-thing"}}
        pods = {"Thing": {"version": "1.2.3"}}
        assert PodfileLock.npm_note(podspec, external, pods) == (
            "the podspec ios/Thing.podspec of the npm package rn-thing, at 1.2.3"
        )
        assert PodfileLock.npm_note(podspec, {}, {}) is None
        assert PodfileLock.npm_note("Thing.podspec", external, pods) is None
