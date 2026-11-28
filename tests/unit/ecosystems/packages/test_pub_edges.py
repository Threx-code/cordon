"""pubspec dependency values, files and locks on the shapes written less often (`ecosystems/packages/pub.py`)."""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.ecosystems.packages.pub import PubSpec
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["pub"]


class TestSpecValues:
    def test_each_form_of_a_dependency_value_is_one_specification(self) -> None:
        assert PubSpec.spec(None, "") == ("any", None)
        assert PubSpec.spec("^1.2.0", "") == ("^1.2.0", None)
        assert PubSpec.spec(["x"], "") == ("*", None)
        assert PubSpec.spec({"git": "https://git.example.invalid/a.git"}, "") == (
            "git+https://git.example.invalid/a.git",
            None,
        )
        assert PubSpec.spec(
            {"git": {"url": "https://g.example.invalid/a.git", "ref": "v1"}}, ""
        ) == (
            "git+https://g.example.invalid/a.git#v1",
            None,
        )


class TestPubspecs:
    def read(self, text: str) -> Any:
        return _Kit.adapter().parse_manifest(_Kit.fc("pubspec.yaml", text))

    def test_an_empty_pubspec_has_no_name_and_one_that_is_not_a_mapping_is_refused(self) -> None:
        assert self.read("").parse_error == "a pubspec has no `name`"
        assert "mapping" in self.read("- a\n").parse_error

    def test_a_dependencies_section_that_is_not_a_mapping_is_refused(self) -> None:
        assert self.read("name: p\ndependencies: [a]\n").parse_error == (
            "`dependencies` is not a mapping"
        )


class TestLocksAndConfigs:
    def test_a_lock_whose_packages_is_not_a_mapping_is_refused(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("pubspec.lock", "packages: [a]\n"))
        assert graph.parse_error == "no `packages` mapping"

    def test_a_package_config_that_is_not_json_or_lists_no_packages_is_refused(self) -> None:
        bad = _Kit.adapter().parse_lockfile(_Kit.fc("package_config.json", "{nope"))
        assert bad.parse_error.startswith("invalid JSON")
        none = _Kit.adapter().parse_lockfile(_Kit.fc("package_config.json", "{}"))
        assert none.parse_error == "no `packages` list"

    def test_a_package_entry_that_is_not_an_object_is_skipped(self) -> None:
        text = json.dumps(
            {
                "packages": [
                    "text",
                    {"name": "http", "rootUri": "file:///c/hosted/pub.dev/http-1.2.0/"},
                ]
            }
        )
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("package_config.json", text))
        assert [(e.name, e.version) for e in graph.entries] == [("http", "1.2.0")]


class TestReleaseNames:
    def test_a_published_pubspec_is_named_by_its_name_and_version(self) -> None:
        adapter = _Kit.adapter()
        pattern = adapter.release_manifest()
        found = pattern.search("http-1.2.0.tar.gz!pubspec.yaml")
        assert adapter.release_identity(
            "x!pubspec.yaml", "name: http\nversion: 1.2.0\n", found
        ) == (
            "http",
            "1.2.0",
        )
        assert adapter.release_identity("x!pubspec.yaml", "name: http\n", found) is None
