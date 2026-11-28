"""vcpkg configuration, manifests and lock files on the shapes written less often (`ecosystems/packages/vcpkg.py`)."""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["vcpkg"]

    @staticmethod
    def manifest(path: str, data: Any) -> Any:
        text = data if isinstance(data, str) else json.dumps(data)
        return _Kit.adapter().parse_manifest(_Kit.fc(path, text))


class TestConfiguration:
    PATH = "vcpkg-configuration.json"

    def test_a_default_registry_set_to_null_is_said_to_be_disabled(self) -> None:
        manifest = _Kit.manifest(self.PATH, {"default-registry": None})
        assert "default registry disabled" in manifest.sources

    def test_each_registry_kind_names_where_it_is_and_the_others_are_skipped(self) -> None:
        manifest = _Kit.manifest(
            self.PATH,
            {
                "registries": [
                    "text",
                    {
                        "kind": "artifact",
                        "location": "https://a.example.invalid/x",
                        "name": "a",
                        "packages": ["p"],
                    },
                    {"kind": "mystery", "packages": ["q"]},
                ]
            },
        )
        assert not manifest.parse_error
        assert manifest.sources[0].startswith("registry artifact https://a.example.invalid/x")
        assert manifest.sources[1].startswith("registry mystery")

    def test_text_that_is_not_json_is_an_error(self) -> None:
        assert _Kit.manifest(self.PATH, "{nope").parse_error.startswith("invalid JSON")


class TestManifest:
    def test_dependencies_that_are_not_a_list_are_refused(self) -> None:
        manifest = _Kit.manifest("vcpkg.json", {"name": "app", "dependencies": "zlib"})
        assert manifest.parse_error == "`dependencies` is not a list"

    def test_a_configuration_beside_the_manifest_that_cannot_be_read_is_ignored(self) -> None:
        main = _Kit.fc("p/vcpkg.json", json.dumps({"name": "app", "dependencies": ["zlib"]}))
        files = {
            "p/vcpkg.json": main,
            "p/vcpkg-configuration.json": _Kit.fc("p/vcpkg-configuration.json", "{nope"),
        }
        manifest = _Kit.adapter().parse_in_tree(main, files)
        assert [d.name for d in manifest.dependencies] == ["zlib"]

    def test_the_platforms_a_manifest_supports_are_named_as_a_source(self) -> None:
        manifest = _Kit.manifest(
            "vcpkg.json", {"name": "app", "supports": "windows & !arm", "dependencies": ["zlib"]}
        )
        assert "supports windows & !arm" in manifest.sources


class TestLock:
    def test_a_lock_that_is_not_json_is_refused(self) -> None:
        assert _Kit.manifest("vcpkg-lock.json", "{nope").parse_error.startswith("invalid JSON")

    def test_a_registry_that_is_not_a_map_of_references_is_refused(self) -> None:
        manifest = _Kit.manifest("vcpkg-lock.json", {"https://r.example.invalid": "text"})
        assert "not a map of references to commits" in manifest.parse_error

    def test_a_reference_not_locked_to_a_commit_is_refused(self) -> None:
        manifest = _Kit.manifest("vcpkg-lock.json", {"https://r.example.invalid": {"HEAD": "main"}})
        assert manifest.parse_error == "a registry reference not locked to a commit"

    def test_a_lock_in_the_lock_file_position_is_read_for_its_errors_only(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("vcpkg-lock.json", "{nope"))
        assert graph.entries == () and graph.parse_error.startswith("invalid JSON")
