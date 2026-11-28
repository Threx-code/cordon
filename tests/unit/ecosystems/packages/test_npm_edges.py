"""package-lock.json links, scopes and unsupported lock names, and published package manifests (`ecosystems/packages/npm.py`)."""

from __future__ import annotations

import json
from typing import Any

from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits
from cordon_scanner.foundation.models import Scope


class _Kit:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["npm"]

    @staticmethod
    def lock(data: Any, path: str = "package-lock.json") -> Any:
        return _Kit.adapter().parse_lockfile(_Kit.fc(path, json.dumps(data)))


class TestPublishedManifest:
    def test_an_entry_point_that_is_a_pattern_or_not_a_string_is_not_followed(self) -> None:
        members = {"package/index.js": "index text", "package/lib/a.js": "a text"}
        found = _Kit.adapter().library_entries(
            members, {"main": "./lib/*.js", "exports": {".": "./lib/a.js", "x": 5}}, False
        )
        assert found == {"a text"}

    def test_the_repository_is_a_string_or_the_url_of_an_object(self) -> None:
        adapter = _Kit.adapter()
        assert adapter.published_repository(
            {"repository": {"url": " git+https://x.example/y.git "}}
        ) == ("git+https://x.example/y.git")
        assert adapter.published_repository({"repository": "o/r"}) == "o/r"
        assert adapter.published_repository({"repository": {"type": "git"}}) == ""


class TestLockNames:
    def test_a_file_that_is_no_lockfile_of_npm_is_unsupported_by_name(self) -> None:
        graph = _Kit.adapter().parse_lockfile(_Kit.fc("weird.lock", "x"))
        assert graph.parse_error == "unsupported lockfile: weird.lock"


class TestPackageLockV3:
    def test_a_link_to_a_workspace_member_is_that_member_and_not_a_second_package(self) -> None:
        graph = _Kit.lock(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "root",
                        "workspaces": ["packages/*"],
                        "dependencies": {"util": "*"},
                    },
                    "node_modules/util": {"resolved": "packages/util", "link": True},
                    "packages/util": {"name": "util", "version": "1.0.0"},
                },
            }
        )
        assert [e.name for e in graph.entries] == ["util"]

    def test_a_dependency_that_is_installed_nowhere_is_kept_by_its_bare_name(self) -> None:
        graph = _Kit.lock(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "dependencies": {"a": "1"}},
                    "node_modules/a": {
                        "version": "1.0.0",
                        "integrity": "sha512-" + "A" * 86 + "==",
                        "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                        "dependencies": {"ghost": "1"},
                    },
                },
            }
        )
        [entry] = graph.entries
        assert entry.dependencies == ("ghost",)

    def test_a_package_that_is_dev_or_optional_everywhere_it_is_used_is_a_dev_package(self) -> None:
        graph = _Kit.lock(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root", "dependencies": {"a": "1"}},
                    "node_modules/a": {
                        "version": "1.0.0",
                        "devOptional": True,
                        "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                        "integrity": "sha512-" + "A" * 86 + "==",
                    },
                },
            }
        )
        assert graph.entries[0].scope is Scope.DEV

    def test_a_package_nested_inside_a_linked_folder_with_no_url_is_local(self) -> None:
        graph = _Kit.lock(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root"},
                    "vendor/thing": {"name": "thing", "version": "1.0.0"},
                },
            }
        )
        assert graph.entries[0].local is True


class TestEdgeWalk:
    def test_a_location_nested_past_the_walk_limit_resolves_nothing(self) -> None:
        from cordon_scanner.ecosystems.packages.npm import NpmEcosystem

        location = "/".join(["node_modules/p"] * 70)
        packages = {"": {}, location: {"version": "1.0.0"}}
        assert NpmEcosystem._resolve_edge(packages, location, "ghost") is None


class TestPackageLockV1:
    def test_a_dependency_entry_that_is_not_an_object_is_skipped(self) -> None:
        graph = _Kit.lock(
            {
                "lockfileVersion": 1,
                "dependencies": {
                    "junk": "text",
                    "a": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                        "integrity": "sha512-" + "A" * 86 + "==",
                    },
                },
            }
        )
        assert [e.name for e in graph.entries] == ["a"]


class TestHelpers:
    def test_a_dependency_that_is_a_link_resolves_to_the_member_it_points_at(self) -> None:
        from cordon_scanner.ecosystems.packages.npm import NpmEcosystem

        packages = {
            "node_modules/util": {"link": True, "resolved": "packages/util"},
            "packages/util": {"name": "util", "version": "1.0.0"},
        }
        assert NpmEcosystem._resolve_edge(packages, "", "util") == "util@1.0.0"

    def test_a_linked_package_is_local_whatever_else_it_says(self) -> None:
        from cordon_scanner.ecosystems.packages.npm import NpmEcosystem

        assert NpmEcosystem._is_local_package("node_modules/a", {"link": True}, None) is True
        assert (
            NpmEcosystem._is_local_package(
                "node_modules/a", {}, "https://registry.npmjs.org/a/-/a-1.tgz"
            )
            is False
        )
