"""The scan upload names, for each dependency, the packages of the lockfile graph that depend on it, so the platform can rebuild the edges."""

from __future__ import annotations

import json
from pathlib import Path

from cordon_scanner import Scanner
from cordon_scanner.cloud.results import SignedResults
from cordon_scanner.foundation.config.settings import Config


class Graph:
    @staticmethod
    def uploaded(root: Path) -> dict[str, dict]:
        (root / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "dependencies": {"a": "1.0.0"}}),
            encoding="utf-8",
        )
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "demo", "version": "1.0.0", "dependencies": {"a": "1.0.0"}},
                        "node_modules/a": {
                            "version": "1.0.0",
                            "dependencies": {"b": "1.0.0", "c": "1.0.0"},
                        },
                        "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "1.0.0"}},
                        "node_modules/c": {"version": "1.0.0"},
                    },
                }
            ),
            encoding="utf-8",
        )
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(root)
        found = json.loads(SignedResults.results_bytes(result))["dependencies"]
        return {d["name"]: d for d in found}


class TestTheUploadCarriesParents:
    def test_a_dependency_lists_each_package_that_depends_on_it(self, tmp_path: Path) -> None:
        found = Graph.uploaded(tmp_path)
        assert found["b"]["parents"] == ["a"]
        assert found["c"]["parents"] == ["a", "b"]

    def test_a_top_level_dependency_has_no_parent_package(self, tmp_path: Path) -> None:
        assert "parents" not in Graph.uploaded(tmp_path)["a"]


class TestTheUploadCarriesVendoredCopies:
    def test_a_bundled_package_is_listed_with_its_state_and_a_plain_tree_lists_none(
        self, tmp_path: Path
    ) -> None:
        vendor = tmp_path / "vendor" / "left-pad"
        vendor.mkdir(parents=True)
        (vendor / "package.json").write_text(
            '{"name":"left-pad","version":"1.3.0"}', encoding="utf-8"
        )
        (vendor / "index.js").write_text("module.exports = pad;\n", encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False, offline=True)).scan(
            tmp_path
        )
        copies = SignedResults.vendored(tmp_path)
        document = json.loads(SignedResults.results_bytes(result, copies))
        assert document["vendored"] == [
            {
                "path": "vendor/left-pad",
                "purl": "pkg:npm/left-pad@1.3.0",
                "digest": copies[0]["digest"],
            }
        ]
        assert "vendored" not in json.loads(SignedResults.results_bytes(result))
