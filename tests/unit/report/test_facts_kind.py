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
from typing import Any

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
    def as_directory(root: Path) -> Path:
        target = root / "repository"
        target.mkdir()
        for name, text in FILES.items():
            (target / name).write_text(text, encoding="utf-8")
        return target

    @staticmethod
    def as_package(root: Path) -> Path:
        target = root / "p-1.0.0.tgz"
        with tarfile.open(target, "w:gz") as archive:
            for name, text in FILES.items():
                data = text.encode()
                info = tarfile.TarInfo(f"package/{name}")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return target

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
