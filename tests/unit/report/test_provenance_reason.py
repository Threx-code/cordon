"""Why a dependency has no provenance to check, said where the report says everything else about it.

A dependency of a registry that publishes no build provenance is `unsupported`; its record then carries `provenance_reason`, the
registry's reason in the words of `PROVENANCE_NOT_PUBLISHED` (what was read, and when). The JSON record has the key for every
dependency (null where the status is not that one) and the text report prints each ecosystem's reason once. The projects are the
repository's real lockfile cases."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from cordon_scanner.foundation.dependencies import PROVENANCE_NOT_PUBLISHED
from support import ROOT

CASES = ROOT / "tests" / "conformance" / "cases"


class Scan:
    @staticmethod
    def run(case: str, form: str, tmp_path: Path) -> str:
        target = tmp_path / "project"
        tmp_path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cp", "-R", str(CASES / case), str(target)], check=True)
        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "cordon_scanner",
                "scan",
                str(target),
                "--offline",
                "--no-cache",
                "--format",
                form,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        return run.stdout


class TestTheJsonRecord:
    def test_a_registry_that_publishes_none_gives_its_reason(self, tmp_path: Path) -> None:
        records = [
            d["record"]
            for d in json.loads(Scan.run("cargo/real-lock-v4", "json", tmp_path))["dependencies"]
        ]
        packages = [r for r in records if r["dependency_type"] != "platform"]
        assert packages
        for record in packages:
            assert record["provenance_status"] == "unsupported"
            assert record["provenance_reason"] == PROVENANCE_NOT_PUBLISHED["cargo"]

    def test_every_record_has_the_key_and_a_registry_that_can_be_checked_has_none(
        self, tmp_path: Path
    ) -> None:
        records = [
            d["record"]
            for d in json.loads(Scan.run("npm/real-npm-v3", "json", tmp_path))["dependencies"]
        ]
        assert records and all("provenance_reason" in r for r in records)
        assert all(r["provenance_reason"] is None for r in records)

    def test_a_reason_goes_only_with_the_unsupported_status(self, tmp_path: Path) -> None:
        for case in ("cargo/real-lock-v4", "npm/real-npm-v3", "composer/real-application"):
            for dependency in json.loads(Scan.run(case, "json", tmp_path / case.replace("/", "-")))[
                "dependencies"
            ]:
                record = dependency["record"]
                assert (record["provenance_reason"] is not None) <= (
                    record["provenance_status"] == "unsupported"
                )


class TestTheTextReport:
    @staticmethod
    def words(text: str) -> str:
        return " ".join(text.split())

    def test_each_ecosystem_reason_is_printed_once_in_the_tables_words(
        self, tmp_path: Path
    ) -> None:
        printed = self.words(Scan.run("cargo/real-lock-v4", "text", tmp_path))
        assert self.words(PROVENANCE_NOT_PUBLISHED["cargo"]) in printed
        assert printed.count(self.words(PROVENANCE_NOT_PUBLISHED["cargo"])) == 1

    def test_nothing_is_printed_for_a_registry_whose_provenance_can_be_checked(
        self, tmp_path: Path
    ) -> None:
        assert "provenance not published" not in Scan.run("npm/real-npm-v3", "text", tmp_path)
