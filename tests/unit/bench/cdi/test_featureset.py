"""A recorded scan row becomes a `FeatureSet` by one versioned function that reuses what the scan already made, and calls no detector of its own.

The function reads the row's findings and its package facts; whether a finding is intel or content is `VerdictFeatures.is_intel`, the facts are `VerdictFeatures.package`'s, and the content digest is a
key over the content features alone. The test lists what the module calls out of the scanner and shows it is that and nothing else: no detector, no analyser, no scan.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from support import ROOT

sys.path.insert(0, str(ROOT))

from bench.cdi import featureset
from bench.cdi.featureset import EXTRACTOR, EXTRACTOR_VERSION, FeatureSetBuilder

ROW: dict[str, Any] = {
    "sha256": "ab" * 32,
    "findings": [
        ["MALWARE.EXFIL.001", "high", "high", "malicious", "pkg/index.js", 3, "capability"],
        [
            "SUSPECT.INSTALL.SCRIPT.001",
            "medium",
            "medium",
            "suspicious",
            "package.json",
            1,
            "install_scripts",
        ],
    ],
    "verdict": {"package": {"hook": 1.0, "n_deps": 2.0, "can_egress": 1.0}},
}


def build(row: dict[str, Any] = ROW, **versions: str) -> dict[str, Any]:
    return FeatureSetBuilder.build_featureset(
        row, artifact_id="art:fx@1.0", ecosystem="npm", versions=versions or None
    )


class TestARecordedRowBecomesAFeatureSet:
    def test_the_findings_and_the_package_facts_are_its_features(self) -> None:
        record = build()
        names = {f["name"] for f in record["features"]}
        assert {
            "finding:MALWARE.EXFIL.001",
            "finding:SUSPECT.INSTALL.SCRIPT.001",
            "pkg:hook",
            "pkg:n_deps",
            "pkg:can_egress",
        } <= names
        assert record["ecosystem"] == "npm" and record["artifact_id"] == "art:fx@1.0"

    def test_the_slot_is_read_from_the_finding_path(self) -> None:
        slots = {f["name"]: f["slot"] for f in build()["features"]}
        assert (
            slots["finding:MALWARE.EXFIL.001"] == "code"
            and slots["finding:SUSPECT.INSTALL.SCRIPT.001"] == "packaging"
        )

    def test_the_same_row_gives_the_same_bytes(self) -> None:
        assert json.dumps(build(), sort_keys=True) == json.dumps(build(), sort_keys=True)

    def test_the_content_digest_does_not_move_with_the_versions_or_an_intel_finding(self) -> None:
        intel = {
            **ROW,
            "findings": [
                *ROW["findings"],
                ["INTEL.KNOWN_MALWARE.001", "high", "high", "malicious", "", 0, "intel"],
            ],
        }
        assert (
            build(scanner="a")["featureset_digest"]
            == build(scanner="b")["featureset_digest"]
            == build(intel)["featureset_digest"]
        )

    def test_another_content_is_another_digest(self) -> None:
        other = {**ROW, "verdict": {"package": {"hook": 0.0, "n_deps": 2.0, "can_egress": 1.0}}}
        assert build()["featureset_digest"] != build(other)["featureset_digest"]


class TestTheFunctionIsVersioned:
    def test_the_record_names_the_extractor_and_its_version(self) -> None:
        assert build()["extractors"][EXTRACTOR] == EXTRACTOR_VERSION

    def test_a_new_version_is_in_every_feature_and_the_record(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(featureset, "EXTRACTOR_VERSION", "9.9.9")
        record = build()
        assert record["extractors"][EXTRACTOR] == "9.9.9" and {
            f["extractor_version"] for f in record["features"]
        } == {"9.9.9"}


class TestNoDetectorIsDuplicated:
    PATH = ROOT / "bench" / "cdi" / "featureset.py"
    CALLED = ("VerdictFeatures.COSMETIC", "VerdictFeatures.is_intel")
    """What the module takes from the scanner, by name: nothing else."""

    @classmethod
    def used_from_the_scanner(cls) -> list[str]:
        used = set()
        for node in ast.walk(ast.parse(cls.PATH.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == "VerdictFeatures"
            ):
                used.add(f"VerdictFeatures.{node.attr}")
        return sorted(used)

    def test_it_lists_what_it_calls_out_of_the_scanner(self) -> None:
        assert self.used_from_the_scanner() == list(self.CALLED)

    def test_it_imports_nothing_of_the_scanner_but_the_verdict_features(self) -> None:
        tree = ast.parse(self.PATH.read_text(encoding="utf-8"))
        modules = [
            n.module
            for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("cordon_scanner")
        ]
        modules += [
            a.name
            for n in ast.walk(tree)
            if isinstance(n, ast.Import)
            for a in n.names
            if a.name.startswith("cordon_scanner")
        ]
        assert modules == ["cordon_scanner.decide.verdict"]

    def test_no_detector_analyser_engine_or_scan_is_imported(self) -> None:
        text = self.PATH.read_text(encoding="utf-8")
        for banned in (
            "cordon_scanner.detect",
            "cordon_scanner.analysis",
            "cordon_scanner.engine",
            "Scanner(",
        ):
            assert banned not in text

    def test_building_runs_no_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import cordon_scanner

        def refuse(*args: object, **kwargs: object) -> None:
            raise AssertionError("a scan was run")

        monkeypatch.setattr(cordon_scanner.Scanner, "scan", refuse)
        assert build()["features"]


def test_the_module_is_where_the_tests_expect_it() -> None:
    assert Path(featureset.__file__).resolve() == TestNoDetectorIsDuplicated.PATH.resolve()
