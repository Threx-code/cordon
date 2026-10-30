"""The verdict features' schema version (`decide/feature_schema`): derived from the extractor's code
and the feature names, moved by what changes the features and by nothing else."""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest import mock

import pytest

from cordon_scanner.decide.feature_schema import FeatureRecord, FeatureSchema
from cordon_scanner.decide.verdict import Verdict, VerdictModel
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    RiskScore,
    Severity,
)
from cordon_scanner.foundation.paths import PackagePaths


class SchemaKit:
    """A copy of the extractor's files, to edit and read the version of."""

    @staticmethod
    def tree(where: Path) -> Path:
        for path, dotted in FeatureSchema.EXTRACTOR:
            source = FeatureSchema.source(path, dotted)
            (where / source).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(PackagePaths.root() / source, where / source)
        return where

    @staticmethod
    def edit(root: Path, path: str, old: str, new: str) -> None:
        text = (root / path).read_text(encoding="utf-8")
        assert text.count(old) == 1, old
        (root / path).write_text(text.replace(old, new), encoding="utf-8")


class TestTheVersion:
    def test_it_is_derived_and_stable(self) -> None:
        version = FeatureSchema.version()
        assert version.startswith(FeatureSchema.PREFIX)
        assert version == FeatureSchema.version() == FeatureSchema.current()

    def test_a_copy_of_the_tree_has_the_same_version(self, tmp_path: Path) -> None:
        root = SchemaKit.tree(tmp_path)
        assert FeatureSchema.version(root, FeatureSchema.names()) == FeatureSchema.version()

    def test_a_docstring_or_comment_edit_leaves_it(self, tmp_path: Path) -> None:
        root = SchemaKit.tree(tmp_path)
        SchemaKit.edit(
            root,
            "decide/verdict_features.py",
            '"""What the model scores, from (rule, severity, confidence, category, path) per finding.',
            '"""What the model scores (reworded), from (rule, severity, confidence, category, path).\n'
            "        # and a comment",
        )
        assert FeatureSchema.version(root, FeatureSchema.names()) == FeatureSchema.version()

    def test_a_change_to_what_is_computed_moves_it(self, tmp_path: Path) -> None:
        root = SchemaKit.tree(tmp_path)
        SchemaKit.edit(
            root,
            "decide/verdict_features.py",
            'out[key + "#n"] = out.get(key + "#n", 0.0) + 1.0',
            'out[key + "#n"] = out.get(key + "#n", 0.0) + 2.0',
        )
        assert FeatureSchema.version(root, FeatureSchema.names()) != FeatureSchema.version()

    def test_a_new_feature_name_moves_it(self) -> None:
        names = FeatureSchema.names()
        assert FeatureSchema.version(None, [*names, "pkg:new_fact"]) != FeatureSchema.version()

    def test_a_stale_extractor_list_fails_loudly(self, tmp_path: Path) -> None:
        root = SchemaKit.tree(tmp_path)
        SchemaKit.edit(
            root, "engine/pipeline/history.py", "def registry_facts(", "def renamed_facts("
        )
        with pytest.raises(LookupError, match=r"History\.registry_facts"):
            FeatureSchema.version(root, FeatureSchema.names())


class RecordKit:
    """A finding and a one-split model (the verdict tests' shape): 0.9 when `r:SUSPECT.X.001` is high."""

    @staticmethod
    def finding(rule: str = "SUSPECT.X.001", severity: Severity = Severity.HIGH) -> Finding:
        return Finding(
            rule_id=rule,
            category=Category.SUSPICIOUS,
            severity=severity,
            confidence=Confidence.HIGH,
            message="m.",
            location=Location(path="package/index.js"),
            evidence=Evidence(
                kind=EvidenceKind.SNIPPET,
                match_hash=Evidence.hash_bytes(b"x"),
                redaction=RedactionMode.MASKED,
            ),
            remediation="",
            explanation=Explanation(summary="", matched_rule=rule),
            risk=RiskScore(value=50, base=50, confidence_multiplier=1.0),
            detector="t",
        )

    @staticmethod
    def model() -> dict[str, object]:
        logit = 2.1972245773
        return {
            "format": VerdictModel.FORMAT,
            "features": ["r:SUSPECT.X.001"],
            "baseline": 0.0,
            "trees": [
                [
                    {
                        "leaf": False,
                        "feature": 0,
                        "threshold": 2.5,
                        "left": 1,
                        "right": 2,
                        "missing_left": True,
                    },
                    {"leaf": True, "value": -logit},
                    {"leaf": True, "value": logit},
                ]
            ],
            "areas": {"npm": 0.5, "package": 0.95},
            "floor": [],
        }

    @staticmethod
    def decide(findings: list[Finding], model: dict[str, object] | None):
        with mock.patch.object(VerdictModel, "load", return_value=model):
            return Verdict.decide(
                findings,
                [("package/package.json", 10), ("package/index.js", 10)],
                {"package/package.json": b'{"name": "x"}'},
            )


class TestTheRecord:
    def test_every_verdict_carries_its_versioned_features(self) -> None:
        _, summary = RecordKit.decide([], None)
        assert summary["features"]["schema"] == FeatureSchema.current()
        assert isinstance(summary["features"]["values"], dict)

    def test_a_score_is_reproduced_from_the_record_alone(self) -> None:
        _, summary = RecordKit.decide([RecordKit.finding()] * 3, RecordKit.model())
        values = summary["features"]["values"]
        assert values["r:SUSPECT.X.001#n"] == 3.0
        assert round(VerdictModel.score(RecordKit.model(), values), 4) == summary["score"]

    def test_a_row_without_the_record_reads_to_the_same_features(self) -> None:
        findings = [RecordKit.finding(), RecordKit.finding("SUSPECT.Y.001", Severity.LOW)]
        _, summary = RecordKit.decide(findings, RecordKit.model())
        legacy = {
            "findings": [
                [f.rule_id, str(f.severity), str(f.confidence), str(f.category), f.location.path]
                for f in findings
            ],
            "verdict": {"package": summary["package"]},
        }
        assert FeatureRecord.read(legacy) == (None, summary["features"]["values"])
        own = {"verdict": {"features": summary["features"]}}
        assert FeatureRecord.read(own) == (FeatureSchema.current(), summary["features"]["values"])
