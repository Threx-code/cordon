"""The verdict features' schema version (`decide/feature_schema`): derived from the extractor's code
and the feature names, moved by what changes the features and by nothing else."""

from __future__ import annotations

import io
import json
import shutil
import tarfile
from pathlib import Path
from typing import ClassVar
from unittest import mock

import pytest

from cordon_scanner.decide.feature_schema import (
    FeatureFold,
    FeatureRecord,
    FeatureSchema,
    FeatureScope,
)
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

    def test_a_rebuilt_row_is_stamped_with_its_producer_and_an_own_record_keeps_its_own(
        self,
    ) -> None:
        _, summary = RecordKit.decide([RecordKit.finding()], RecordKit.model())
        legacy = {"findings": [], "verdict": {"package": summary["package"]}}
        assert FeatureRecord.read(legacy, producer="fs1-producer")[0] == "fs1-producer"
        own = {"verdict": {"features": summary["features"]}}
        assert FeatureRecord.read(own, producer="fs1-producer")[0] == FeatureSchema.current()


class FoldKit:
    """Raw hashed code features, and a format-3 model split on one folded bucket: 0.9 when
    `pkg:code_install_tok_f5` (raw buckets 5, 517, 1029, ... summed) is above 2.5, else 0.1."""

    RAW: ClassVar[dict[str, float]] = {
        "code_install_tok_5": 1.0,
        "code_install_tok_517": 2.0,
        "code_import_apih_262143": 1.0,
        "code_install_api_exec": 1.0,
    }

    @staticmethod
    def model(fold: str | None = None) -> dict[str, object]:
        model = RecordKit.model()
        model["features"] = ["pkg:code_install_tok_f5"]
        return {
            **model,
            "format": VerdictModel.FORMAT,
            **FeatureFold.stamp(),
            "fold": fold or FeatureFold.version(),
        }

    @staticmethod
    def decide(model: dict[str, object] | None):
        with mock.patch.object(VerdictModel, "load", return_value=model):
            return Verdict.decide(
                [RecordKit.finding()],
                [("package/package.json", 10), ("package/index.js", 10)],
                {"package/package.json": b'{"name": "x"}'},
                profile=dict(FoldKit.RAW),
            )


class TestTheFold:
    def test_hashed_code_features_fold_and_others_stay(self) -> None:
        folded = FeatureFold.apply({f"pkg:{k}": v for k, v in FoldKit.RAW.items()} | {"r:X#n": 2.0})
        assert folded == {
            "pkg:code_install_tok_f5": 3.0,
            "pkg:code_import_apih_f511": 1.0,
            "pkg:code_install_api_exec": 1.0,
            "r:X#n": 2.0,
        }

    def test_the_fit_and_the_scanner_fold_to_identical_vectors(self) -> None:
        _, summary = FoldKit.decide(FoldKit.model())
        # The row keeps the raw features; the fit's reader and scoring fold them the same way.
        assert summary["features"]["values"]["pkg:code_install_tok_517"] == 2.0
        _, fitted = FeatureRecord.read({"verdict": {"features": summary["features"]}})
        scored = VerdictModel.inputs(FoldKit.model(), summary["features"]["values"])
        assert fitted == scored == FeatureFold.apply(summary["features"]["values"])
        # The score was taken on the folded bucket (1 + 2 > 2.5), which no raw feature reaches.
        assert summary["score"] == round(VerdictModel.score(FoldKit.model(), fitted), 4) == 0.9

    def test_a_model_from_before_the_fold_is_scored_on_raw_features(self) -> None:
        unfolded = {**RecordKit.model(), "format": VerdictModel.UNFOLDED}
        features = {"pkg:code_install_tok_517": 2.0}
        assert VerdictModel.inputs(unfolded, features) is features

    def test_a_model_of_another_fold_is_refused(self, tmp_path: Path) -> None:
        import gzip
        import json

        def written(model: dict[str, object]) -> Path:
            path = tmp_path / f"m{len(list(tmp_path.iterdir()))}.json.gz"
            with gzip.open(path, "wt", encoding="utf-8") as handle:
                json.dump(model, handle)
            return path

        VerdictModel.load.cache_clear()
        assert VerdictModel.load(written(FoldKit.model())) is not None
        assert VerdictModel.load(written(FoldKit.model(fold="ff1-0000000000000000"))) is None
        assert VerdictModel.load(written({**FoldKit.model(), "fold": None})) is None
        assert (
            VerdictModel.load(written({**RecordKit.model(), "format": VerdictModel.UNFOLDED}))
            is not None
        )

    def test_the_width_moves_the_fold_version_and_not_the_row_version(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        rows, fold = FeatureSchema.current(), FeatureFold.version()
        monkeypatch.setattr(FeatureFold, "WIDTH", 1024)
        FeatureFold.version.cache_clear()
        try:
            assert FeatureFold.version() != fold
            assert FeatureFold.stamp()["width"] == 1024
            assert FeatureSchema.version() == rows
        finally:
            monkeypatch.undo()
            FeatureFold.version.cache_clear()
        assert FeatureFold.version() == fold


class TestAnOlderTree:
    def test_a_tree_from_before_a_move_is_versioned_at_the_recorded_path(
        self, tmp_path: Path
    ) -> None:
        """`MOVED` names where a piece lives now; a checkout from before the move (as P8's producer
        is) still has it at the recorded path, and gets the version a pure move leaves alone."""
        before = SchemaKit.tree(tmp_path / "before")
        for recorded, moved in FeatureSchema.MOVED.items():
            (before / moved).rename(before / recorded.split(":")[0])
        assert FeatureSchema.version(before) == FeatureSchema.version(
            SchemaKit.tree(tmp_path / "after")
        )


class ScopeKit:
    """A small benign npm package, scanned whole, with and without the measurement variable."""

    FILES: ClassVar[dict[str, str]] = {
        "package/package.json": json.dumps(
            {
                "name": "scope-probe",
                "version": "1.0.0",
                "scripts": {"postinstall": "node install.js"},
            }
        ),
        "package/install.js": (
            'const fs = require("fs");\nconst path = require("path");\n'
            'console.log(fs.readFileSync(path.join(__dirname, "package.json"), "utf8").length);\n'
        ),
        "package/index.js": "module.exports = function add(a, b) { return a + b; };\n",
    }

    @staticmethod
    def features(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, measure: bool) -> set[str]:
        from cordon_scanner import Scanner
        from cordon_scanner.foundation.config.settings import Config

        archive = tmp_path / "scope-probe-1.0.0.tgz"
        if not archive.exists():
            with tarfile.open(archive, "w:gz") as handle:
                for name, text in ScopeKit.FILES.items():
                    data = text.encode()
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    handle.addfile(info, io.BytesIO(data))
        if measure:
            monkeypatch.setenv("CORDON_MEASURE_FEATURES", "1")
        else:
            monkeypatch.delenv("CORDON_MEASURE_FEATURES", raising=False)
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)
        assert result.verdict is not None
        return set(result.verdict["features"]["values"])


class TestFeatureScope:
    def test_a_users_scan_computes_no_measure_only_feature_and_the_variable_adds_only_those(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        users = ScopeKit.features(tmp_path, monkeypatch, measure=False)
        measured = ScopeKit.features(tmp_path, monkeypatch, measure=True)
        assert all(FeatureScope.computed(name) for name in users)
        added = measured - users
        assert added, "the probe reaches no code feature: it proves nothing"
        assert not any(FeatureScope.computed(name) for name in added)

    def test_the_predicate_names_every_place_the_code_features_read(self) -> None:
        from cordon_scanner.detect.code.features import CodeFeatures

        for place in CodeFeatures.PLACES:
            assert not FeatureScope.computed(f"pkg:code_{place}_tok_1")
        assert FeatureScope.computed("pkg:code_share")
        assert not FeatureScope.computed(
            FeatureFold.apply({"pkg:code_import_tok_517": 1.0}).popitem()[0]
        )
