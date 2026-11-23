"""verdict_train reads features as the scanner scores them: through FeatureRecord.read, folded.

```
  row ── evidence(row) ──────────────► rebuilt from findings + verdict.package, folded
  row ── evidence(row, record=True) ─► the scan's own record where it has one, folded
```
"""

from __future__ import annotations

import sys
from typing import ClassVar

import pytest

from cordon_scanner.decide.feature_schema import FeatureFold, FeatureRecord
from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "model"))

from verdict_train import VerdictTrain


class VerdictTrainKit:
    PACKAGE: ClassVar[dict[str, float]] = {
        "code_import_tok_65541": 2.0,
        "code_import_tok_5": 1.0,
        "files": 3.0,
    }

    @staticmethod
    def row(record: dict[str, float] | None = None) -> dict:
        verdict: dict = {"package": dict(VerdictTrainKit.PACKAGE)}
        if record is not None:
            verdict["features"] = {"schema": "fs1-test", "values": record}
        return {
            "file": "npm/x-1.0.0.tgz",
            "findings": [
                ["SUSPECT.X.001", "high", "high", "suspicious", "package/index.js", 1, "h"]
            ],
            "verdict": verdict,
        }


class TestEvidence:
    def test_a_row_is_rebuilt_and_folded_as_the_scanner_folds(self) -> None:
        row = VerdictTrainKit.row()
        features = VerdictTrain.evidence(row)
        assert features == FeatureRecord.read(row)[1]
        assert features["pkg:code_import_tok_f5"] == 3.0
        assert "pkg:code_import_tok_65541" not in features

    def test_the_record_is_read_only_when_asked(self) -> None:
        record = {"pkg:code_import_tok_65541": 7.0, "r:SUSPECT.Y.001": 1.0}
        row = VerdictTrainKit.row(record)
        assert VerdictTrain.evidence(row, record=True) == FeatureFold.apply(record)
        assert VerdictTrain.evidence(row) == VerdictTrain.evidence(VerdictTrainKit.row())


class TestAnAreaWithTooLittleMalwareHasNoTreesOfItsOwn:
    """The trainer gives an area trees of its own only when its work half holds enough malware to separate it; every other area is scored by the shared trees."""

    MALWARE: ClassVar[dict[str, int]] = {"npm": 900, "skill": 40, "mcp": 12, "pypi": 300}

    def test_an_area_at_the_minimum_keeps_its_own_trees(self) -> None:
        assert VerdictTrain.own_trees(["skill", "mcp"], {"skill": 40, "mcp": 30}, 30) == [
            "skill",
            "mcp",
        ]

    def test_an_area_under_the_minimum_gets_none_and_the_rest_keep_theirs(self) -> None:
        assert VerdictTrain.own_trees(["skill", "mcp", "pypi"], self.MALWARE, 30) == [
            "skill",
            "pypi",
        ]

    def test_an_area_with_no_malware_at_all_gets_none(self) -> None:
        assert VerdictTrain.own_trees(["ci", "skill"], self.MALWARE, 30) == ["skill"]

    def test_the_trainer_builds_its_groups_and_its_export_from_that_list_only(self) -> None:
        text = (REPO / "bench" / "model" / "verdict_train.py").read_text(encoding="utf-8")
        assert "for x in own_areas}" in text and "for x in a.separate" not in text


class TestTheCapacitySearchOnAFixtureTable:
    """The trainer sets capacity on a table in which no family is split across folds, and the exported model carries the record."""

    @staticmethod
    def table() -> tuple[object, object, list[str]]:
        np = pytest.importorskip("numpy")

        rng = np.random.default_rng(3)
        rows, labels, families = [], [], []
        for n in range(60):
            rows.append([rng.normal(0, 1), rng.normal(0, 1), 0.0])
            labels.append(0)
            families.append(f"legit-{n}")
        for n in range(60):
            rows.append([rng.normal(2, 1), rng.normal(1, 1), 1.0])
            labels.append(1)
            families.append(f"mal-{n % 12}")
        return np.array(rows), np.array(labels), families

    @staticmethod
    def build(point: dict[str, float]) -> object:
        from sklearn.ensemble import HistGradientBoostingClassifier

        return HistGradientBoostingClassifier(
            max_iter=int(point["trees"]),
            learning_rate=point["learning_rate"],
            max_leaf_nodes=int(point["leaves"]),
            min_samples_leaf=int(point["min_leaf"]),
            random_state=0,
        )

    def test_the_record_has_the_grid_the_whole_curve_and_a_choice_from_the_grid(self) -> None:
        x, y, families = self.table()
        grid = {"trees": (20, 60), "leaves": (4, 8), "learning_rate": (0.1,), "min_leaf": (5,)}
        record = VerdictTrain.search_capacity(x, y, families, self.build, grid=grid)
        assert len(record["curve"]) == 4 and record["grid"]["trees"] == [20, 60]
        assert record["chosen"] in [c["point"] for c in record["curve"]]
        assert all(0.0 <= c["mean"] <= 1.0 for c in record["curve"])

    def test_the_model_scores_the_held_out_families_better_than_chance(self) -> None:
        x, y, families = self.table()
        grid = {"trees": (30,), "leaves": (4,), "learning_rate": (0.1,), "min_leaf": (5,)}
        (point,) = VerdictTrain.search_capacity(x, y, families, self.build, grid=grid)["curve"]
        assert point["mean"] > 0.3
