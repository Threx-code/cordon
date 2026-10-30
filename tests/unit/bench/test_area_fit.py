"""The per-area fit writes a model the scanner loads and scores as the fit predicted.

```
  export.json (trees, rows, the fit's probabilities; bench/model/area_fit.py --fixture)
      └─► format-3 model ──► VerdictModel.load ──► VerdictModel.score(row) == probability
  shipped model (format 2, no hashed feature) ──► carry ──► the same score, folded or raw
```
"""

from __future__ import annotations

import copy
import gzip
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.decide.feature_schema import FeatureFold, FeatureSchema
from cordon_scanner.decide.verdict import MODEL_PATH, VerdictModel
from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "model"))

from area_fit import AreaFit

FIXTURE = REPO / "tests" / "unit" / "data" / "area_fit" / "export.json"


class AreaFitKit:
    @staticmethod
    def export() -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads(FIXTURE.read_text(encoding="utf-8"))
        return loaded

    @staticmethod
    def written(model: dict[str, Any], where: Path) -> Path:
        path = where / "verdict.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump(model, handle)
        return path

    @staticmethod
    def shipped() -> dict[str, Any]:
        with gzip.open(MODEL_PATH, "rt", encoding="utf-8") as handle:
            model: dict[str, Any] = json.load(handle)
        return model


class TestTheExport:
    def test_the_written_model_loads_and_scores_as_the_fit_predicted(self, tmp_path: Path) -> None:
        fixture = AreaFitKit.export()
        model = AreaFit.carry(AreaFitKit.shipped())
        model["by_area"]["npm"] = fixture["section"]
        VerdictModel.load.cache_clear()
        loaded = VerdictModel.load(AreaFitKit.written(model, tmp_path))
        assert loaded is not None
        section = loaded["by_area"]["npm"]
        for row, want in zip(fixture["rows"], fixture["expected"], strict=True):
            assert (
                abs(VerdictModel.score(section, VerdictModel.inputs(loaded, row)) - want)
                <= AreaFit.TOLERANCE
            )
        assert AreaFit.check(section, fixture["rows"], fixture["expected"]) <= AreaFit.TOLERANCE

    def test_an_export_that_walks_differently_is_not_written(self) -> None:
        fixture = AreaFitKit.export()
        section = copy.deepcopy(fixture["section"])
        split = next(n for tree in section["trees"] for n in tree if not n["leaf"])
        split["threshold"] += 2.0
        with pytest.raises(ValueError, match="not written"):
            AreaFit.check(section, fixture["rows"], fixture["expected"])


class TestTheBase:
    def test_the_shipped_model_scores_the_same_folded_or_raw(self) -> None:
        shipped = AreaFitKit.shipped()
        carried = AreaFit.carry(shipped)
        assert carried["format"] == VerdictModel.FORMAT
        assert carried["fold"] == FeatureFold.version()
        assert carried["schema"] == FeatureSchema.current()
        raw = {name: float(i % 5) for i, name in enumerate(shipped["features"])}
        raw |= {"pkg:code_install_tok_517": 3.0, "pkg:code_import_apih_9": 2.0}
        assert VerdictModel.score(carried, VerdictModel.inputs(carried, raw)) == VerdictModel.score(
            shipped, raw
        )

    def test_a_base_that_reads_a_hashed_feature_is_refused(self) -> None:
        shipped = AreaFitKit.shipped()
        hashed = {**shipped, "features": [*shipped["features"], "pkg:code_install_tok_5"]}
        with pytest.raises(ValueError, match="never computes"):
            AreaFit.carry(hashed)

    def test_a_base_that_reads_a_measure_only_feature_is_refused(self) -> None:
        shipped = AreaFitKit.shipped()
        unread = {**shipped, "features": [*shipped["features"], "pkg:code_import_api_exec"]}
        with pytest.raises(ValueError, match="never computes"):
            AreaFit.carry(unread)


class TestTheRows:
    def test_a_row_of_another_version_is_refused_unless_accepted(self, tmp_path: Path) -> None:
        row = {"file": "npm/x-1.0.0.tgz", "findings": [], "verdict": {"area": "npm", "package": {}}}
        (tmp_path / "set-abc.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
        args = (tmp_path, [("set", 0, None)], "fs1-other", "abc", set(), "npm")
        with pytest.raises(ValueError, match="refused"):
            list(AreaFit.rows(*args, set()))
        assert [label for label, _, _ in AreaFit.rows(*args, {"fs1-other"})] == [0]

    def test_one_file_gives_both_labels_by_prefix(self, tmp_path: Path) -> None:
        rows = [
            {"file": f"{where}/x", "findings": [], "verdict": {"area": "mcp", "package": {}}}
            for where in ("benign", "malware", "elsewhere")
        ]
        (tmp_path / "asb-abc.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
        )
        sets = [("asb", 0, "benign/"), ("asb", 1, "malware/")]
        found = AreaFit.rows(tmp_path, sets, "fs1-p", "abc", set(), "mcp", {"fs1-p"})
        assert [(label, unit) for label, unit, _ in found] == [(0, "benign/x"), (1, "malware/x")]
