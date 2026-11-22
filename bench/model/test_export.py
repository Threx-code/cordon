"""The exporter: the fitted model leaves training as gzip-JSON trees the scanner walks, and nothing else is published."""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

import pytest

from bench.model import area
from bench.model.export import ExportRefused, ModelExport

HERE = Path(__file__).resolve().parent


class TestTheVersion:
    def test_it_is_a_day_and_twelve_hex_of_the_training_list_hash(self) -> None:
        sha = area.Contract.training_list_sha(["a", "b"])
        version = ModelExport.version("2026-11-22", sha)
        assert version == f"2026-11-22-{sha.removeprefix('sha256:')[:12]}"

    def test_a_day_that_is_not_a_day_is_refused(self) -> None:
        with pytest.raises(ExportRefused):
            ModelExport.version("yesterday", area.Contract.training_list_sha(["a"]))


class TestNothingButDataIsPublished:
    def test_no_trainer_or_packager_writes_or_reads_a_pickle(self) -> None:
        for name in ("train.py", "bundle.py", "export.py"):
            code = (HERE / name).read_text(encoding="utf-8")
            body = "\n".join(line for line in code.splitlines() if not line.lstrip().startswith(("#", '"""')))
            assert "joblib.dump" not in body and "joblib.load" not in body and "pickle" not in body.lower().replace("no pickle", ""), name


class TestTheExportedTreesScoreAsTheFittedModelDoes:
    @pytest.fixture
    def trained(self, tmp_path: Path):
        pytest.importorskip("lightgbm")
        from bench.model import train

        listing = tmp_path / "list.txt"
        listing.write_text("\n".join(f"unit-{i}" for i in range(150)) + "\n", encoding="utf-8")
        args = argparse.Namespace(
            train=listing, seed=5, work=tmp_path, schema="fs1-7e81bff59a9cc09a", fold="ff1-00f3139150f90490", day="2026-11-22"
        )
        assert train.Training.fixture(args) == 0
        return tmp_path / "model-fixture"

    def test_the_file_is_gzip_json_with_the_fields_the_feed_reads_and_nothing_else_is_written_to_publish(self, trained: Path) -> None:
        model = json.loads(gzip.decompress((trained / "model.json.gz").read_bytes()))
        assert set(model) == {"format", "features", "baseline", "trees", "areas", "floor", "schema", "fold", "version"}
        assert list(model["areas"]) == ["package"] and 0.0 < model["areas"]["package"] < 1.0 and model["floor"] == []
        assert model["format"] == 3 and model["schema"] == "fs1-7e81bff59a9cc09a" and model["fold"] == "ff1-00f3139150f90490"
        assert sorted(p.name for p in trained.iterdir()) == ["metrics.json", "model.json.gz", "training_list.sha256"]

    def test_the_scanners_own_walk_gives_the_fitted_probability(self, trained: Path) -> None:
        verdict = pytest.importorskip("cordon_scanner.decide.verdict")
        from bench.model import train

        model = json.loads(gzip.decompress((trained / "model.json.gz").read_bytes()))
        matrix, _ = train.Training.fixture_rows([f"unit-{i}" for i in range(150)])
        for row in matrix[:25]:
            named = {name: float(v) for name, v in zip(model["features"], row, strict=True)}
            assert abs(verdict.VerdictModel.score(model, named) - ModelExport.score(model, row.tolist())) < 1e-6

    def test_metrics_name_the_file_its_hash_and_the_version(self, trained: Path) -> None:
        body = json.loads((trained / "metrics.json").read_text(encoding="utf-8"))
        assert body["model_file"] == "model.json.gz" and len(body["model_sha256"]) == 64
        assert body["version"].startswith("2026-11-22-") and body["deterministic"] is True

    def test_an_export_that_scores_differently_from_the_fit_is_not_written(self) -> None:
        lightgbm = pytest.importorskip("lightgbm")
        import numpy as np

        matrix = np.array([[0.1, 0.9], [0.8, 0.2], [0.4, 0.6], [0.9, 0.1]] * 10)
        labels = np.array([0, 1, 0, 1] * 10)
        booster = lightgbm.train(
            {"objective": "binary", "verbose": -1, "num_leaves": 3, "min_data_in_leaf": 2}, lightgbm.Dataset(matrix, labels), 5
        )
        with pytest.raises(ExportRefused, match="not written"):
            ModelExport.from_lightgbm(
                booster,
                ["a", "b"],
                schema="fs1-0000000000000000",
                fold="ff1-0000000000000000",
                version="2026-11-22-0123456789ab",
                rows=matrix.tolist(),
                predict=lambda rows: np.full(len(rows), 0.5),
                line=0.5,
            )
