"""`train.py` is the only way to train a model: every trainer refuses to run on its own, and a new one has to be registered."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from bench.model import area

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FITS = re.compile(r"lgb\.train|\.fit\(|HistGradientBoosting|save_model|joblib\.dump|LogisticRegression|LGBM")


def scripts() -> list[Path]:
    return sorted(
        p for p in HERE.glob("*.py") if not p.name.startswith("test_") and '__name__ == "__main__"' in p.read_text(encoding="utf-8")
    )


class TestEveryScriptThatFitsAModelIsRegistered:
    def test_a_script_that_fits_a_model_is_train_py_a_registered_trainer_or_evaluation_only(self) -> None:
        allowed = {"train.py", *area.EntryPoint.TRAINERS.values(), *area.EntryPoint.EVALUATION_ONLY}
        unregistered = [
            p.name for p in scripts() if FITS.search(p.read_text(encoding="utf-8")) and p.name not in allowed
        ]
        assert unregistered == [], f"train through bench/model/train.py; register a new trainer in area.EntryPoint: {unregistered}"

    def test_every_registered_trainer_exists_and_refuses_to_run_unless_train_py_started_it(self) -> None:
        for name in area.EntryPoint.TRAINERS.values():
            source = (HERE / name).read_text(encoding="utf-8")
            main_block = source.split('if __name__ == "__main__":', 1)[1]
            assert "EntryPoint.require(__file__)" in main_block, name

    def test_the_registry_has_no_trainer_twice_and_evaluation_scripts_are_not_trainers(self) -> None:
        values = list(area.EntryPoint.TRAINERS.values())
        assert len(values) == len(set(values))
        assert not set(values) & area.EntryPoint.EVALUATION_ONLY

    def test_train_py_dispatches_from_the_registry_and_gives_the_child_the_grant(self) -> None:
        source = (HERE / "train.py").read_text(encoding="utf-8")
        assert "area.EntryPoint.TRAINERS[args.area]" in source
        assert "env=area.EntryPoint.environment()" in source

    @pytest.mark.parametrize("name", sorted(area.EntryPoint.TRAINERS.values()))
    def test_run_on_its_own_a_trainer_is_refused(self, name: str) -> None:
        env = {k: v for k, v in os.environ.items() if k != area.EntryPoint.ENV}
        env.update({"PYTHONPATH": f"{ROOT}:{ROOT / 'src'}", "PYTHONDONTWRITEBYTECODE": "1"})
        run = subprocess.run(
            [sys.executable, str(HERE / name)], capture_output=True, text=True, env=env, check=False, timeout=60
        )
        if "ModuleNotFoundError" in run.stderr:
            pytest.skip(f"{name} cannot be imported here")
        assert run.returncode != 0 and "is not an entry point" in run.stderr

    def test_the_grant_is_only_given_by_train_py(self) -> None:
        assert area.EntryPoint.environment()[area.EntryPoint.ENV] == "1"
        os.environ.pop(area.EntryPoint.ENV, None)
        with pytest.raises(SystemExit, match="train through bench/model/train.py"):
            area.EntryPoint.require("verdict_train.py")


class TestTheSameListAndSeedGiveTheSameModelByteForByte:
    @pytest.fixture
    def train(self):
        pytest.importorskip("lightgbm")
        from bench.model import train

        return train

    @staticmethod
    def run(train, tmp_path: Path, ids: list[str], seed: int, name: str) -> Path:
        listing = tmp_path / f"{name}.txt"
        listing.write_text("\n".join(ids) + "\n", encoding="utf-8")
        work = tmp_path / name
        work.mkdir()
        args = argparse.Namespace(train=listing, seed=seed, work=work)
        assert train.Training.fixture(args) == 0
        return work / "model-fixture"

    IDS = [f"pkg-{i}@1.0.{i % 7}" for i in range(120)]

    def test_two_runs_write_identical_model_bytes_and_the_same_list_hash(self, train, tmp_path: Path) -> None:
        a = self.run(train, tmp_path, self.IDS, 7, "a")
        b = self.run(train, tmp_path, self.IDS, 7, "b")
        assert (a / "model.txt").read_bytes() == (b / "model.txt").read_bytes()
        assert (a / "metrics.json").read_bytes() == (b / "metrics.json").read_bytes()
        assert (a / "training_list.sha256").read_text(encoding="utf-8") == (b / "training_list.sha256").read_text(encoding="utf-8")

    def test_the_order_of_the_list_does_not_change_the_model(self, train, tmp_path: Path) -> None:
        a = self.run(train, tmp_path, self.IDS, 7, "a")
        b = self.run(train, tmp_path, list(reversed(self.IDS)), 7, "b")
        assert (a / "model.txt").read_bytes() == (b / "model.txt").read_bytes()

    def test_another_list_gives_another_model_and_another_hash(self, train, tmp_path: Path) -> None:
        a = self.run(train, tmp_path, self.IDS, 7, "a")
        b = self.run(train, tmp_path, self.IDS[:-20], 7, "b")
        assert (a / "model.txt").read_bytes() != (b / "model.txt").read_bytes()
        assert (a / "training_list.sha256").read_text(encoding="utf-8") != (b / "training_list.sha256").read_text(encoding="utf-8")

    def test_the_list_hash_is_of_the_sorted_unique_ids(self, train, tmp_path: Path) -> None:
        a = self.run(train, tmp_path, self.IDS + self.IDS[:5], 7, "a")
        expected = "sha256:" + hashlib.sha256("\n".join(sorted(set(self.IDS))).encode("utf-8")).hexdigest()
        assert (a / "training_list.sha256").read_text(encoding="utf-8").strip() == expected

    def test_metrics_json_names_the_area_the_seed_and_the_list(self, train, tmp_path: Path) -> None:
        body = json.loads((self.run(train, tmp_path, self.IDS, 7, "a") / "metrics.json").read_text(encoding="utf-8"))
        assert (body["area"], body["seed"], body["n_train"]) == ("fixture", 7, 120)
        assert body["training_list_sha"].startswith("sha256:")

    def test_a_missing_list_is_refused(self, train, tmp_path: Path) -> None:
        args = argparse.Namespace(train=tmp_path / "none.txt", seed=1, work=tmp_path)
        assert train.Training.fixture(args) == 2
