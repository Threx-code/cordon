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
#: What a script that writes a model does, whatever library fitted it: a pickle or a joblib file, a saved booster, a gzip file written
#: in text mode (the JSON models), a model file copied into place, or a name that is one of the model files.
WRITES = re.compile(
    r"pickle\.dump|joblib\.dump|save_model|torch\.save|gzip\.open\([^)]*[\"']w|shutil\.copy\w*\([^)]*model"
    r"|[\"'][\w./{}-]*model\.txt[\"']|[\"'][\w./{}-]*\.joblib[\"']"
)


class Helpers:
    @staticmethod
    def scripts() -> list[Path]:
        return sorted(p for p in HERE.glob("*.py") if not p.name.startswith("test_"))




class TestEveryScriptThatFitsAModelIsRegistered:
    def test_a_script_that_fits_a_model_is_train_py_a_registered_trainer_or_evaluation_only(self) -> None:
        allowed = {
            "train.py",
            "area.py",
            *area.EntryPoint.TRAINERS.values(),
            *area.EntryPoint.EVALUATION_ONLY,
            *area.EntryPoint.PACKAGING,
        }
        unregistered = [
            p.name
            for p in Helpers.scripts()
            if (FITS.search(p.read_text(encoding="utf-8")) or WRITES.search(p.read_text(encoding="utf-8")))
            and p.name not in allowed
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

    def test_the_write_side_is_seen_whatever_library_fitted_the_model(self) -> None:
        for code in (
            "pickle.dump(model, handle)",
            "torch.save(net, path)",
            'with gzip.open(out, "wt") as h:',
            'shutil.copyfile(a, out / "model.txt")',
            'path = work / "meta.joblib"',
        ):
            assert WRITES.search(code), code
        assert not WRITES.search("rows = json.loads(path.read_text())")

    def test_the_grant_names_train_py_and_nothing_typed_into_a_shell_opens_a_trainer(self, monkeypatch) -> None:
        monkeypatch.setenv(area.EntryPoint.ENV, "1")
        assert not area.EntryPoint.granted()
        monkeypatch.setenv(area.EntryPoint.ENV, str(os.getppid()))
        # the parent here is not train.py; where /proc shows it, the grant is refused
        if Path(f"/proc/{os.getppid()}/cmdline").exists():
            assert not area.EntryPoint.granted()
        monkeypatch.delenv(area.EntryPoint.ENV)
        with pytest.raises(SystemExit, match="train through bench/model/train.py"):
            area.EntryPoint.require("verdict_train.py")

    def test_the_environment_train_py_hands_on_carries_its_own_pid_and_replaces_any_other_grant(self, monkeypatch) -> None:
        monkeypatch.setenv(area.EntryPoint.ENV, "typed-in-a-shell")
        assert area.EntryPoint.environment()[area.EntryPoint.ENV] == str(os.getpid())

    def test_a_grant_already_in_the_environment_stops_train_py_from_starting(self, monkeypatch) -> None:
        monkeypatch.setenv(area.EntryPoint.ENV, "1")
        with pytest.raises(SystemExit, match="already set"):
            area.EntryPoint.refuse_inherited()

    def test_train_py_run_with_a_grant_in_the_shell_does_not_start(self) -> None:
        env = {**os.environ, area.EntryPoint.ENV: "1", "PYTHONPATH": f"{ROOT}:{ROOT / 'src'}", "PYTHONDONTWRITEBYTECODE": "1"}
        run = subprocess.run(
            [sys.executable, str(HERE / "train.py"), "--area", "fixture"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=60,
        )
        assert run.returncode != 0 and "already set" in run.stderr

    def test_a_trainer_run_with_the_grant_typed_in_a_shell_is_refused(self) -> None:
        env = {**os.environ, area.EntryPoint.ENV: "1", "PYTHONPATH": f"{ROOT}:{ROOT / 'src'}", "PYTHONDONTWRITEBYTECODE": "1"}
        run = subprocess.run(
            [sys.executable, str(HERE / "mcp_recalibrate.py")], capture_output=True, text=True, env=env, check=False, timeout=60
        )
        assert run.returncode != 0 and "is not an entry point" in run.stderr

    def test_a_trainer_started_by_train_py_is_not_refused_as_an_entry_point(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != area.EntryPoint.ENV}
        env.update({"PYTHONPATH": f"{ROOT}:{ROOT / 'src'}", "PYTHONDONTWRITEBYTECODE": "1"})
        run = subprocess.run(
            [sys.executable, str(HERE / "train.py"), "--area", "mcp-lines"],
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=60,
        )
        assert "is not an entry point" not in run.stderr


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
        assert (a / "model.json.gz").read_bytes() == (b / "model.json.gz").read_bytes()
        assert (a / "metrics.json").read_bytes() == (b / "metrics.json").read_bytes()
        assert (a / "training_list.sha256").read_text(encoding="utf-8") == (b / "training_list.sha256").read_text(encoding="utf-8")

    def test_the_order_of_the_list_does_not_change_the_model(self, train, tmp_path: Path) -> None:
        a = self.run(train, tmp_path, self.IDS, 7, "a")
        b = self.run(train, tmp_path, list(reversed(self.IDS)), 7, "b")
        assert (a / "model.json.gz").read_bytes() == (b / "model.json.gz").read_bytes()

    def test_another_list_gives_another_model_and_another_hash(self, train, tmp_path: Path) -> None:
        a = self.run(train, tmp_path, self.IDS, 7, "a")
        b = self.run(train, tmp_path, self.IDS[:-20], 7, "b")
        assert (a / "model.json.gz").read_bytes() != (b / "model.json.gz").read_bytes()
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
