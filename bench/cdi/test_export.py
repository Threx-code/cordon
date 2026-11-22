"""SI-G2: the export writes the three lists, split by family and time, and a second run never changes `eval`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bench.cdi.export import DatasetExport
from bench.cdi.manifests import Manifests

EVAL_FAMILY = next(f for f in (f"fam{i}" for i in range(1_000)) if DatasetExport.eval_family(f))
TRAIN_FAMILIES = [f for f in (f"fam{i}" for i in range(1_000)) if not DatasetExport.eval_family(f)][:3]


class Kit:
    @staticmethod
    def unit(digest: str, family: str, seen: str = "2026-01-05") -> dict[str, Any]:
        return {"digest": digest, "family": family, "first_seen": seen}


    @staticmethod
    def read(out: Path, name: str) -> dict[str, Any]:
        return json.loads((out / f"{name}.json").read_text(encoding="utf-8"))


UNITS = [
    Kit.unit("e1", EVAL_FAMILY),
    Kit.unit("e2", EVAL_FAMILY),
    Kit.unit("t1", TRAIN_FAMILIES[0]),
    Kit.unit("t2", TRAIN_FAMILIES[1]),
    Kit.unit("f1", TRAIN_FAMILIES[0], "2026-11-10"),
    Kit.unit("f2", EVAL_FAMILY, "2026-11-11"),
]


class TestTheThreeLists:
    def test_the_job_writes_train_eval_and_fresh(self, tmp_path: Path) -> None:
        counts = DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        assert counts == {"train": 2, "eval": 2, "fresh": 2, "excluded": 0}
        assert Kit.read(tmp_path, "train")["artifacts"] == ["t1", "t2"]
        assert Kit.read(tmp_path, "eval")["artifacts"] == ["e1", "e2"]
        assert Kit.read(tmp_path, "fresh")["artifacts"] == ["f1", "f2"]

    def test_each_file_is_a_manifest_the_miss_lookup_reads(self, tmp_path: Path) -> None:
        DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        manifests = Manifests([Kit.read(tmp_path, n) for n in ("train", "eval", "fresh")])
        assert [manifests.membership(d) for d in ("t1", "e1", "f1")] == ["train", "eval", "fresh"]
        assert Kit.read(tmp_path, "eval")["dataset"] == "pypi-eval"

    def test_the_area_names_the_datasets(self, tmp_path: Path) -> None:
        DatasetExport.export(UNITS, tmp_path, "npm", "2026-11-01")
        assert Kit.read(tmp_path, "train")["dataset"] == "npm-train"

    def test_a_family_is_wholly_in_eval_or_wholly_in_train(self, tmp_path: Path) -> None:
        many = [Kit.unit(f"d{i}", f"fam{i % 40}") for i in range(200)]
        DatasetExport.export(many, tmp_path, "pypi", "2026-11-01")
        family = {u["digest"]: u["family"] for u in many}
        train = {family[d] for d in Kit.read(tmp_path, "train")["artifacts"]}
        held = {family[d] for d in Kit.read(tmp_path, "eval")["artifacts"]}
        assert held and train and not train & held

    def test_time_decides_fresh_before_family_does(self, tmp_path: Path) -> None:
        DatasetExport.export([Kit.unit("x", EVAL_FAMILY, "2026-11-01")], tmp_path, "a", "2026-11-01")
        assert Kit.read(tmp_path, "fresh")["artifacts"] == ["x"]

    def test_the_day_before_the_cut_is_not_fresh(self, tmp_path: Path) -> None:
        DatasetExport.export([Kit.unit("x", TRAIN_FAMILIES[0], "2026-10-31")], tmp_path, "a", "2026-11-01")
        assert Kit.read(tmp_path, "train")["artifacts"] == ["x"]

    def test_the_order_of_the_units_does_not_matter(self, tmp_path: Path) -> None:
        a, b = tmp_path / "a", tmp_path / "b"
        DatasetExport.export(UNITS, a, "p", "2026-11-01")
        DatasetExport.export(list(reversed(UNITS)), b, "p", "2026-11-01")
        assert all((a / f"{n}.json").read_text(encoding="utf-8") == (b / f"{n}.json").read_text(encoding="utf-8") for n in ("train", "eval", "fresh", "excluded"))


class TestEvalIsFrozen:
    def test_a_second_run_never_changes_eval(self, tmp_path: Path) -> None:
        DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        first = (tmp_path / "eval.json").read_text(encoding="utf-8")
        more = [*UNITS, Kit.unit("e3", EVAL_FAMILY), Kit.unit("t3", TRAIN_FAMILIES[2])]
        DatasetExport.export(more, tmp_path, "pypi", "2026-11-01")
        assert (tmp_path / "eval.json").read_text(encoding="utf-8") == first

    def test_a_new_unit_of_an_eval_family_is_excluded_and_not_trained_on(self, tmp_path: Path) -> None:
        DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        counts = DatasetExport.export([*UNITS, Kit.unit("e3", EVAL_FAMILY)], tmp_path, "pypi", "2026-11-01")
        assert counts["excluded"] == 1 and "e3" not in Kit.read(tmp_path, "train")["artifacts"]
        assert Kit.read(tmp_path, "excluded")["artifacts"] == ["e3"]

    def test_a_new_ordinary_unit_goes_to_train(self, tmp_path: Path) -> None:
        DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        DatasetExport.export([*UNITS, Kit.unit("t3", TRAIN_FAMILIES[2])], tmp_path, "pypi", "2026-11-01")
        assert "t3" in Kit.read(tmp_path, "train")["artifacts"]

    def test_a_unit_that_left_the_catalogue_stays_in_eval(self, tmp_path: Path) -> None:
        DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        DatasetExport.export([u for u in UNITS if u["digest"] != "e1"], tmp_path, "pypi", "2026-11-01")
        assert Kit.read(tmp_path, "eval")["artifacts"] == ["e1", "e2"]

    def test_the_family_of_a_departed_eval_unit_stays_closed(self, tmp_path: Path) -> None:
        DatasetExport.export([Kit.unit("e1", EVAL_FAMILY)], tmp_path, "pypi", "2026-11-01")
        counts = DatasetExport.export([Kit.unit("e9", EVAL_FAMILY)], tmp_path, "pypi", "2026-11-01")
        assert counts["eval"] == 1 and counts["excluded"] == 1 and counts["train"] == 0

    def test_an_eval_list_written_empty_is_still_frozen(self, tmp_path: Path) -> None:
        DatasetExport.export([Kit.unit("t1", TRAIN_FAMILIES[0])], tmp_path, "pypi", "2026-11-01")
        DatasetExport.export([Kit.unit("t1", TRAIN_FAMILIES[0]), Kit.unit("e1", EVAL_FAMILY)], tmp_path, "pypi", "2026-11-01")
        assert Kit.read(tmp_path, "eval")["artifacts"] == [] and Kit.read(tmp_path, "excluded")["artifacts"] == ["e1"]

    def test_a_third_run_changes_nothing(self, tmp_path: Path) -> None:
        DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        snapshot = {n: (tmp_path / f"{n}.json").read_text(encoding="utf-8") for n in ("train", "eval", "fresh", "excluded")}
        DatasetExport.export(UNITS, tmp_path, "pypi", "2026-11-01")
        assert snapshot == {n: (tmp_path / f"{n}.json").read_text(encoding="utf-8") for n in snapshot}
