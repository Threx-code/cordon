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
import json

import pytest

from cordon_scanner.decide.verdict import MODEL_PATH, Verdict, VerdictModel


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
    """MCP servers are held to 0.9 of the model's block line (candidate, cordon-a0 2026-11-15; the
    sealed finals decide whether it stays). The pin is in code, so the model stays what was fitted."""

    def test_the_pin_is_mcp_at_nine_tenths_and_nothing_else(self) -> None:
        assert Verdict.LINE_SCALE == {"mcp": 0.9}

    def test_mcp_blocks_at_nine_tenths_of_its_line(self) -> None:
        assert Verdict.line({"mcp": 1.0, "package": 0.5}, "mcp") == pytest.approx(0.9)

    @pytest.mark.parametrize("area", ["npm", "pypi", "skill", "package", "actions"])
    def test_every_other_area_keeps_its_line(self, area: str) -> None:
        areas = {"npm": 0.8, "pypi": 0.7, "skill": 0.6, "package": 0.5, "actions": 0.4, "mcp": 1.0}
        assert Verdict.line(areas, area) == areas[area]

    def test_an_area_with_no_line_answers_to_the_fallback_unscaled(self) -> None:
        assert Verdict.line({"package": 0.5}, "ruby") == 0.5

    def test_mcp_with_no_line_of_its_own_answers_to_the_fallback_scaled(self) -> None:
        assert Verdict.line({"package": 0.5}, "mcp") == pytest.approx(0.45)

    def test_the_shipped_models_mcp_line_is_scaled_by_it(self) -> None:
        model = VerdictModel.load()
        if model is None or "mcp" not in model.get("areas", {}):
            pytest.skip("no shipped model with an MCP line in this tree")
        assert Verdict.line(model["areas"], "mcp") == pytest.approx(0.9 * model["areas"]["mcp"])
