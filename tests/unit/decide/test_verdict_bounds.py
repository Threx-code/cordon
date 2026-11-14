"""S6, the package verdict: where the trained model may lower a rule's block (lead's decision,
2026-11-10, under the owner's strict rule).

```
  area mcp, skill, package, PyPI, ... ──► add-only: the model may add a block, never lift one
  area npm (the measured, shipped lift) ──► may lift where the model lists it
  Verdict.LIFT_AREAS_ALLOWED = {npm}: a new lift area is a deliberate, reviewed change
```
"""

from __future__ import annotations

import pytest

from cordon_scanner.decide.verdict import Verdict, VerdictModel


class TestTheLiftAreas:
    def test_only_npm_may_lift(self) -> None:
        assert frozenset({"npm"}) == Verdict.LIFT_AREAS_ALLOWED

    @pytest.mark.parametrize("area", ["mcp", "skill", "package", "pypi", "actions"])
    def test_every_other_area_is_add_only_whatever_the_model_lists(self, area: str) -> None:
        model = {"lift_areas": ["npm", "mcp", "skill", "package", "pypi", "actions"]}
        assert not Verdict.liftable(model, area)

    def test_npm_lifts_where_the_model_lists_it(self) -> None:
        assert Verdict.liftable({"lift_areas": ["npm", "mcp"]}, "npm")
        assert not Verdict.liftable({"lift_areas": ["mcp"]}, "npm")

    def test_the_shipped_model_lifts_in_npm_at_most(self) -> None:
        model = VerdictModel.load()
        if model is None:
            pytest.skip("no shipped model in this tree")
        areas = set(model.get("lift_areas") or ()) | set(model.get("areas", {}))
        assert {a for a in areas if Verdict.liftable(model, a)} <= {"npm"}
