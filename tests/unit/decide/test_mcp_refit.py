"""The MCP area has trees and a line of its own, and every other area is scored as it was (doc 20).

```
  verdict.json.gz   format 3: by_area["mcp"] (area_fit's trees on MCP rows) + areas["mcp"] (the pre-registered line)
                    + everything else carried: the shared trees, the other areas' lines, the policy lists
  verdict-pypi.json.gz   not rewritten: the same bytes as before the refit
```
The digests are of the files as shipped before the refit (0469472a). They are computed over the canonical
JSON (sorted keys, no blanks) of the carried parts, so a changed tree, line or list fails here by name.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import math
from typing import Any

import pytest

from cordon_scanner.decide.feature_schema import FeatureFold, FeatureScope
from cordon_scanner.decide.verdict import MODEL_PATH, PYPI_MODEL_PATH, Verdict, VerdictModel

#: Before the refit (the shipped files at 0469472a), see the module docstring.
SHARED_TREES = "f0b06e434b3dee7e1442d19bef62ae332fbc659ac3f48526386d769df3cd1eaf"
OTHER_AREA_LINES = "24a0837f36d51cb80f7201635a16d47a75a89651a2a8ece34cfee1b417a0a69f"
POLICY_LISTS = "df853ff692582ec8e123b4f269b06c12bead8073104d3ce2141b697e50d0ddc8"
PYPI_FILE = "7d025ecfe40bd6e8067922681c991b412708eb92aa423ec31774590c0cf6f30a"
#: The pre-registered operating point (doc 20, written before any sealed number): the line the
#: legitimate MCP rows exceed at 0.05% out of fold.
BAR = 0.0005


def canon(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode()).hexdigest()


def shipped() -> dict[str, Any]:
    with gzip.open(MODEL_PATH, "rt", encoding="utf-8") as handle:
        return json.load(handle)


class TestEveryOtherAreaIsScoredAsItWas:
    def test_the_shared_trees_are_the_shipped_ones(self) -> None:
        model = shipped()
        assert (
            canon(
                {
                    "features": model["features"],
                    "baseline": model["baseline"],
                    "trees": model["trees"],
                }
            )
            == SHARED_TREES
        )

    def test_the_other_areas_keep_their_lines(self) -> None:
        areas = {k: v for k, v in shipped()["areas"].items() if k != "mcp"}
        assert canon(areas) == OTHER_AREA_LINES

    def test_the_policy_lists_are_the_shipped_ones(self) -> None:
        model = shipped()
        lists = {k: model.get(k) for k in ("floor", "keep", "add_only", "lift_areas")}
        assert canon(lists) == POLICY_LISTS

    def test_the_pypi_model_is_the_same_file(self) -> None:
        assert hashlib.sha256(PYPI_MODEL_PATH.read_bytes()).hexdigest() == PYPI_FILE

    def test_only_mcp_has_trees_of_its_own(self) -> None:
        assert set(shipped()["by_area"]) == {"mcp"}

    def test_mcp_stays_add_only(self) -> None:
        model = VerdictModel.load(MODEL_PATH)
        assert model is not None
        assert Verdict.liftable(model, "mcp") is False


class TestTheMcpTreesAndLine:
    def test_the_model_is_fitted_at_this_trees_fold(self) -> None:
        model = shipped()
        assert model["format"] == VerdictModel.FORMAT
        assert model["fold"] == FeatureFold.version()

    def test_the_trees_read_only_what_a_users_scan_computes(self) -> None:
        names = shipped()["by_area"]["mcp"]["features"]
        assert names
        assert all(FeatureScope.computed(n) for n in names)

    def test_the_line_is_the_one_area_fit_measured_at_the_pre_registered_bar(self) -> None:
        model = shipped()
        fit = model["manifest"]["area_fits"]["mcp"]
        assert fit["bar"] == BAR
        assert fit["folds"] == 5
        assert model["areas"]["mcp"] == fit["line"]
        assert 0.0 < fit["line"] < 1.0
        # At most floor(bar * n) legitimate rows were over the line out of fold.
        assert fit["benign_blocked"] <= math.floor(BAR * fit["benign"])
        assert fit["export_worst_difference"] <= 1e-6

    def test_no_scale_is_put_on_top_of_it(self) -> None:
        assert Verdict.LINE_SCALE == {}
        areas = {"mcp": 0.25, "package": 0.5}
        assert Verdict.line(areas, "mcp") == 0.25

    def test_mcp_is_scored_by_its_own_trees_and_the_others_by_the_shared_ones(self) -> None:
        model = shipped()
        assert "mcp" in model["by_area"]
        for area in ("npm", "skill", "package", "pypi", "actions"):
            assert area not in model["by_area"]


@pytest.mark.parametrize("area", ["npm", "skill", "package", "actions"])
def test_a_non_mcp_area_is_judged_by_the_shared_model(area: str) -> None:
    model = VerdictModel.load(MODEL_PATH)
    assert model is not None
    assert model.get("by_area", {}).get(area, model) is model
