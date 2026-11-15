"""The MCP model's lines are re-set on a larger benign pool, and the weights are not touched.

```
  shipped model (weights, bias) + devset rows (label, channel, source, group, half, text)
      pool     = held-out half of the sources the lines were first set on,
                 plus every row of a source the weights never saw
      line     = the score above which at most `share` of the pool's servers fall,
                 a server scoring as its highest text (the trainer's own rule)
      written  = the same weights and bias, new thresholds, a calibration that says what it used
```
"""

from __future__ import annotations

import gzip
import json
import sys
from typing import Any

from cordon_scanner.detect.agents.mcp_servers.description_model import McpDescriptionModel
from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "model"))

from mcp_model_train import McpModelTrainer
from mcp_recalibrate import McpRecalibrate


class Rows:
    @staticmethod
    def row(source: str, group: str, half: str, channel: str = "description", label: int = 0):
        return {
            "source": source,
            "group": group,
            "half": half,
            "channel": channel,
            "label": label,
            "text": f"{source} {group}",
        }


class TestThePool:
    def test_the_held_out_half_of_a_trained_source_counts_and_its_work_half_does_not(self) -> None:
        rows = [Rows.row("corpus", "a", "holdout"), Rows.row("corpus", "b", "work")]
        assert [r["group"] for r in McpRecalibrate.pool(rows, "description")] == ["a"]

    def test_a_source_the_weights_never_saw_counts_whole(self) -> None:
        rows = [Rows.row("census", "a", "holdout"), Rows.row("census", "b", "work")]
        assert [r["group"] for r in McpRecalibrate.pool(rows, "description")] == ["a", "b"]

    def test_an_attack_row_never_counts(self) -> None:
        rows = [Rows.row("census", "a", "holdout", label=1), Rows.row("mcptox", "b", "holdout")]
        assert McpRecalibrate.pool(rows, "description") == []

    def test_each_channel_has_its_own_sources(self) -> None:
        rows = [
            Rows.row("census", "a", "holdout"),
            Rows.row("census-return", "b", "holdout", channel="return"),
            Rows.row("corpus-return", "c", "work", channel="return"),
        ]
        assert [r["group"] for r in McpRecalibrate.pool(rows, "description")] == ["a"]
        assert [r["group"] for r in McpRecalibrate.pool(rows, "return")] == ["b"]


class TestTheLines:
    def test_a_server_scores_as_its_highest_text_and_the_line_is_the_trainers(self) -> None:
        rows = [Rows.row("census", str(i % 50), "work") for i in range(500)]
        scores = [(i % 50) / 50.0 + (i // 50) / 1000.0 for i in range(500)]
        block, warn, servers = McpRecalibrate.lines(rows, scores, 0.02, 0.2)
        best = McpModelTrainer.per_group(rows, scores)
        assert servers == 50 == len(best)
        assert block == McpModelTrainer.threshold(best, 0.02)
        assert warn == McpModelTrainer.threshold(best, 0.2)
        assert warn < block

    def test_the_same_group_name_in_two_sources_is_two_servers(self) -> None:
        rows = [Rows.row("census", "x", "work"), Rows.row("corpus", "x", "holdout")]
        assert McpRecalibrate.lines(rows, [0.1, 0.2], 0.5, 0.5)[2] == 2


class TestTheModelWritten:
    @staticmethod
    def shipped() -> dict[str, Any]:
        model: dict[str, Any] = {
            "bias": -3.5,
            "weights": {"7": 1.25, "9": -0.5},
            "thresholds": {"description": [0.7, 0.3], "return": [0.9, 0.6]},
            "calibration": {
                "description": {"benign_servers_held_out": 10, "block": 0.7, "warn": 0.3},
                "return": {"benign_servers_held_out": 8, "block": 0.9, "warn": 0.6},
                "return:atr-return": {"n": 606, "blocked": 0.3135, "warned_or_blocked": 0.4686},
            },
            "trained_on": ["corpus"],
            "features": "word 1-3 grams",
        }
        return model

    def written(self) -> dict[str, Any]:
        rows = [Rows.row("census", str(i), "work") for i in range(200)]
        rows += [Rows.row("census-return", str(i), "work", channel="return") for i in range(100)]
        scores = {
            "description": [i / 200 for i in range(200)],
            "return": [i / 100 for i in range(100)],
        }
        return McpRecalibrate.recalibrated(self.shipped(), rows, scores)

    def test_the_weights_and_the_bias_are_the_same(self) -> None:
        model = self.written()
        assert model["weights"] == self.shipped()["weights"]
        assert model["bias"] == self.shipped()["bias"]
        assert model["trained_on"] == self.shipped()["trained_on"]

    def test_the_lines_are_the_ones_the_pool_gives(self) -> None:
        model = self.written()
        for channel, count in (("description", 200), ("return", 100)):
            block, warn = model["thresholds"][channel]
            report = model["calibration"][channel]
            assert (block, warn) == (report["block"], report["warn"])
            assert report["benign_servers_held_out"] == count
            assert 0.0 < warn < block < 1.0 + 1e-6

    def test_the_calibration_says_what_it_replaced(self) -> None:
        recalibration = self.written()["calibration"]["recalibration"]
        assert recalibration["previous_lines"] == {"description": [0.7, 0.3], "return": [0.9, 0.6]}
        assert "census" in recalibration["never_trained_on"]

    def test_a_figure_that_cannot_be_remeasured_is_marked_as_the_old_lines(self) -> None:
        carried = self.written()["calibration"]["return:atr-return"]
        assert carried["n"] == 606
        assert carried["lines"] == "previous"


class TestTheShippedModel:
    """The lines the model ships are the ones its calibration records."""

    @staticmethod
    def raw() -> dict[str, Any]:
        path = REPO / "src" / "cordon_scanner" / "detect" / "data" / "mcp-descriptions.json.gz"
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            loaded: dict[str, Any] = json.load(handle)
        return loaded

    def test_the_lines_match_the_calibration(self) -> None:
        raw = self.raw()
        for channel in ("description", "return"):
            assert raw["thresholds"][channel] == [
                raw["calibration"][channel]["block"],
                raw["calibration"][channel]["warn"],
            ]
        assert tuple(raw["thresholds"]["description"]) == McpDescriptionModel.thresholds()

    def test_the_recorded_recall_on_the_held_out_attacks_stays_above_its_floor(self) -> None:
        """MCPTox descriptions on the held-out half, at the lines that ship."""
        recorded = self.raw()["calibration"]["description:mcptox"]
        assert recorded["n"] >= 100
        assert recorded["blocked"] >= 0.98
