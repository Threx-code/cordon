"""One channel of the MCP model takes its own weights and lines; every other channel is left byte for byte.

```
  shipped {bias, weights, thresholds{description, return}}   retrained {bias, weights, thresholds{...}}
      --channel return -->  shipped + channels.return = {bias, weights}, the retrained return lines
```
Inert fixtures: tiny models with a few made-up weights, no text.
"""

from __future__ import annotations

import copy
import sys
from typing import Any

import pytest

from support import ROOT as REPO

sys.path.insert(0, str(REPO / "bench" / "model"))

from mcp_channel_model import McpChannelModel


class Models:
    @staticmethod
    def shipped() -> dict[str, Any]:
        return {
            "bias": -3.0,
            "weights": {"7": 1.5, "2": -0.5},
            "thresholds": {"description": [0.7, 0.2], "return": [0.9, 0.7]},
            "calibration": {
                "description": {"benign_servers_held_out": 900},
                "return": {"benign_servers_held_out": 726},
                "return:mcpsafetybench-return": {"n": 20, "blocked": 0.05},
                "description:mcptox": {"n": 79, "blocked": 0.7},
            },
            "trained_on": ["mcptox"],
        }

    @staticmethod
    def retrained() -> dict[str, Any]:
        return {
            "bias": -4.5,
            "weights": {"7": 0.1, "3": 2.0},
            "thresholds": {"description": [0.95, 0.12], "return": [0.77, 0.07]},
            "calibration": {
                "description": {"benign_servers_held_out": 5000},
                "return": {"benign_servers_held_out": 3500},
                "return:mcpsafetybench-return": {"n": 34, "blocked": 0.44},
            },
            "trained_on": ["mcptox", "harvest"],
        }


class TestMerged:
    def test_the_named_channel_takes_the_retrained_weights_and_lines(self) -> None:
        out = McpChannelModel.merged(Models.shipped(), Models.retrained(), "return")
        assert out["channels"]["return"] == {"bias": -4.5, "weights": {"7": 0.1, "3": 2.0}}
        assert out["thresholds"]["return"] == [0.77, 0.07]

    def test_every_other_channel_is_byte_for_byte_the_shipped_one(self) -> None:
        before = Models.shipped()
        out = McpChannelModel.merged(before, Models.retrained(), "return")
        assert McpChannelModel.digest(out, "description") == McpChannelModel.digest(
            before, "description"
        )
        assert out["weights"] == before["weights"]
        assert out["bias"] == before["bias"]
        assert out["thresholds"]["description"] == before["thresholds"]["description"]

    def test_the_channels_calibration_is_replaced_and_the_others_kept(self) -> None:
        out = McpChannelModel.merged(Models.shipped(), Models.retrained(), "return")
        assert out["calibration"]["return"]["benign_servers_held_out"] == 3500
        assert out["calibration"]["return:mcpsafetybench-return"]["n"] == 34
        assert out["calibration"]["description"]["benign_servers_held_out"] == 900
        assert out["calibration"]["description:mcptox"]["n"] == 79

    def test_it_records_what_the_channel_was_trained_on_and_that_the_others_did_not_move(
        self,
    ) -> None:
        out = McpChannelModel.merged(Models.shipped(), Models.retrained(), "return")
        record = out["calibration"]["channel_models"]["return"]
        assert record["trained_on"] == ["mcptox", "harvest"]
        assert record["weight_count"] == 2
        assert record["others_unchanged"]["description"] == McpChannelModel.digest(
            Models.shipped(), "description"
        )

    def test_the_inputs_are_not_changed(self) -> None:
        before, other = Models.shipped(), Models.retrained()
        kept = (copy.deepcopy(before), copy.deepcopy(other))
        McpChannelModel.merged(before, other, "return")
        assert (before, other) == kept

    def test_it_refuses_a_channel_either_model_has_no_lines_for(self) -> None:
        with pytest.raises(ValueError, match="skill"):
            McpChannelModel.merged(Models.shipped(), Models.retrained(), "skill")


class TestDigest:
    def test_it_follows_the_channels_own_block_when_there_is_one(self) -> None:
        plain = Models.shipped()
        out = McpChannelModel.merged(plain, Models.retrained(), "return")
        assert McpChannelModel.digest(out, "return") != McpChannelModel.digest(plain, "return")

    def test_a_changed_weight_a_changed_bias_or_a_changed_line_each_moves_it(self) -> None:
        base = McpChannelModel.digest(Models.shipped(), "description")
        a, b, c = Models.shipped(), Models.shipped(), Models.shipped()
        a["weights"]["7"] = 1.6
        b["bias"] = -3.1
        c["thresholds"]["description"][0] = 0.71
        assert (
            len(
                {
                    base,
                    McpChannelModel.digest(a, "description"),
                    McpChannelModel.digest(b, "description"),
                    McpChannelModel.digest(c, "description"),
                }
            )
            == 4
        )

    def test_the_calibration_and_the_other_channels_do_not_move_it(self) -> None:
        base = McpChannelModel.digest(Models.shipped(), "description")
        changed = Models.shipped()
        changed["calibration"]["description"]["benign_servers_held_out"] = 1
        changed["thresholds"]["return"] = [0.1, 0.05]
        assert McpChannelModel.digest(changed, "description") == base
