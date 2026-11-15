"""The shipped MCP tool-description model loads, is calibrated, and is quiet on plain tools.

Its recall is measured by `bench/suites/mcp_poisoning.py` and `bench/model/mcp_model_train.py` on attack
datasets, not asserted here with invented attacks.
"""

from __future__ import annotations

import gzip
import json
import math
import sys
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.detect.agents.mcp_servers.description_model import (
    MODEL_PATH,
    LinearTextModel,
    McpDescriptionModel,
)
from support import ROOT


class TestTheModel:
    def test_it_ships_with_calibrated_thresholds(self) -> None:
        limits = McpDescriptionModel.thresholds()
        assert limits is not None
        block, warn = limits
        assert 0.0 < warn < block < 1.0
        calibration = McpDescriptionModel.model()["calibration"]
        assert calibration["description"]["benign_servers_held_out"] > 500
        assert McpDescriptionModel.thresholds("return") is not None

    @pytest.mark.parametrize(
        "description",
        [
            "Returns the weather forecast for a city.",
            "List all files in a directory. Returns names and sizes.",
            "Create a GitHub issue in the given repository with a title and body.",
            "Search the documentation and return the five most relevant passages.",
        ],
    )
    def test_a_plain_description_is_below_the_warning(self, description: str) -> None:
        score = McpDescriptionModel.score(description)
        assert score is not None and score < McpDescriptionModel.thresholds()[1]

    def test_scoring_is_deterministic(self) -> None:
        text = "Read a file from the workspace."
        assert McpDescriptionModel.score(text) == McpDescriptionModel.score(text)
        assert McpDescriptionModel.features(text) == McpDescriptionModel.features(text)


class Files:
    @staticmethod
    def model(tmp_path: Path, content: dict[str, Any]) -> Path:
        path = tmp_path / "model.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump(content, handle)
        return path

    @staticmethod
    def shipped() -> dict[str, Any]:
        with gzip.open(MODEL_PATH, "rt", encoding="utf-8") as handle:
            return json.load(handle)  # type: ignore[no-any-return]


class TestAChannelWithItsOwnWeights:
    """A file may give one channel its own bias and weights (`channels.<name>`); a channel without
    a block, and a file without any, scores from the top-level weights as before. Inert fixtures:
    no weight touches the text, so a score is the bias alone."""

    TEXT = "Read a file from the workspace."

    @staticmethod
    def logistic(z: float) -> float:
        return 1.0 / (1.0 + math.exp(-z))

    def test_a_channel_block_scores_its_channel_and_the_other_keeps_the_top_level_weights(
        self, tmp_path: Path
    ) -> None:
        path = Files.model(
            tmp_path,
            {
                "bias": -2.0,
                "weights": {},
                "thresholds": {"description": [0.9, 0.5], "return": [0.9, 0.5]},
                "channels": {"return": {"bias": 1.0, "weights": {}}},
            },
        )
        scorer = LinearTextModel(path, 8_000)
        assert scorer.score(self.TEXT, "description") == pytest.approx(self.logistic(-2.0))
        assert scorer.score(self.TEXT, "return") == pytest.approx(self.logistic(1.0))

    def test_a_channel_block_is_read_with_its_weights_by_index(self, tmp_path: Path) -> None:
        text = "alpha"
        index = next(iter(LinearTextModel(tmp_path, 8_000).features(text, "return")))
        path = Files.model(
            tmp_path,
            {
                "bias": 0.0,
                "weights": {},
                "thresholds": {"return": [0.9, 0.5]},
                "channels": {"return": {"bias": 0.0, "weights": {str(index): 5.0}}},
            },
        )
        scorer = LinearTextModel(path, 8_000)
        assert scorer.score(text, "return") > 0.9
        assert scorer.score(text, "description") == pytest.approx(0.5)

    def test_a_file_without_the_block_scores_every_channel_from_the_top_level_weights(
        self, tmp_path: Path
    ) -> None:
        path = Files.model(
            tmp_path,
            {
                "bias": -2.0,
                "weights": {},
                "thresholds": {"description": [0.9, 0.5], "return": [0.9, 0.5]},
            },
        )
        scorer = LinearTextModel(path, 8_000)
        assert scorer.score(self.TEXT, "description") == scorer.score(self.TEXT, "return")


class TestTheShippedChannels:
    DESCRIPTION = "c07ab8a0b8032a7024476f7c34e911f2bb9a5a2e3d6443879939ce47a4e3068c"
    """`McpChannelModel.digest(model, "description")` of the file as it shipped before the return
    channel was retrained (its weights, bias and lines). A later retraining that moves the
    description channel fails here on purpose: it has to say so, and show LOST 0 on the malicious
    units that only this channel holds (review 98, 12-TD-MODEL-RETRAIN)."""

    def test_the_description_channel_is_the_one_the_model_shipped_with(self) -> None:
        sys.path.insert(0, str(ROOT / "bench" / "model"))
        from mcp_channel_model import McpChannelModel

        assert McpChannelModel.digest(Files.shipped(), "description") == self.DESCRIPTION

    def test_the_return_channel_has_its_own_retrained_weights_and_lines(self) -> None:
        model = Files.shipped()
        assert "return" in model["channels"]
        block, warn = model["thresholds"]["return"]
        assert 0.0 < warn < block < 1.0
        assert model["calibration"]["channel_models"]["return"]["others_unchanged"][
            "description"
        ] == (self.DESCRIPTION)
