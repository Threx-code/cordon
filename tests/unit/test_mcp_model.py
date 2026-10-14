"""The shipped MCP tool-description model loads, is calibrated, and is quiet on plain tools.

Its recall is measured by `bench/mcp_poisoning.py` and `bench/mcp_model_train.py` on attack
datasets, not asserted here with invented attacks.
"""

from __future__ import annotations

import pytest

from cordon_scanner.detect.mcp_model import McpDescriptionModel


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
