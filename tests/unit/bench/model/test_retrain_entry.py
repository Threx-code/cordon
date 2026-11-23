"""A retrain on a fixture list writes the model, the metrics and the list's sha256; a model that would lower a finding is refused and writes nothing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from bench.model.area import Contract
from bench.model.retrain_entry import RetrainEntry, RetrainRefused

IDS = ["u1", "u2", "u3"]


class Kit:
    @staticmethod
    def run(out: Path, new_scores: dict[str, float], **more: Any) -> dict[str, Any]:
        return RetrainEntry.run(
            out,
            area="npm",
            seed=7,
            train_ids=IDS,
            model={"trees": []},
            metrics={"recall": 0.9},
            old_scores={"m1": 0.9, "m2": 0.8, "l1": 0.1},
            old_line=0.5,
            new_scores=new_scores,
            new_line=0.5,
            never_lose=["m1"],
            **more,
        )


class TestARetrainOnAFixtureList:
    def test_it_writes_the_model_the_metrics_and_the_lists_sha256(self, tmp_path: Path) -> None:
        body = Kit.run(tmp_path, {"m1": 0.95, "m2": 0.7, "l1": 0.1, "m3": 0.9})
        assert (tmp_path / "model.json").is_file() and (tmp_path / "metrics.json").is_file()
        sha = (tmp_path / "training_list.sha256").read_text(encoding="utf-8").strip()
        assert sha == Contract.training_list_sha(IDS) == body["training_list_sha"]
        assert body["flips"] == {"unblocked": 0, "newly_blocked": 1, "kept_blocked": 2, "lost": 0}

    def test_the_same_list_in_another_order_has_the_same_sha(self, tmp_path: Path) -> None:
        assert Contract.training_list_sha(reversed(IDS)) == Contract.training_list_sha(IDS)


class TestAModelThatWouldLowerAFindingIsRefused:
    def test_a_never_lose_unit_that_goes_from_blocked_to_allowed_refuses_it_and_writes_nothing(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(RetrainRefused, match="never-lose"):
            Kit.run(tmp_path, {"m1": 0.2, "m2": 0.9, "l1": 0.1})
        assert list(tmp_path.iterdir()) == []

    def test_a_never_lose_unit_the_new_model_does_not_score_refuses_it(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(RetrainRefused):
            Kit.run(tmp_path, {"m2": 0.9, "l1": 0.1})

    def test_a_looser_line_on_the_established_legitimate_units_refuses_it(
        self, tmp_path: Path
    ) -> None:
        old = {"npm": {"l1": 0.1, "l2": 0.2}}
        new = {"npm": {"l1": 0.6, "l2": 0.7}}
        with pytest.raises(RetrainRefused, match="npm"):
            Kit.run(
                tmp_path,
                {"m1": 0.95, "m2": 0.9, "l1": 0.1},
                scores_by_area=(old, new),
                lines_by_area=({"npm": 0.5}, {"npm": 0.5}),
                established=["l1", "l2"],
            )
        assert list(tmp_path.iterdir()) == []
