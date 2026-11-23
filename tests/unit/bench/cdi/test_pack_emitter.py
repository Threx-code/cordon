"""A pack the loop emits explains itself with the numbers the distiller measured, under ids the scanner accepts."""

from __future__ import annotations

import sys

import pytest
import yaml

from support import ROOT as REPO

sys.path.insert(0, str(REPO))

from bench.cdi.distill import Distiller, PackRenderer
from test_pack_probing import Evasion


class Emitted:
    @staticmethod
    def candidate() -> dict:
        found = Distiller().distill(Evasion.first_window()).candidate
        assert found is not None
        return found

    @classmethod
    def rule(cls, batch: str | None = "batch-one", rule_id: str = "LEARNED.NPM.7") -> dict:
        return yaml.safe_load(PackRenderer.render(cls.candidate(), rule_id, batch=batch))["rules"][
            0
        ]


class TestTheLearnedBlock:
    def test_it_has_exactly_the_four_keys_the_scanner_reads(self) -> None:
        assert set(Emitted.rule()["learned"]) == {"families", "legit_rate", "interval", "batch"}

    def test_families_is_the_number_the_rule_was_learned_from(self) -> None:
        block = Emitted.rule()["learned"]
        assert block["families"] == Emitted.candidate()["train"]["families"] == 4 and isinstance(
            block["families"], int
        )

    def test_the_rate_lies_inside_its_interval_inside_zero_and_one(self) -> None:
        block = Emitted.rule()["learned"]
        low, high = block["interval"]
        assert 0 <= low <= block["legit_rate"] <= high <= 1 and low == 0

    def test_the_rate_is_the_observed_one_and_the_upper_bound_is_the_confirm_bound(self) -> None:
        confirm = Emitted.candidate()["confirm"]
        block = Emitted.rule()["learned"]
        assert block["legit_rate"] == round(confirm["legit_fires"] / confirm["legit_n"], 6)
        assert block["interval"][1] == max(confirm["legit_upper"], block["legit_rate"])

    def test_the_batch_is_the_label_given(self) -> None:
        assert Emitted.rule(batch="window:2026-w47")["learned"]["batch"] == "window:2026-w47"

    @pytest.mark.parametrize("batch", ["", "a b", "x" * 65, "ü", "a/b"])
    def test_a_batch_the_scanner_would_refuse_is_not_written(self, batch: str) -> None:
        with pytest.raises(ValueError, match="batch label"):
            PackRenderer.render(Emitted.candidate(), "LEARNED.NPM.7", batch=batch)

    def test_without_a_batch_there_is_no_block(self) -> None:
        assert "learned" not in Emitted.rule(batch=None)

    def test_a_candidate_with_no_confirm_count_cannot_state_its_rate(self) -> None:
        candidate = Emitted.candidate()
        candidate["confirm"] = {"families": 1, "legit_upper": 0.001}
        with pytest.raises(ValueError, match="confirm legit count"):
            PackRenderer.render(candidate, "LEARNED.NPM.7", batch="b")


class TestTheIds:
    @pytest.mark.parametrize(
        "rule_id", ["LEARNED.NPM.1", "LEARNED.MCP.123456", "LEARNED.SKILL_X.7"]
    )
    def test_an_area_and_a_number_are_accepted(self, rule_id: str) -> None:
        assert Emitted.rule(rule_id=rule_id)["id"] == rule_id

    @pytest.mark.parametrize(
        "rule_id",
        [
            "SUSPECT.NPM.1",
            "LEARNED.NPM",
            "LEARNED.npm.1",
            "LEARNED.NPM.INSTALL.001",
            "LEARNED.NPM.x",
        ],
    )
    def test_any_other_shape_is_refused(self, rule_id: str) -> None:
        with pytest.raises(ValueError, match="LEARNED"):
            PackRenderer.render(Emitted.candidate(), rule_id)
