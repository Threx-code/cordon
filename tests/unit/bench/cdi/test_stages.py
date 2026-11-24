"""A candidate that would block 5% of legitimate packages is stopped at the first stage it reaches; a sound one passes them all."""

from __future__ import annotations

from typing import ClassVar

import pytest
from bench.cdi.stages import Stages


class Rates:
    SOUND: ClassVar[dict[str, tuple[int, int]]] = {
        "pretest": (0, 4000),
        "gate": (3, 4000),
        "shadow": (2, 1000),
        "rollback": (1, 1000),
    }

    @staticmethod
    def with_(stage: str, blocked: int, units: int) -> dict[str, tuple[int, int]]:
        return {**Rates.SOUND, stage: (blocked, units)}


class TestTheFirstStageThatSeesIt:
    def test_a_candidate_that_blocks_five_percent_is_stopped_at_the_pretest(self) -> None:
        record = Stages.run(Rates.with_("pretest", 200, 4000))
        assert record["stopped_at"] == "pretest" and record["passed"] == []

    def test_even_if_every_later_stage_would_also_stop_it_the_first_one_is_named(self) -> None:
        worst = dict.fromkeys(Stages.ORDER, (50, 1000))
        assert Stages.run(worst)["stopped_at"] == "pretest"

    def test_a_candidate_the_pretest_cannot_see_is_stopped_at_the_gate(self) -> None:
        record = Stages.run({"gate": (50, 1000), "shadow": (50, 1000)})
        assert (record["stopped_at"], record["passed"]) == ("gate", [])

    def test_a_candidate_that_passes_to_the_shadow_run_is_stopped_there(self) -> None:
        record = Stages.run(Rates.with_("shadow", 50, 1000))
        assert (record["stopped_at"], record["passed"]) == ("shadow", ["pretest", "gate"])

    def test_the_devices_rollback_is_the_last_stage(self) -> None:
        record = Stages.run(Rates.with_("rollback", 30, 1000))
        assert (record["stopped_at"], record["passed"]) == (
            "rollback",
            ["pretest", "gate", "shadow"],
        )

    def test_a_sound_candidate_passes_every_stage(self) -> None:
        assert Stages.run(Rates.SOUND) == {
            "stopped_at": None,
            "passed": list(Stages.ORDER),
            "reason": "",
        }

    @pytest.mark.parametrize("stage", Stages.ORDER)
    def test_a_stage_with_no_units_is_no_evidence_and_stops_the_candidate(self, stage: str) -> None:
        assert Stages.run({stage: (0, 0)})["stopped_at"] == stage
