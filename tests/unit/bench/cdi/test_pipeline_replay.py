"""LL-147: a candidate whose block arrives through a composite is counted by the pre-test, which runs the scanner's own composites over a unit's cached findings."""

from __future__ import annotations

from typing import ClassVar

from bench.cdi.pipeline_replay import PipelineReplay

SELF_PUBLISH = ["SUSPECT.REGISTRY.SELF_PUBLISH.001", "medium", "medium", "suspicious", "capability"]
DECODE_EXEC = ["SUSPECT.DECODE_EXEC.001", "medium", "medium", "suspicious", "capability"]
REMOTE_CODE = ["SUSPECT.DROPPER.REMOTE_CODE.001", "medium", "medium", "suspicious", "capability"]


class TestAWormPartThatDoesNotBlockAloneCompletesTheComposite:
    def test_the_cached_findings_alone_do_not_block(self) -> None:
        assert PipelineReplay.blocks([SELF_PUBLISH, DECODE_EXEC]) is False

    def test_the_candidates_own_finding_does_not_block_by_the_content_rule(self) -> None:
        """Today's pre-test: the unit with the candidate's finding added, judged one finding at a time, is still not blocked."""
        assert PipelineReplay.blocks_by_content([SELF_PUBLISH, DECODE_EXEC, REMOTE_CODE]) is False

    def test_with_the_composites_the_unit_is_blocked_and_the_block_came_through_one(self) -> None:
        cached, added = [SELF_PUBLISH, DECODE_EXEC], [REMOTE_CODE]
        assert PipelineReplay.blocks(cached, added) is True
        assert PipelineReplay.through_a_composite(cached, added) is True

    def test_the_composite_is_the_scanners_own_finding(self) -> None:
        made = PipelineReplay.composites([SELF_PUBLISH, DECODE_EXEC, REMOTE_CODE])
        assert [r[0] for r in made] == ["MALWARE.WORM.SELF_PROPAGATION.001"]
        assert made[0][1] == "critical" and made[0][3] == "malicious"

    def test_two_of_three_parts_make_no_composite(self) -> None:
        assert PipelineReplay.composites([SELF_PUBLISH, REMOTE_CODE]) == []
        assert PipelineReplay.blocks([SELF_PUBLISH], [REMOTE_CODE]) is False

    def test_a_part_graded_under_medium_does_not_count(self) -> None:
        low = [*REMOTE_CODE[:1], "low", *REMOTE_CODE[2:]]
        assert PipelineReplay.blocks([SELF_PUBLISH, DECODE_EXEC], [low]) is False


class TestWhatTheReplayDoesNotChange:
    def test_a_unit_the_gate_already_blocks_is_not_counted_as_through_a_composite(self) -> None:
        blocking = ["MALWARE.EXFIL.001", "high", "high", "malicious", "capability"]
        assert PipelineReplay.blocks([blocking]) is True
        assert PipelineReplay.through_a_composite([blocking], []) is False

    def test_an_intel_finding_is_not_content(self) -> None:
        known = ["MALWARE.PACKAGE.KNOWN.001", "critical", "confirmed", "malicious", "intel"]
        assert PipelineReplay.blocks_by_content([known]) is False

    def test_nothing_added_and_nothing_cached_blocks_nothing(self) -> None:
        assert PipelineReplay.blocks([], []) is False

    def test_the_gaps_are_named_for_every_report(self) -> None:
        assert set(PipelineReplay.GAPS) == {"ceilings", "verdict_model", "injection_basis"}


class TestInjectionPhraseBesideTheLearnedReading:
    PHRASE: ClassVar[list[str]] = [
        "SUSPECT.AGENT.ATR.PROMPT_INJECTION.001",
        "medium",
        "low",
        "suspicious",
        "agents",
    ]
    READING: ClassVar[list[str]] = [
        "SUSPECT.AGENT.SKILL_INSTRUCTIONS.001",
        "low",
        "low",
        "suspicious",
        "agents",
    ]

    def test_both_present_make_the_corroborated_finding(self) -> None:
        made = PipelineReplay.composites([self.PHRASE, self.READING])
        assert [r[0] for r in made] == ["SUSPECT.AGENT.INJECTION_CORROBORATED.001"]

    def test_the_phrase_at_another_grade_is_not_the_one_measured(self) -> None:
        other = [self.PHRASE[0], "high", "high", *self.PHRASE[3:]]
        assert PipelineReplay.composites([other, self.READING]) == []


class TestFlagsOverUnits:
    def test_a_candidate_adding_the_third_part_flags_exactly_the_units_that_hold_the_other_two(
        self,
    ) -> None:
        units = [
            {"u": "a", "f": [SELF_PUBLISH, DECODE_EXEC]},
            {"u": "b", "f": [SELF_PUBLISH]},
            {"u": "c", "f": []},
        ]
        flagged = PipelineReplay.flags(units, lambda u: [REMOTE_CODE])
        assert flagged == {"a": True, "b": False, "c": False}
