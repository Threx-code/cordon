"""The edges the mutation of the nine row modules found loose (PR 99): each test pins one value, boundary or message a mutant could move unseen."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bench.cdi.claims import ClaimRefused, Claims
from bench.cdi.export import DatasetExport
from bench.cdi.feedback import Feedback
from bench.cdi.graph import COMMON_AT, ThreatGraph
from bench.cdi.hypothesis import Distance, HypothesisRefused
from bench.cdi.lineage import Lineage
from bench.cdi.scorecard import Baseline, Conclusion, Proportions, Scorecard

FINDING = [["SUSPECT.AGENT.SKILL_INSTRUCTIONS.001", "high", "high", "suspicious", "a/SKILL.md", 3, "agent"]]
OTHER = [["MALWARE.DROPPER.001", "critical", "high", "malicious", "b/setup.py", 9, "dropper"]]


class Rows:
    @staticmethod
    def row(name: str, sha: str | None, findings: list[list[Any]]) -> dict[str, Any]:
        row: dict[str, Any] = {"file": name, "exit": 1, "findings": findings}
        if sha is not None:
            row["sha256"] = sha
        return row


class TestLineage:
    def test_two_units_with_nothing_in_common_are_not_a_miss_of_the_sha_check_either(self) -> None:
        train = {"t": Rows.row("a", "sha-1", FINDING)}
        held = {"h": Rows.row("b", "sha-2", OTHER)}
        assert Lineage.overlap(train, held) == {"units": 0, "by_content": 0, "by_sha256": 0, "missed_by_sha256": 0}

    def test_a_row_with_no_sha256_is_compared_by_its_file_name(self) -> None:
        train = {"t": Rows.row("same-name", None, [])}
        assert Lineage.overlap(train, {"h": Rows.row("same-name", None, [])})["by_sha256"] == 1
        assert Lineage.overlap(train, {"h": Rows.row("other-name", None, [])})["by_sha256"] == 0

    def test_a_row_with_neither_sha256_nor_file_has_the_empty_name(self) -> None:
        assert Lineage.sha({}) == ""

    def test_a_reworded_copy_is_counted_once_as_missed_by_the_sha_check(self) -> None:
        train = {"t": Rows.row("a", "sha-1", FINDING)}
        held = {"h": Rows.row("b", "sha-2", [[*FINDING[0][:5], 77, "agent"]])}
        assert Lineage.overlap(train, held)["missed_by_sha256"] == 1


class TestClaims:
    def test_a_catalogue_just_under_100000_is_the_plan_for_legitimate_units(self) -> None:
        assert Claims.short_of_plan(500, 20_000, catalogue=99_999) == (
            "legitimate held-out 20000 is short of the plan 99999",
        )

    def test_a_catalogue_of_exactly_100000_is_not_under_it_so_the_plan_is_15000(self) -> None:
        assert Claims.short_of_plan(500, 15_000, catalogue=100_000) == ()
        assert Claims.short_of_plan(500, 14_999, catalogue=100_000) == (
            "legitimate held-out 14999 is short of the plan 15000",
        )

    def test_a_refusal_says_refused_and_joins_every_reason(self) -> None:
        with pytest.raises(ClaimRefused) as caught:
            Claims.require(["only"] * 5, 1, 10)
        text = str(caught.value)
        assert text.startswith("refused: ") and "; " in text
        assert all(reason in text for reason in caught.value.reasons)

    def test_the_largest_family_share_is_the_largest_whatever_the_order(self) -> None:
        held = ["a"] * 3 + ["b"] * 40 + ["c"] * 3 + [f"f{i}" for i in range(10)] * 2
        assert any("40 of" in reason for reason in Claims.diversity(held, 1_000))


class TestExport:
    def read(self, out: Path, name: str) -> dict[str, Any]:
        return json.loads((out / f"{name}.json").read_text(encoding="utf-8"))

    def unit(self, digest: str, family: str, seen: str = "2026-01-05") -> dict[str, Any]:
        return {"digest": digest, "family": family, "first_seen": seen}

    def test_one_family_in_ten_is_in_the_eval_bucket_and_which_ones_never_change(self) -> None:
        assert [i for i in range(60) if DatasetExport.eval_family(f"fam{i}")] == [7, 11, 19, 32, 49]
        assert sum(1 for i in range(1_000) if DatasetExport.eval_family(f"fam{i}")) == 90

    def test_only_the_eval_manifest_lists_its_families_and_before_the_freeze_it_names_them(self, tmp_path: Path) -> None:
        eval_family = next(f for f in (f"fam{i}" for i in range(100)) if DatasetExport.eval_family(f))
        DatasetExport.export([self.unit("e1", eval_family), self.unit("t1", "fam0")], tmp_path, "a", "2026-11-01")
        assert self.read(tmp_path, "eval")["families"] == [eval_family]
        for name in ("train", "fresh", "excluded"):
            assert "families" not in self.read(tmp_path, name)

    def test_the_output_folder_is_made_with_its_parents_and_may_already_exist(self, tmp_path: Path) -> None:
        out = tmp_path / "deep" / "er" / "still"
        DatasetExport.export([self.unit("t1", "fam0")], out, "a", "2026-11-01")
        DatasetExport.export([self.unit("t1", "fam0")], out, "a", "2026-11-01")
        assert (out / "train.json").exists()

    def test_each_file_is_indented_json_ending_in_a_newline(self, tmp_path: Path) -> None:
        DatasetExport.export([self.unit("t1", "fam0")], tmp_path, "a", "2026-11-01")
        text = (tmp_path / "train.json").read_text(encoding="utf-8")
        assert text.startswith('{\n "dataset"') and text.endswith("}\n")


class TestHypothesis:
    def test_a_refused_candidate_says_refused_and_names_every_reason(self) -> None:
        refusal = HypothesisRefused(("no confirmed label", "no independent evidence"))
        assert str(refusal) == "refused: no confirmed label; no independent evidence"

    def feature(self, artifact: str, *names: str) -> dict[str, Any]:
        return {
            "artifact_id": artifact,
            "features": [{"name": n, "value": "1", "slot": "c", "source": "content"} for n in names],
        }

    def test_two_sets_exactly_at_the_limit_join_and_a_hair_under_it_they_do_not(self) -> None:
        a, b = self.feature("a", "1", "2"), self.feature("b", "1")  # distance 0.5
        assert Distance.group([a, b], 0.5) == [["a", "b"]]
        assert Distance.group([a, b], 0.49) == [["a"], ["b"]]

    def test_every_pair_is_compared_not_only_neighbours(self) -> None:
        sets = [self.feature(name, "1") for name in "abcd"]
        assert Distance.group(sets, 0.0) == [["a", "b", "c", "d"]]


class TestProportions:
    def test_the_wilson_interval_matches_the_textbook_values(self) -> None:
        assert Proportions.wilson(0, 10) == pytest.approx((0.0, 0.27754), abs=1e-4)
        assert Proportions.wilson(5, 10) == pytest.approx((0.23659, 0.76341), abs=1e-4)
        assert Proportions.wilson(10, 10) == pytest.approx((0.72246, 1.0), abs=1e-4)
        assert Proportions.wilson(1, 1) == pytest.approx((0.20654, 1.0), abs=1e-4)

    def test_an_empty_sample_says_nothing(self) -> None:
        assert Proportions.wilson(0, 0) == (0.0, 1.0)

    def test_newcombes_interval_matches_the_published_example_56_of_70_against_48_of_80(self) -> None:
        delta, low, high = Proportions.difference(56, 70, 48, 80)
        assert (delta, low, high) == pytest.approx((0.2, 0.0524, 0.3339), abs=1e-3)

    def test_equal_proportions_give_a_symmetric_interval_about_zero(self) -> None:
        delta, low, high = Proportions.difference(0, 100, 0, 100)
        assert delta == 0 and low == pytest.approx(-0.03699, abs=1e-4) and high == pytest.approx(0.03699, abs=1e-4)

    def test_either_side_empty_gives_the_widest_interval_and_neither_does_not(self) -> None:
        assert Proportions.difference(0, 0, 5, 10) == (0.0, -1.0, 1.0)
        assert Proportions.difference(5, 10, 0, 0) == (0.0, -1.0, 1.0)
        assert Proportions.difference(1, 1, 5, 10) != (0.0, -1.0, 1.0)


class TestScorecardEdges:
    BASE = Baseline.freeze({"mal_blocked": 300, "mal_n": 400, "benign_blocked": 5, "benign_n": 5_000})

    def counts(self, **over: int) -> dict[str, int]:
        return {"mal_blocked": 360, "mal_n": 400, "benign_blocked": 5, "benign_n": 5_000, **over}

    def test_every_unit_blocked_and_none_blocked_are_both_valid_counts(self) -> None:
        assert Scorecard.of(self.BASE, self.counts(mal_blocked=400))["recall_candidate"] == 1.0
        assert Scorecard.of(self.BASE, self.counts(mal_blocked=0, benign_blocked=0))["recall_candidate"] == 0.0

    @pytest.mark.parametrize("over", [{"mal_blocked": -1}, {"mal_blocked": 401}, {"benign_blocked": 5_001}])
    def test_a_count_outside_its_total_is_refused(self, over: dict[str, int]) -> None:
        with pytest.raises(ValueError, match="is not within"):
            Scorecard.of(self.BASE, self.counts(**over))

    def test_the_baseline_digest_does_not_depend_on_the_order_the_counts_were_written_in(self) -> None:
        assert Baseline.digest({"a": 1, "b": 2}) == Baseline.digest({"b": 2, "a": 1})

    def test_a_set_exactly_at_the_minimum_is_not_too_small_and_one_under_is(self) -> None:
        assert Conclusion.too_small({"mal_n": 185, "benign_n": 3_000}) is False
        assert Conclusion.too_small({"mal_n": 184, "benign_n": 3_000}) is True
        assert Conclusion.too_small({"mal_n": 185, "benign_n": 2_999}) is True

    def test_no_areas_say_every_area_is_unavailable(self) -> None:
        assert "every area" in Conclusion.of({})["reasons"][0]


class TestFeedbackEdges:
    def test_the_log_folder_is_made_with_its_parents(self, tmp_path: Path) -> None:
        folder = tmp_path / "a" / "b"
        Feedback.add(folder, "miss", "d1")
        assert Feedback.path(folder).exists()

    def test_the_detail_given_is_the_detail_kept(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "false_positive", "d1", {"rule": "R.1"})
        assert Feedback.records(tmp_path)[0]["detail"] == {"rule": "R.1"}
        Feedback.add(tmp_path, "miss", "d2")
        assert Feedback.records(tmp_path)[1]["detail"] == {}

    def test_a_correction_may_name_the_last_record_and_not_the_next_one(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "miss", "d1")
        Feedback.add(tmp_path, "miss", "d2")
        assert Feedback.add(tmp_path, "miss", "d3", corrects=1) == 2
        with pytest.raises(ValueError, match="no record 3"):
            Feedback.add(tmp_path, "miss", "d4", corrects=3)

    def test_each_record_is_written_with_its_keys_in_order(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "miss", "d1", {"z": 1, "a": 2})
        line = Feedback.path(tmp_path).read_text(encoding="utf-8").splitlines()[0]
        assert line.index('"artifact_digest"') < line.index('"detail"') < line.index('"id"') < line.index('"kind"')
        assert line.index('"a"') < line.index('"z"')


class TestGraphEdges:
    def test_a_node_whose_id_holds_colons_keeps_its_kind(self) -> None:
        g = ThreatGraph()
        g.add("a", "fragment:x:y:z")
        g.add("b", "fragment:x:y:z")
        assert g.weight("fragment:x:y:z") == 0.4 and g.score("a", "b") == pytest.approx(0.4)

    def test_a_node_at_half_the_common_line_is_worth_half(self) -> None:
        g = ThreatGraph({"file:f": COMMON_AT / 2})
        assert g.weight("file:f") == pytest.approx(0.3)

    def test_a_node_with_no_kind_before_its_colon_is_refused(self) -> None:
        with pytest.raises(ValueError):
            ThreatGraph().add("a", ":id")
