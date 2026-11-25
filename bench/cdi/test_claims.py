"""An ecosystem is claimed only on a held-out split that is large and diverse enough, and a refusal names the minimum."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from bench.cdi.claims import ClaimRefused, Claims
from bench.cdi.gate import Gate

MANY = [f"fam{i % 12}" for i in range(240)]  # 12 families of 20, none above 20%


class TestTheSizes:
    def test_a_malware_split_below_185_is_refused_with_the_minimum_named(self) -> None:
        assert Claims.sizes(184, 5_000) == ("malware held-out 184 is below the minimum 185",)

    def test_185_malware_is_enough(self) -> None:
        assert Claims.sizes(185, 3_000) == ()

    def test_a_legitimate_split_below_3000_is_refused_with_the_minimum_named(self) -> None:
        assert Claims.sizes(300, 2_999) == ("legitimate held-out 2999 is below the minimum 3000",)

    def test_both_short_names_both(self) -> None:
        assert len(Claims.sizes(10, 10)) == 2

    def test_the_plan_size_is_reported_apart_and_never_refuses(self) -> None:
        assert Claims.short_of_plan(300, 5_000) == (
            "malware held-out 300 is short of the plan 500",
            "legitimate held-out 5000 is short of the plan 15000",
        )

    def test_a_catalogue_under_100000_is_the_plan_for_legitimate_units(self) -> None:
        assert Claims.short_of_plan(500, 20_000, catalogue=40_000) == (
            "legitimate held-out 20000 is short of the plan 40000",
        )

    def test_a_big_catalogue_falls_back_to_15000(self) -> None:
        assert Claims.short_of_plan(500, 15_000, catalogue=250_000) == ()


class TestTheDiversity:
    def test_a_split_of_one_campaign_fails_each_rule_it_breaks(self) -> None:
        reasons = Claims.diversity(["github-actions"] * 237, 300)
        assert len(reasons) == 2
        assert "1 distinct campaigns or families, the minimum is 10" in reasons[0]
        assert "237 of 237" in reasons[1]

    def test_a_family_above_20_percent_fails_though_there_are_ten(self) -> None:
        held = ["big"] * 21 + [f"f{i}" for i in range(9)] * 8  # 21 of 93 is 22.6%
        reasons = Claims.diversity(held, 1_000)
        assert len(reasons) == 1 and "most allowed is 20%" in reasons[0]

    def test_exactly_20_percent_passes(self) -> None:
        held = ["a"] * 20 + [f"f{i}" for i in range(10)] * 8  # 20 of 100
        assert Claims.diversity(held, 100) == ()

    def test_fewer_than_ten_families_fails_though_none_is_large(self) -> None:
        held = [f"f{i % 9}" for i in range(90)]
        assert Claims.diversity(held, 100) == (
            "9 distinct campaigns or families, the minimum is 10",
        )

    def test_a_development_split_smaller_than_the_held_out_one_fails(self) -> None:
        reasons = Claims.diversity(MANY, 239)
        assert reasons == ("the development split (239) is smaller than the held-out one (240)",)

    def test_a_development_split_as_large_passes(self) -> None:
        assert Claims.diversity(MANY, 240) == ()

    def test_exactly_ten_families_pass(self) -> None:
        assert Claims.diversity([f"f{i % 10}" for i in range(100)], 100) == ()


class TestRequire:
    def test_a_refusal_carries_every_reason(self) -> None:
        with pytest.raises(ClaimRefused) as caught:
            Claims.require(["one"] * 50, 10, 100)
        assert len(caught.value.reasons) == 5

    def test_a_good_split_returns_what_is_short_of_the_plan(self) -> None:
        assert Claims.require(MANY, 300, 5_000) == {
            "short_of_plan": (
                "malware held-out 240 is short of the plan 500",
                "legitimate held-out 5000 is short of the plan 15000",
            )
        }


class TestTheGate:
    def spec(self, tmp_path: Path, claim: dict[str, Any]) -> dict[str, Any]:
        rows = tmp_path / "scans"
        rows.write_text(
            '{"file": "m1", "exit": 1, "findings": [], "seconds": 1}\n', encoding="utf-8"
        )
        return {
            "candidate_id": "c",
            "sets": [
                {"name": "m", "kind": "malware", "area": "x", "off": str(rows), "on": str(rows)}
            ],
            "claim": claim,
        }

    def test_a_split_failing_a_rule_rejects_with_the_minimum_in_the_reason(
        self, tmp_path: Path
    ) -> None:
        claim = {"held_families": ["gha"] * 237, "dev_malware_n": 300, "legit_n": 5_000}
        _, decision = Gate.evaluate(self.spec(tmp_path, claim))
        assert decision["gates"]["claim"]["result"] == "fail"
        assert "the minimum is 10" in decision["gates"]["claim"]["reason"]
        assert decision["outcome"] == "reject"

    def test_a_good_split_passes_and_says_what_is_short_of_the_plan(self, tmp_path: Path) -> None:
        claim = {"held_families": MANY, "dev_malware_n": 300, "legit_n": 5_000}
        _, decision = Gate.evaluate(self.spec(tmp_path, claim))
        assert decision["gates"]["claim"]["result"] == "pass"
        assert "short of the plan" in decision["gates"]["claim"]["reason"]

    def test_no_claim_adds_no_gate(self, tmp_path: Path) -> None:
        spec = self.spec(tmp_path, {})
        del spec["claim"]
        _, decision = Gate.evaluate(spec)
        assert "claim" not in decision["gates"]
