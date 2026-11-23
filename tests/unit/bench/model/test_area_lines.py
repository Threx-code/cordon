"""An area's line holds the share of legitimate packages it blocks to the budget at the upper end of the 95% interval, and the model records the bound."""

from __future__ import annotations

from bench.model.area_lines import AreaLines


class Fixtures:
    @staticmethod
    def scores(n: int, high: int) -> list[float]:
        """`n` legitimate scores of which the top `high` are 0.9 and the rest spread under 0.3."""
        return [0.9] * high + [round(0.3 * i / n, 4) for i in range(n - high)]


class TestTheLowestLineWithinTheBudget:
    def test_the_line_is_the_lowest_one_whose_upper_bound_holds(self) -> None:
        scores = [i / 10000 for i in range(4000)]
        line = AreaLines.lowest(scores)
        assert AreaLines.upper(scores, line)[1] <= AreaLines.BUDGET
        below = max(s for s in scores if s < line)
        assert AreaLines.upper(scores, below)[1] > AreaLines.BUDGET

    def test_the_bound_is_held_where_the_point_estimate_would_pass(self) -> None:
        scores = Fixtures.scores(1000, 3)
        blocked, upper = AreaLines.upper(scores, 0.5)
        assert blocked == 3 and 3 / 1000 < AreaLines.BUDGET < upper

    def test_a_set_too_small_to_hold_any_block_gets_a_line_that_blocks_nothing(self) -> None:
        assert AreaLines.lowest([0.2] * 50) == AreaLines.NEVER


class TestEnforcement:
    def test_a_line_that_breaks_the_budget_is_raised_and_one_that_holds_is_kept(self) -> None:
        legit = {"npm": Fixtures.scores(4000, 2), "pypi": Fixtures.scores(4000, 60)}
        lines, record = AreaLines.enforce({"npm": 0.5, "pypi": 0.5}, legit)
        assert lines["npm"] == 0.5 and lines["pypi"] > 0.5
        assert all(
            r["upper"] <= AreaLines.BUDGET or r["line"] == AreaLines.NEVER for r in record.values()
        )

    def test_the_record_has_the_line_the_counts_and_the_upper_bound_per_area(self) -> None:
        _, record = AreaLines.enforce({"npm": 0.5}, {"npm": Fixtures.scores(4000, 2)})
        assert set(record["npm"]) == {"line", "legit_blocked", "legit_n", "upper", "budget"}
        assert record["npm"]["legit_blocked"] == 2 and record["npm"]["legit_n"] == 4000

    def test_an_area_with_no_legitimate_scores_keeps_its_line_and_says_the_bound_is_one(
        self,
    ) -> None:
        lines, record = AreaLines.enforce({"mcp": 0.4}, {})
        assert (
            lines["mcp"] == 0.4 and record["mcp"]["upper"] == 1.0 and record["mcp"]["legit_n"] == 0
        )
