"""The miss analysis job: one DetectionMiss per confirmed false negative, and a regression test kept for each.

The census prints tables for people. This turns the confirmed misses of a census into the records the learning loop reads, and keeps
the loop honest about each one:

    confirmed         only a miss whose label is confirmed or corroborated becomes a record; any other is left out and counted
    regression test   a record is made only when a regression test for that miss is named; a miss with none is refused
    failing then      the test must FAIL on the build that missed (the fixture is still not blocked) and PASS on the build that
    passing           fixes it (the fixture is blocked); a test that already passes on the old build reproduces nothing, and one
                      that still fails on the fix has not fixed the miss

A record carries the reproduction, what ran, what was absent and what is needed, never the unit's content: `fixture` names a small
synthetic file made to show the same behaviour. Nothing here reads a package."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any, Final

from .miss import Miss

CONFIRMED_LABELS: Final = frozenset({"confirmed", "corroborated"})


class NoRegressionTest(ValueError):
    """A confirmed miss has no regression test named: it is refused, never recorded without one."""


class NotAReproduction(ValueError):
    """The regression test already passes on the build that missed, so it shows nothing."""


class MissAnalysis:
    @classmethod
    def emit(cls, confirmed: Iterable[Mapping[str, Any]], tests: Mapping[str, str]) -> dict[str, Any]:
        """The DetectionMiss records for the confirmed misses of a census.

        Each item has the keys of `Miss.detection_miss` (without `regression_test_ref`) and a `label_state`. `tests` maps a
        miss id to the regression test that keeps it from coming back. Raises `NoRegressionTest` naming the first miss that has
        none. Returns the records and how many items were left out for an unconfirmed label."""
        records: list[dict[str, Any]] = []
        left_out = 0
        for item in confirmed:
            if item.get("label_state") not in CONFIRMED_LABELS:
                left_out += 1
                continue
            miss_id = str(item["miss_id"])
            if not tests.get(miss_id):
                raise NoRegressionTest(f"miss {miss_id} has no regression test: a miss is not recorded without one")
            fields = {k: v for k, v in item.items() if k != "label_state"}
            records.append(Miss.detection_miss(**fields, regression_test_ref=tests[miss_id]))
        return {"records": records, "left_out": left_out}

    @staticmethod
    def regression(fixture: Any, missed_by: Callable[[Any], bool], fixed_by: Callable[[Any], bool]) -> dict[str, Any]:
        """Runs one regression test: `missed_by(fixture)` and `fixed_by(fixture)` say whether each build blocks the fixture.

        Returns `failing_then_passing` when the old build does not block and the fixed build does. Raises `NotAReproduction`
        when the old build already blocks it. Returns `still_failing` when the fixed build does not block it either."""
        if missed_by(fixture):
            raise NotAReproduction("the test passes on the build that missed: it reproduces nothing")
        return {"status": "failing_then_passing" if fixed_by(fixture) else "still_failing"}
