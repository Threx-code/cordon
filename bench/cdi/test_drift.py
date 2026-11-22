"""The drift watch: the share near the decision line, per area and window."""

from __future__ import annotations

import pytest
from bench.cdi.drift import DriftRefused, DriftSeries


def scores(near: int, far: int, line: float = 0.9) -> list[float]:
    return [line + 0.01] * near + [0.1] * far


def series() -> DriftSeries:
    s = DriftSeries(line=0.9, margin=0.05)
    s.accept("npm", scores(20, 980))
    s.accept("pypi", scores(10, 990))
    return s


class TestTheSeriesExistsPerArea:
    def test_each_window_gives_one_point_for_each_area(self) -> None:
        s = series()
        added = s.add("w1", {"npm": scores(20, 980), "pypi": scores(10, 990)})
        assert [(p["area"], p["near"], p["scored"]) for p in added] == [("npm", 20, 1000), ("pypi", 10, 1000)]
        s.add("w2", {"npm": scores(22, 978), "pypi": scores(11, 989)})
        assert [len(s.points[a]) for a in ("npm", "pypi")] == [2, 2]

    def test_a_steady_area_is_ok(self) -> None:
        s = series()
        assert s.add("w1", {"npm": scores(21, 979)})[0]["state"] == "ok"

    def test_an_area_with_far_more_near_the_line_is_drift_and_listed(self) -> None:
        s = series()
        s.add("w1", {"npm": scores(20, 980), "pypi": scores(120, 880)})
        assert s.drifting() == ["pypi"]

    def test_a_thin_window_is_unmeasured_not_ok(self) -> None:
        assert series().add("w1", {"npm": scores(5, 50)})[0]["state"] == "unmeasured"

    def test_an_area_with_no_accepted_share_is_unmeasured(self) -> None:
        assert series().add("w1", {"cargo": scores(20, 980)})[0]["state"] == "unmeasured"

    def test_a_point_carries_counts_and_an_interval_never_a_package(self) -> None:
        point = series().add("w1", {"npm": scores(20, 980)})[0]
        assert set(point) == {"window", "area", "near", "scored", "share", "low", "high", "accepted_share", "state"}
        assert point["low"] < point["share"] < point["high"]


class TestWhatIsRefused:
    def test_a_window_not_after_the_last_is_refused(self) -> None:
        s = series()
        s.add("w2", {"npm": scores(20, 980)})
        with pytest.raises(DriftRefused, match="after the last"):
            s.add("w2", {"npm": scores(20, 980)})

    def test_a_score_outside_zero_to_one_is_refused(self) -> None:
        with pytest.raises(DriftRefused, match="between 0 and 1"):
            series().add("w1", {"npm": [1.5]})

    def test_acceptance_on_too_few_packages_is_refused(self) -> None:
        with pytest.raises(DriftRefused, match="fewer than 200"):
            DriftSeries(0.9).accept("npm", scores(1, 10))

    def test_a_margin_outside_zero_to_one_is_refused(self) -> None:
        with pytest.raises(DriftRefused):
            DriftSeries(0.9, margin=0)
