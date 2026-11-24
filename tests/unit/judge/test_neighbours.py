"""The five nearest malicious and five nearest benign releases are picked by cosine, the same way every time."""

from __future__ import annotations

import pytest

from cordon_scanner.judge.neighbours import LabelledVector, NeighbourSearch


class Fixture:
    @staticmethod
    def corpus() -> list[LabelledVector]:
        malicious = [LabelledVector(f"m{i}", "malicious", (1.0, float(i), 0.0)) for i in range(8)]
        benign = [LabelledVector(f"b{i}", "benign", (0.0, 1.0, float(i))) for i in range(8)]
        return [*malicious, *benign, LabelledVector("zero", "benign", (0.0, 0.0, 0.0))]


class TestCosine:
    def test_the_same_direction_is_one_and_orthogonal_is_zero(self) -> None:
        assert NeighbourSearch.cosine((1.0, 2.0), (2.0, 4.0)) == pytest.approx(1.0)
        assert NeighbourSearch.cosine((1.0, 0.0), (0.0, 1.0)) == 0.0

    def test_a_zero_vector_and_a_size_mismatch_are_never_near(self) -> None:
        assert NeighbourSearch.cosine((0.0, 0.0), (1.0, 1.0)) == 0.0
        assert NeighbourSearch.cosine((1.0,), (1.0, 1.0)) == 0.0


class TestNearest:
    def test_five_of_each_label_nearest_first(self) -> None:
        found = NeighbourSearch.nearest((1.0, 0.0, 0.0), Fixture.corpus())
        assert [i.release for i in found if i.label == "malicious"] == [
            "m0",
            "m1",
            "m2",
            "m3",
            "m4",
        ]
        assert sum(i.label == "benign" for i in found) <= 5

    def test_fewer_than_five_gives_what_there_is(self) -> None:
        found = NeighbourSearch.nearest((1.0, 0.0, 0.0), Fixture.corpus()[:2])
        assert [i.release for i in found] == ["m0", "m1"]

    def test_the_answer_does_not_depend_on_the_order_given(self) -> None:
        rows = Fixture.corpus()
        first = NeighbourSearch.nearest((1.0, 1.0, 0.0), rows)
        assert NeighbourSearch.nearest((1.0, 1.0, 0.0), list(reversed(rows))) == first

    def test_the_bundle_gets_labels_and_ids_only(self) -> None:
        shown = NeighbourSearch.for_bundle((1.0, 0.0, 0.0), Fixture.corpus())
        assert shown[0].label == "malicious" and shown[0].summary == "m0"
