"""SI-Q5 and SI-Q6: discovery yields a hypothesis, and compares a cluster with its nearest benign by FeatureSet distance."""

from __future__ import annotations

from typing import Any

import pytest

from bench.cdi.hypothesis import Distance, Hypotheses, HypothesisRefused


def hypothesis(**over: Any) -> dict[str, Any]:
    parts: dict[str, Any] = {
        "hypothesis_id": "h1",
        "statement": "units reading ~/.ssh and posting off-host",
        "supporting_samples": ["a", "b"],
        "counterexamples": ["none found"],
        "expected_coverage": "2 of 40 unlabelled units",
        "limits": "regex over fenced directives",
        "validation_plan": "label 10, rescan",
    }
    return Hypotheses.build(**{**parts, **over})


def featureset(artifact: str, *content: tuple[str, str, str], intel: bool = False) -> dict[str, Any]:
    features = [{"name": n, "value": v, "slot": s, "source": "content"} for n, v, s in content]
    if intel:
        features.append({"name": "finding:INTEL.X", "value": True, "slot": "none", "source": "intel"})
    return {"artifact_id": artifact, "features": features}


class TestAHypothesisIsNotALabel:
    def test_it_carries_every_part_and_no_label(self) -> None:
        h = hypothesis()
        assert h["kind"] == "hypothesis" and h["label"] is None
        assert h["counterexamples"] == ["none found"] and h["validation_plan"]

    @pytest.mark.parametrize(
        "part", ["statement", "supporting_samples", "counterexamples", "expected_coverage", "limits", "validation_plan"]
    )
    def test_a_missing_part_is_refused_by_name(self, part: str) -> None:
        empty: Any = [] if part in ("supporting_samples", "counterexamples") else ""
        with pytest.raises(ValueError, match=part):
            hypothesis(**{part: empty})

    def test_a_novel_unlabelled_cluster_produces_a_hypothesis_and_no_candidate(self) -> None:
        h = hypothesis()
        with pytest.raises(HypothesisRefused) as caught:
            Hypotheses.require_candidate(h, None, [])
        assert caught.value.reasons == ("no confirmed label", "no independent evidence")

    def test_a_confirmed_label_without_independent_evidence_is_not_enough(self) -> None:
        assert Hypotheses.candidate_blockers(hypothesis(), "confirmed", []) == ("no independent evidence",)

    def test_independent_evidence_without_a_confirmed_label_is_not_enough(self) -> None:
        assert Hypotheses.candidate_blockers(hypothesis(), "silver", ["advisory:1"]) == (
            "label tier silver is not confirmed or corroborated",
        )

    @pytest.mark.parametrize("tier", ["confirmed", "corroborated"])
    def test_both_together_allow_a_candidate(self, tier: str) -> None:
        Hypotheses.require_candidate(hypothesis(), tier, ["advisory:1"])

    def test_a_record_that_is_not_a_hypothesis_is_refused(self) -> None:
        assert "not a hypothesis record" in Hypotheses.candidate_blockers({"kind": "label"}, "confirmed", ["x"])


class TestTheNearestBenign:
    MAL = featureset("mal", ("a", "1", "code"), ("b", "1", "code"), ("c", "1", "code"))

    def test_a_fixture_pair_returns_the_nearest_benign_and_the_differing_features(self) -> None:
        near = featureset("near", ("a", "1", "code"), ("b", "1", "code"), ("d", "1", "text"))
        far = featureset("far", ("z", "1", "code"))
        found = Distance.nearest_benign(self.MAL, [far, near])
        assert found == {
            "artifact_id": "near",
            "distance": 0.5,
            "only_malicious": [("c", "1", "code")],
            "only_benign": [("d", "1", "text")],
        }

    def test_the_same_content_is_distance_zero_and_nothing_differs(self) -> None:
        twin = featureset("twin", ("a", "1", "code"), ("b", "1", "code"), ("c", "1", "code"))
        found = Distance.nearest_benign(self.MAL, [twin])
        assert found is not None and found["distance"] == 0.0 and found["only_malicious"] == []

    def test_no_shared_content_is_distance_one(self) -> None:
        assert Distance.between(self.MAL, featureset("o", ("q", "1", "code"))) == 1.0

    def test_intel_features_do_not_count(self) -> None:
        with_intel = featureset("i", ("a", "1", "code"), intel=True)
        without = featureset("j", ("a", "1", "code"))
        assert Distance.between(with_intel, without) == 0.0

    def test_a_tie_goes_to_the_smaller_artifact_id(self) -> None:
        a, b = featureset("b-id", ("a", "1", "code")), featureset("a-id", ("a", "1", "code"))
        assert Distance.nearest_benign(self.MAL, [a, b])["artifact_id"] == "a-id"  # type: ignore[index]

    def test_no_benign_set_gives_none(self) -> None:
        assert Distance.nearest_benign(self.MAL, []) is None

    def test_two_empty_sets_are_the_same_content(self) -> None:
        assert Distance.between(featureset("x"), featureset("y")) == 0.0


class TestClustersWithinACategory:
    def test_close_sets_join_directly_or_through_a_neighbour(self) -> None:
        a = featureset("a", ("1", "1", "c"), ("2", "1", "c"), ("3", "1", "c"), ("4", "1", "c"))
        b = featureset("b", ("1", "1", "c"), ("2", "1", "c"), ("3", "1", "c"), ("5", "1", "c"))
        c = featureset("c", ("2", "1", "c"), ("3", "1", "c"), ("5", "1", "c"), ("6", "1", "c"))
        far = featureset("far", ("x", "1", "c"))
        assert Distance.group([far, c, b, a], 0.7) == [["a", "b", "c"], ["far"]]

    def test_a_tighter_limit_splits_them(self) -> None:
        a = featureset("a", ("1", "1", "c"), ("2", "1", "c"))
        b = featureset("b", ("1", "1", "c"), ("3", "1", "c"))
        assert Distance.group([a, b], 0.5) == [["a"], ["b"]]
        assert Distance.group([a, b], 0.67) == [["a", "b"]]

    def test_no_sets_no_clusters(self) -> None:
        assert Distance.group([], 0.5) == []
