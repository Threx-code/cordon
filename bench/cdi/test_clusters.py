"""A cluster from families and edges, weighted; a shared fragment raises priority and never carries a label."""

from __future__ import annotations

from typing import ClassVar

import pytest
from bench.cdi.clusters import EDGE_WEIGHTS, ClusterBuilder
from bench.cdi.records import LABEL_STATES, Records


class Kit:
    @staticmethod
    def link(a: str, b: str, kind: str) -> dict[str, str]:
        return {"a": a, "b": b, "type": kind}

    @staticmethod
    def edges(cluster: dict) -> set[tuple[str, str, str, float]]:
        return {(e["a"], e["b"], e["kind"], e["weight"]) for e in cluster["record"]["edges"]}


class TestAClusterFromRelatedReleases:
    """A fixture of related releases yields one cluster with the right edge types and weights."""

    def build(self) -> list[dict]:
        return ClusterBuilder.build(
            families={"f1": ["r1", "r2", "r3"]},
            links=[
                Kit.link("r3", "r4", "campaign_sibling"),
                Kit.link("r4", "r5", "shared_fragment"),
                Kit.link("r5", "r6", "infra"),
                Kit.link("r6", "r7", "name"),
                Kit.link("x1", "x2", "name"),
            ],
        )

    def test_the_related_releases_are_one_cluster_and_the_unrelated_pair_is_another(self) -> None:
        built = self.build()
        assert sorted(len(c["record"]["members"]) for c in built) == [2, 7]

    def test_each_edge_has_its_type_and_the_weight_of_what_it_is_evidence_of(self) -> None:
        big = max(self.build(), key=lambda c: len(c["record"]["members"]))
        assert Kit.edges(big) == {
            ("r1", "r2", "same_family", 0.8),
            ("r1", "r3", "same_family", 0.8),
            ("r3", "r4", "campaign_sibling", 1.0),
            ("r4", "r5", "shared_fragment", 0.4),
            ("r5", "r6", "infra", 1.0),
            ("r6", "r7", "name", 0.2),
        }

    def test_the_five_types_and_their_weights_order_infra_and_campaign_over_family_over_fragment_over_name(
        self,
    ) -> None:
        w = EDGE_WEIGHTS
        assert set(w) == {"infra", "campaign_sibling", "same_family", "shared_fragment", "name"}
        assert (
            w["infra"]
            == w["campaign_sibling"]
            > w["same_family"]
            > w["shared_fragment"]
            > w["name"]
            > 0
        )

    def test_priority_adds_the_strongest_edge_of_each_type_so_many_fragments_are_one_vote(
        self,
    ) -> None:
        one = ClusterBuilder.build({}, [Kit.link("a", "b", "shared_fragment")])
        many = ClusterBuilder.build(
            {},
            [
                Kit.link("a", "b", "shared_fragment"),
                Kit.link("b", "c", "shared_fragment"),
                Kit.link("c", "d", "shared_fragment"),
            ],
        )
        assert one[0]["priority"] == many[0]["priority"] == 0.4

    def test_the_most_urgent_cluster_comes_first_and_the_same_input_gives_the_same_records(
        self,
    ) -> None:
        built = self.build()
        assert built[0]["priority"] > built[1]["priority"]
        assert built == self.build()

    def test_an_edge_type_nobody_defined_is_refused(self) -> None:
        with pytest.raises(ValueError, match="edge type"):
            ClusterBuilder.build({}, [Kit.link("a", "b", "vibes")])


class TestSharedCodeRaisesPriorityAndNeverLabels:
    """A cluster whose only link is shared code has a raised priority and a null label; independent evidence gives a state."""

    SHARED: ClassVar[list[dict[str, str]]] = [Kit.link("a", "b", "shared_fragment")]

    def test_a_cluster_joined_only_by_shared_code_has_a_priority_and_no_label(self) -> None:
        (cluster,) = ClusterBuilder.build({}, self.SHARED)
        assert (
            cluster["priority"] == EDGE_WEIGHTS["shared_fragment"]
            and cluster["record"]["label"] is None
        )

    def test_a_shared_fragment_added_to_a_cluster_raises_its_priority_and_changes_no_label(
        self,
    ) -> None:
        base = [Kit.link("a", "b", "name")]
        (before,) = ClusterBuilder.build({}, base)
        (after,) = ClusterBuilder.build({}, [*base, Kit.link("b", "c", "shared_fragment")])
        assert after["priority"] > before["priority"]
        assert before["record"]["label"] is None and after["record"]["label"] is None

    def test_a_member_that_is_labelled_malicious_by_a_weak_source_is_still_no_label(self) -> None:
        evidence = {"a": {"state": "confirmed_malicious", "tier": "silver"}}
        (cluster,) = ClusterBuilder.build({}, self.SHARED, evidence)
        assert cluster["record"]["label"] is None

    @pytest.mark.parametrize("state", LABEL_STATES)
    def test_independent_evidence_gives_a_state_from_the_six(self, state: str) -> None:
        evidence = {"a": {"state": state, "tier": "confirmed"}}
        (cluster,) = ClusterBuilder.build({}, self.SHARED, evidence)
        assert cluster["record"]["label"] == state

    def test_corroborated_evidence_counts_too(self) -> None:
        evidence = {"b": {"state": "confirmed_malicious", "tier": "corroborated"}}
        assert (
            ClusterBuilder.build({}, self.SHARED, evidence)[0]["record"]["label"]
            == "confirmed_malicious"
        )

    def test_malicious_and_benign_evidence_in_one_cluster_is_disputed_and_other_mixes_stay_null(
        self,
    ) -> None:
        mixed = {
            "a": {"state": "confirmed_malicious", "tier": "confirmed"},
            "b": {"state": "confirmed_benign", "tier": "confirmed"},
        }
        assert ClusterBuilder.build({}, self.SHARED, mixed)[0]["record"]["label"] == "disputed"
        odd = {
            "a": {"state": "suspicious", "tier": "confirmed"},
            "b": {"state": "unreviewed", "tier": "confirmed"},
        }
        assert ClusterBuilder.build({}, self.SHARED, odd)[0]["record"]["label"] is None

    def test_a_word_that_is_not_one_of_the_six_is_refused_wherever_it_comes_from(self) -> None:
        with pytest.raises(ValueError):
            ClusterBuilder.build(
                {}, self.SHARED, {"a": {"state": "probably_bad", "tier": "confirmed"}}
            )
        with pytest.raises(ValueError):
            Records.threat_cluster(
                members=["a", "b"], edges=[], method="m", method_version="1", label="probably_bad"
            )

    def test_the_six_states_are_exactly_the_label_stores(self) -> None:
        assert LABEL_STATES == (
            "unreviewed",
            "suspicious",
            "confirmed_malicious",
            "confirmed_benign",
            "disputed",
            "insufficient_evidence",
        )
