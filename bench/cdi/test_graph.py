"""SI-C1: the threat graph is built from the label store's facts, and shared common code adds no implication."""

from __future__ import annotations

import pytest
from bench.cdi.graph import COMMON_AT, ThreatGraph


class Kit:
    @staticmethod
    def graph(share: dict[str, float] | None = None) -> ThreatGraph:
        return ThreatGraph(share)


class TestCommonCodeNeverImplicatesAlone:
    def test_a_fragment_every_benign_package_has_implicates_nobody(self) -> None:
        g = Kit.graph({"fragment:license-header": 0.40})
        g.add("a", "fragment:license-header")
        g.add("b", "fragment:license-header")
        assert g.implicated("a") == {} and g.score("a", "b") == 0.0

    def test_a_file_at_the_common_line_counts_for_nothing(self) -> None:
        g = Kit.graph({"file:setup.py": COMMON_AT})
        g.add("a", "file:setup.py")
        g.add("b", "file:setup.py")
        assert g.weight("file:setup.py") == 0.0 and g.implicated("a") == {}

    def test_common_code_plus_a_weak_link_still_does_not_reach_the_threshold(self) -> None:
        g = Kit.graph({"fragment:boiler": 0.5})
        for node in ("fragment:boiler", "release:pkg-1.1"):
            g.add("a", node)
            g.add("b", node)
        assert g.implicated("a") == {}

    def test_rare_code_alone_is_below_the_threshold_too(self) -> None:
        g = Kit.graph({"fragment:rare": 0.0, "file:rare.js": 0.0})
        for node in ("fragment:rare", "file:rare.js"):
            g.add("a", node)
            g.add("b", node)
        # 0.4 + 0.6 = 1.0: two kinds of evidence together reach it
        assert g.implicated("a") == {"b": pytest.approx(1.0)}

    def test_a_single_rare_fragment_is_not_enough(self) -> None:
        g = Kit.graph({"fragment:rare": 0.0})
        g.add("a", "fragment:rare")
        g.add("b", "fragment:rare")
        assert g.implicated("a") == {}


class TestStrongEvidenceImplicates:
    def test_a_shared_infrastructure_indicator_implicates_alone(self) -> None:
        g = Kit.graph()
        g.add("a", "infra:evil.example")
        g.add("b", "infra:evil.example")
        assert g.implicated("a") == {"b": 1.0}

    def test_a_shared_campaign_implicates_alone(self) -> None:
        g = Kit.graph()
        g.add("a", "campaign:c1")
        g.add("b", "campaign:c1")
        assert g.implicated("b") == {"a": 1.0}

    def test_a_hundred_shared_fragments_are_one_vote_not_a_hundred(self) -> None:
        g = Kit.graph()
        for i in range(100):
            g.add("a", f"fragment:f{i}")
            g.add("b", f"fragment:f{i}")
        assert g.score("a", "b") == pytest.approx(0.4) and g.implicated("a") == {}

    def test_a_less_common_node_is_worth_less(self) -> None:
        g = Kit.graph({"fragment:f": 0.025})
        assert g.weight("fragment:f") == pytest.approx(0.2)

    def test_common_code_next_to_a_real_link_does_not_add_to_it(self) -> None:
        g = Kit.graph({"fragment:boiler": 0.9})
        for node in ("fragment:boiler", "infra:c2"):
            g.add("a", node)
            g.add("b", node)
        assert g.evidence("a", "b") == {"infra": 1.0}

    def test_an_unrelated_artefact_is_not_implicated(self) -> None:
        g = Kit.graph()
        g.add("a", "infra:x")
        g.add("c", "infra:y")
        assert g.implicated("a") == {}

    def test_the_seed_never_implicates_itself(self) -> None:
        g = Kit.graph()
        g.add("a", "campaign:c")
        assert g.implicated("a") == {}

    def test_the_graph_is_symmetric(self) -> None:
        g = Kit.graph()
        g.add("a", "campaign:c")
        g.add("b", "campaign:c")
        assert g.score("a", "b") == g.score("b", "a")


class TestTheNodes:
    @pytest.mark.parametrize("bad", ["nokind", "host:evil", ":x"])
    def test_a_node_of_no_known_kind_is_refused(self, bad: str) -> None:
        with pytest.raises(ValueError, match="not one of"):
            Kit.graph().add("a", bad)

    def test_the_release_link_is_weak(self) -> None:
        g = Kit.graph()
        g.add("a", "release:pkg")
        g.add("b", "release:pkg")
        assert g.score("a", "b") == 0.2 and g.implicated("a") == {}
