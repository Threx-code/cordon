"""SI-K3: schema tests, and one record of each of ThreatCluster, DetectionBundle and DeploymentObservation built from a threat graph and a promotion."""

from __future__ import annotations

from typing import Any

import pytest

from bench.cdi.graph import ThreatGraph
from bench.cdi.records import COUNTERS, Records
from bench.cdi.schemas import REQUIRED, SCHEMA_VERSIONS, Schemas

COUNTS = {"scans_seen": 1000, "would_change": 12, "fires": 5, "confirmed_fires": 4, "crashes": 0, "timeouts": 1}
ARTEFACTS = [{"path": "rulepack.yaml", "sha256": "aa"}, {"path": "decision.json", "sha256": "bb"}]


class Kit:
    @staticmethod
    def bundle(**over: Any) -> dict[str, Any]:
        parts: dict[str, Any] = {
            "candidate_id": "rulepack:cdi.t@1.0.0",
            "artefacts": ARTEFACTS,
            "decision_digest": "sha256:dd",
            "compatibility": {"min_scanner_version": "0.8.0"},
            "channel": "shadow",
        }
        return Records.detection_bundle(**{**parts, **over})


class TestTheSchemas:
    @pytest.mark.parametrize("kind", ["ThreatCluster", "DetectionBundle", "DeploymentObservation"])
    def test_each_record_has_a_version_and_required_keys(self, kind: str) -> None:
        assert SCHEMA_VERSIONS[kind] == "1.0.0" and "schema_version" in REQUIRED[kind]

    @pytest.mark.parametrize("kind", ["DetectionBundle", "DeploymentObservation"])
    def test_a_record_missing_a_key_is_refused(self, kind: str) -> None:
        record = Kit.bundle() if kind == "DetectionBundle" else Records.deployment_observation(bundle_id="b", channel="stable", window="w", counts=COUNTS)
        del record["channel"]
        with pytest.raises(ValueError, match="missing keys"):
            Schemas.validate(kind, record)


class TestThreatCluster:
    def from_graph(self) -> dict[str, Any]:
        g = ThreatGraph()
        for a in ("b", "a", "c"):
            g.add(a, "campaign:c1")
        members = ["c", "a", "b"]
        edges = [{"a": "a", "b": "b", "kind": "campaign", "weight": 1.0}, {"a": "a", "b": "c", "kind": "campaign", "weight": 1.0}]
        assert set(g.implicated("a")) == {"b", "c"}
        return Records.threat_cluster(members=members, edges=edges, method="graph", method_version="1", label="confirmed")

    def test_a_cluster_from_a_graph_is_valid_and_sorted(self) -> None:
        c = self.from_graph()
        assert c["members"] == ["a", "b", "c"] and c["label"] == "confirmed"

    def test_the_same_group_has_the_same_id_in_any_order(self) -> None:
        a = Records.threat_cluster(members=["x", "y"], edges=[], method="m", method_version="1", label=None)
        b = Records.threat_cluster(members=["y", "x"], edges=[], method="m", method_version="1", label=None)
        assert a == b

    def test_another_group_has_another_id(self) -> None:
        a = Records.threat_cluster(members=["x", "y"], edges=[], method="m", method_version="1", label=None)
        b = Records.threat_cluster(members=["x", "z"], edges=[], method="m", method_version="1", label=None)
        assert a["cluster_id"] != b["cluster_id"]

    def test_one_member_or_a_repeat_is_refused(self) -> None:
        for members in (["x"], ["x", "x"]):
            with pytest.raises(ValueError, match="at least two distinct"):
                Records.threat_cluster(members=members, edges=[], method="m", method_version="1", label=None)

    def test_an_edge_to_a_non_member_is_refused(self) -> None:
        with pytest.raises(ValueError, match="non-member"):
            Records.threat_cluster(members=["x", "y"], edges=[{"a": "x", "b": "q", "kind": "infra", "weight": 1.0}], method="m", method_version="1", label=None)


class TestDetectionBundle:
    def test_a_bundle_is_addressed_by_what_it_holds(self) -> None:
        assert Kit.bundle()["bundle_id"] == Kit.bundle(artefacts=list(reversed(ARTEFACTS)))["bundle_id"]
        assert Kit.bundle()["bundle_id"] != Kit.bundle(artefacts=[{"path": "rulepack.yaml", "sha256": "ff"}, ARTEFACTS[1]])["bundle_id"]
        assert Kit.bundle()["bundle_id"] != Kit.bundle(decision_digest="sha256:ee")["bundle_id"]

    def test_the_artefacts_are_sorted_by_path(self) -> None:
        assert [a["path"] for a in Kit.bundle()["artefacts"]] == ["decision.json", "rulepack.yaml"]

    @pytest.mark.parametrize("channel", ["shadow", "canary", "stable"])
    def test_every_channel_is_accepted(self, channel: str) -> None:
        assert Kit.bundle(channel=channel)["channel"] == channel

    def test_an_unknown_channel_is_refused(self) -> None:
        with pytest.raises(ValueError, match="channel"):
            Kit.bundle(channel="beta")

    @pytest.mark.parametrize("artefacts", [[], [{"path": "p", "sha256": ""}], [{"path": "", "sha256": "x"}]])
    def test_a_bundle_without_a_complete_artefact_is_refused(self, artefacts: list[dict[str, str]]) -> None:
        with pytest.raises(ValueError, match="at least one artefact"):
            Kit.bundle(artefacts=artefacts)


class TestDeploymentObservation:
    def test_a_record_carries_every_counter(self) -> None:
        o = Records.deployment_observation(bundle_id="b1", channel="canary", window="2026-11-22/2026-11-23", counts=COUNTS)
        assert all(o[c] == COUNTS[c] for c in COUNTERS) and o["bundle_id"] == "b1"

    def test_a_missing_counter_is_refused_by_name(self) -> None:
        with pytest.raises(ValueError, match="crashes"):
            Records.deployment_observation(bundle_id="b", channel="stable", window="w", counts={k: v for k, v in COUNTS.items() if k != "crashes"})

    def test_a_negative_counter_is_refused(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            Records.deployment_observation(bundle_id="b", channel="stable", window="w", counts={**COUNTS, "timeouts": -1})

    def test_more_confirmed_fires_than_fires_is_refused(self) -> None:
        with pytest.raises(ValueError, match="more confirmed"):
            Records.deployment_observation(bundle_id="b", channel="stable", window="w", counts={**COUNTS, "confirmed_fires": 6})

    def test_equal_confirmed_fires_and_fires_is_allowed(self) -> None:
        assert Records.deployment_observation(bundle_id="b", channel="stable", window="w", counts={**COUNTS, "confirmed_fires": 5})["fires"] == 5

    def test_an_unknown_channel_is_refused(self) -> None:
        with pytest.raises(ValueError, match="channel"):
            Records.deployment_observation(bundle_id="b", channel="beta", window="w", counts=COUNTS)

    def test_the_bundle_id_it_names_can_be_a_real_bundle(self) -> None:
        o = Records.deployment_observation(bundle_id=Kit.bundle()["bundle_id"], channel="shadow", window="w", counts=COUNTS)
        assert o["bundle_id"].startswith("sha256:")
