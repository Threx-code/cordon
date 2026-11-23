"""ThreatCluster from families and edges: how releases are grouped, how urgent the group is, and what it is called.

Releases are joined by edges of five types, each weighted by what it is evidence of:

    infra             1.0   the same host, wallet or key
    campaign_sibling  1.0   the same labelled campaign
    same_family       0.8   members of one family (`families.py`)
    shared_fragment   0.4   a shared code fragment (a content hash): suggestive, never proof
    name              0.2   a look-alike or related package name

A cluster is the set of releases any chain of edges joins. Its PRIORITY is how much to look at it: the strongest edge of
each type, added up, so a hundred shared fragments are one vote. A shared fragment raises the priority and nothing
else: the graph prioritises and never labels. A cluster's LABEL is null unless a release in it already has independent
evidence in the label store (a state at tier confirmed or corroborated), and then it is one of the six label states and
no other word.
"""

from __future__ import annotations

from typing import Any, Final

from bench.cdi.records import LABEL_STATES, Records

EDGE_WEIGHTS: Final = {
    "infra": 1.0,
    "campaign_sibling": 1.0,
    "same_family": 0.8,
    "shared_fragment": 0.4,
    "name": 0.2,
}
INDEPENDENT_TIERS: Final = frozenset({"confirmed", "corroborated"})
METHOD: Final = "edge-components"
METHOD_VERSION: Final = "1"


class ClusterBuilder:
    @staticmethod
    def components(members: set[str], edges: list[dict[str, Any]]) -> list[set[str]]:
        parent = {m: m for m in members}

        def find(item: str) -> str:
            while parent[item] != item:
                parent[item] = parent[parent[item]]
                item = parent[item]
            return item

        for edge in edges:
            parent[find(edge["a"])] = find(edge["b"])
        groups: dict[str, set[str]] = {}
        for member in members:
            groups.setdefault(find(member), set()).add(member)
        return [g for g in groups.values() if len(g) > 1]

    @classmethod
    def edges_of(
        cls, families: dict[str, list[str]], links: list[dict[str, str]]
    ) -> list[dict[str, Any]]:
        """Every edge, with its weight: the links given (`{"a", "b", "type"}`) and a same_family edge from each family's
        first member to each other member. An unknown type is refused."""
        edges = []
        for link in links:
            if link["type"] not in EDGE_WEIGHTS:
                raise ValueError(f"edge type {link['type']!r} is not one of {sorted(EDGE_WEIGHTS)}")
            edges.append({"a": link["a"], "b": link["b"], "kind": link["type"]})
        for members in families.values():
            ordered = sorted(members)
            edges.extend(
                {"a": ordered[0], "b": other, "kind": "same_family"} for other in ordered[1:]
            )
        for edge in edges:
            edge["weight"] = EDGE_WEIGHTS[edge["kind"]]
        return edges

    @staticmethod
    def priority(edges: list[dict[str, Any]]) -> float:
        """The strongest edge of each type, added up."""
        strongest: dict[str, float] = {}
        for edge in edges:
            strongest[edge["kind"]] = max(strongest.get(edge["kind"], 0.0), edge["weight"])
        return round(sum(strongest.values()), 6)

    @staticmethod
    def label(members: set[str], evidence: dict[str, dict[str, str]]) -> str | None:
        """The cluster's label from the independent evidence its members already have, or None when they have none.
        Evidence is `{release: {"state": one of the six, "tier": ...}}`; only tier confirmed or corroborated counts. One
        state is that state; mixed malicious and benign evidence is `disputed`; anything else mixed stays null."""
        states = {
            evidence[m]["state"]
            for m in members
            if m in evidence and evidence[m].get("tier") in INDEPENDENT_TIERS
        }
        unknown = states - set(LABEL_STATES)
        if unknown:
            raise ValueError(f"label states are the six, not {sorted(unknown)}")
        if not states:
            return None
        if len(states) == 1:
            return next(iter(states))
        return "disputed" if {"confirmed_malicious", "confirmed_benign"} <= states else None

    @classmethod
    def build(
        cls,
        families: dict[str, list[str]],
        links: list[dict[str, str]],
        evidence: dict[str, dict[str, str]] | None = None,
    ) -> list[dict[str, Any]]:
        """`[{"record": ThreatCluster, "priority": float}]`, highest priority first."""
        evidence = evidence or {}
        edges = cls.edges_of(families, links)
        members = {m for f in families.values() for m in f} | {
            e[k] for e in edges for k in ("a", "b")
        }
        built = []
        for group in cls.components(members, edges):
            inside = [e for e in edges if e["a"] in group and e["b"] in group]
            record = Records.threat_cluster(
                members=sorted(group),
                edges=inside,
                method=METHOD,
                method_version=METHOD_VERSION,
                label=cls.label(group, evidence),
            )
            built.append({"record": record, "priority": cls.priority(inside)})
        return sorted(built, key=lambda c: (-c["priority"], c["record"]["cluster_id"]))
