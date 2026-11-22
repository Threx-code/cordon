"""What discovery produces (SI-Q5) and how it compares a cluster with its neighbours (SI-Q6).

SI-Q5. Discovery output is a HYPOTHESIS, not a label: supporting samples, counterexamples, expected coverage, limits and a validation plan. "Novelty is not maliciousness": a hypothesis becomes a
candidate only with a confirmed (or corroborated) label AND independent evidence, so a novel cluster nobody has labelled produces a hypothesis and no candidate.

SI-Q6. A confirmed-malicious cluster is compared with its nearest benign FeatureSet, by the distance between their content features (the Jaccard distance of the `(name, value, slot)` sets: the same content
features the `featureset_digest` is built from), and the differing features are returned: the ones only the malicious side has are what a rule may key on, and the ones only the benign side has are what a
rule must not trip. Clusters within a confirmed-malicious category are grouped by the same distance (single linkage under a maximum distance).
"""

from __future__ import annotations

import itertools
from typing import Any, Final

from bench.cdi.schemas import FACTORY_TIERS

HYPOTHESIS_FIELDS: Final = (
    "hypothesis_id",
    "statement",
    "supporting_samples",
    "counterexamples",
    "expected_coverage",
    "limits",
    "validation_plan",
)


class HypothesisRefused(ValueError):
    """A hypothesis was offered as a candidate without what makes it one; `reasons` names each."""

    def __init__(self, reasons: tuple[str, ...]) -> None:
        super().__init__("refused: " + "; ".join(reasons))
        self.reasons = reasons


class Hypotheses:
    @staticmethod
    def build(
        *,
        hypothesis_id: str,
        statement: str,
        supporting_samples: list[str],
        counterexamples: list[str],
        expected_coverage: str,
        limits: str,
        validation_plan: str,
    ) -> dict[str, Any]:
        """A hypothesis record. Every part is required and non-empty (an empty `counterexamples` list is allowed only as the explicit statement that none were found: pass `["none found"]`)."""
        record: dict[str, Any] = {
            "kind": "hypothesis",
            "hypothesis_id": hypothesis_id,
            "statement": statement,
            "supporting_samples": list(supporting_samples),
            "counterexamples": list(counterexamples),
            "expected_coverage": expected_coverage,
            "limits": limits,
            "validation_plan": validation_plan,
            "label": None,
        }
        empty = [name for name in HYPOTHESIS_FIELDS if not record[name]]
        if empty:
            raise ValueError(f"a hypothesis needs every part: missing {', '.join(empty)}")
        return record

    @staticmethod
    def candidate_blockers(
        hypothesis: dict[str, Any], label_tier: str | None, independent_evidence: list[str]
    ) -> tuple[str, ...]:
        """Why a hypothesis may not become a candidate yet (empty: it may). Novelty is not maliciousness."""
        out = []
        if hypothesis.get("kind") != "hypothesis":
            out.append("not a hypothesis record")
        if label_tier not in FACTORY_TIERS:
            out.append(
                "no confirmed label" if label_tier is None else f"label tier {label_tier} is not confirmed or corroborated"
            )
        if not independent_evidence:
            out.append("no independent evidence")
        return tuple(out)

    @staticmethod
    def require_candidate(
        hypothesis: dict[str, Any], label_tier: str | None, independent_evidence: list[str]
    ) -> None:
        reasons = Hypotheses.candidate_blockers(hypothesis, label_tier, independent_evidence)
        if reasons:
            raise HypothesisRefused(reasons)


class Distance:
    @staticmethod
    def content(featureset: dict[str, Any]) -> frozenset[tuple[str, str, str]]:
        """The content features of a FeatureSet as `(name, value, slot)`, the set the digest is made of."""
        return frozenset(
            (f["name"], str(f["value"]), f["slot"])
            for f in featureset["features"]
            if f.get("source") == "content"
        )

    @staticmethod
    def between(a: dict[str, Any], b: dict[str, Any]) -> float:
        """The Jaccard distance of two FeatureSets' content features: 0 for the same content, 1 for none shared (two empty sets are the same content)."""
        left, right = Distance.content(a), Distance.content(b)
        union = left | right
        return 0.0 if not union else 1 - len(left & right) / len(union)

    @staticmethod
    def nearest_benign(
        malicious: dict[str, Any], benign: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """The nearest benign FeatureSet (the smaller artifact id on a tie) and the differing features, or None when there is no benign set to compare with."""
        if not benign:
            return None
        best = min(benign, key=lambda b: (Distance.between(malicious, b), str(b["artifact_id"])))
        left, right = Distance.content(malicious), Distance.content(best)
        return {
            "artifact_id": best["artifact_id"],
            "distance": Distance.between(malicious, best),
            "only_malicious": sorted(left - right),
            "only_benign": sorted(right - left),
        }

    @staticmethod
    def group(featuresets: list[dict[str, Any]], max_distance: float) -> list[list[str]]:
        """Clusters within a category: FeatureSets joined when within `max_distance` of one another, directly or through others. Each cluster lists its artifact ids, sorted;
        the clusters are ordered by their first id."""
        parent = list(range(len(featuresets)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for i, j in itertools.combinations(range(len(featuresets)), 2):
            if Distance.between(featuresets[i], featuresets[j]) <= max_distance:
                parent[find(i)] = find(j)
        groups: dict[int, list[str]] = {}
        for i, featureset in enumerate(featuresets):
            groups.setdefault(find(i), []).append(str(featureset["artifact_id"]))
        return sorted(sorted(ids) for ids in groups.values())
